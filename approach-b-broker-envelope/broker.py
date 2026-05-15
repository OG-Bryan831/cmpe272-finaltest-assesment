#!/usr/bin/env python3
"""Approach B broker -- an UNTRUSTED store-and-forward blob server.

This process is deliberately dumb and deliberately untrusted. It holds:
  * encrypted chunk blobs (ChaCha20-Poly1305 ciphertext), and
  * the signed manifest + its detached Ed25519 signature.
It holds NO key material and NEVER sees plaintext. A full compromise of this
process therefore leaks only ciphertext + a signed manifest -- it cannot read
the file, and any blob it tampers with is caught by the receiver (signed
per-chunk hashes + AEAD tags + manifest signature => fail closed).

Wire protocol (TCP, length-prefixed frames via common.util):
  client -> "PUT <key>"  then a data frame      ; server -> "OK" | "ERR ..."
  client -> "GET <key>"                         ; server -> "OK"+data | "MISSING"
  client -> "STAT <key>"                        ; server -> "OK <size>" | "MISSING"
  client -> "LIST <prefix>"                     ; server -> "OK" + newline-joined keys
One connection may carry many commands; it ends when the client disconnects.

Run:  python broker.py [--host 127.0.0.1 --port 9000 --storage ./broker_storage]
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.util import line_buffered_stdout, recv_frame, send_frame  # noqa: E402

# Keys are exactly "<namespace>/<name>"; both segments are restricted character
# sets with no "." path components, which makes directory traversal impossible.
_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}/[A-Za-z0-9_.-]{1,128}$")

# Test affordance (NOT a security feature): when --fail-after-puts N is set, the
# broker drops the connection and exits right after the Nth PUT. This lets the
# test suite deterministically simulate a hostile/flaky broker cutting a sender
# off mid-upload, to exercise the sender's resume path.
_FAIL_AFTER_PUTS = 0
_PUT_COUNT = 0
_LOCK = threading.Lock()


def _safe_path(storage_root: str, key: str) -> str:
    if not _KEY_RE.match(key) or ".." in key:
        raise ValueError(f"illegal blob key: {key!r}")
    namespace, name = key.split("/", 1)
    return os.path.join(storage_root, namespace, name)


def _handle_command(storage_root: str, conn: socket.socket, line: bytes) -> None:
    parts = line.decode("utf-8", "replace").split(" ", 1)
    op = parts[0]
    arg = parts[1] if len(parts) > 1 else ""

    if op == "PUT":
        data = recv_frame(conn)  # the blob payload always follows a PUT command
        try:
            path = _safe_path(storage_root, arg)
        except ValueError as e:
            send_frame(conn, f"ERR {e}".encode())
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # atomic: a GET never sees a half-written blob
        with _LOCK:
            global _PUT_COUNT
            _PUT_COUNT += 1
            if _FAIL_AFTER_PUTS and _PUT_COUNT >= _FAIL_AFTER_PUTS:
                print(f"[broker] --fail-after-puts {_FAIL_AFTER_PUTS} reached; "
                      "dropping connection and exiting (simulated hostile broker)")
                conn.close()
                os._exit(3)
        send_frame(conn, b"OK")

    elif op == "GET":
        try:
            path = _safe_path(storage_root, arg)
        except ValueError:
            send_frame(conn, b"MISSING")
            return
        if not os.path.isfile(path):
            send_frame(conn, b"MISSING")
            return
        with open(path, "rb") as f:
            data = f.read()
        send_frame(conn, b"OK")
        send_frame(conn, data)

    elif op == "STAT":
        try:
            path = _safe_path(storage_root, arg)
        except ValueError:
            send_frame(conn, b"MISSING")
            return
        if os.path.isfile(path):
            send_frame(conn, f"OK {os.path.getsize(path)}".encode())
        else:
            send_frame(conn, b"MISSING")

    elif op == "LIST":
        prefix = arg
        keys = []
        for ns in sorted(os.listdir(storage_root)) if os.path.isdir(storage_root) else []:
            ns_dir = os.path.join(storage_root, ns)
            if not os.path.isdir(ns_dir):
                continue
            for name in sorted(os.listdir(ns_dir)):
                if name.endswith(".tmp"):
                    continue
                key = f"{ns}/{name}"
                if key.startswith(prefix):
                    keys.append(key)
        send_frame(conn, b"OK")
        send_frame(conn, "\n".join(keys).encode())

    else:
        send_frame(conn, f"ERR unknown op {op!r}".encode())


def _serve_client(storage_root: str, conn: socket.socket, peer) -> None:
    with conn:
        try:
            while True:
                try:
                    line = recv_frame(conn)
                except ConnectionError:
                    break  # client disconnected -- normal end of session
                _handle_command(storage_root, conn, line)
        except Exception as e:  # noqa: BLE001  -- a dumb broker must not crash the host
            print(f"[broker] client {peer} error: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach B untrusted blob broker")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--storage", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "broker_storage"))
    ap.add_argument("--fail-after-puts", type=int, default=0,
                    help="test affordance: drop the connection and exit after "
                         "the Nth PUT (simulate a hostile/flaky broker)")
    args = ap.parse_args()
    line_buffered_stdout()

    global _FAIL_AFTER_PUTS
    _FAIL_AFTER_PUTS = args.fail_after_puts
    os.makedirs(args.storage, exist_ok=True)
    with socket.create_server((args.host, args.port)) as srv:
        print(f"[broker] UNTRUSTED blob store on {args.host}:{args.port} "
              f"(storage: {args.storage})")
        print("[broker] holds ciphertext + signed manifest only; no keys, no plaintext.")
        while True:
            conn, peer = srv.accept()
            threading.Thread(
                target=_serve_client, args=(args.storage, conn, peer), daemon=True
            ).start()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[broker] shutting down")
        sys.exit(0)
