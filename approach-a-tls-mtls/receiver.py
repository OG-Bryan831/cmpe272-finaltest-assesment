#!/usr/bin/env python3
"""Approach A receiver -- mutually-authenticated TLS 1.3 streaming server.

Security envelope = the TLS 1.3 channel itself:
  * Confidentiality + per-record Integrity : TLS 1.3 AEAD record protection.
  * Authenticity (mutual)                  : we present receiver.crt AND require
                                             a client cert chaining to ca.crt
                                             (verify_mode = CERT_REQUIRED).
  * Forward secrecy                         : TLS 1.3 is ECDHE-only.
On top of the channel the app adds an end-to-end SHA-256 of the *plaintext*
(spec pitfall: "hash the plaintext too") and a temp-file / atomic-rename
discipline so a dropped connection never leaves a valid-looking partial file.

Run:  python receiver.py --out received.bin [--host 127.0.0.1 --port 8443]
"""
from __future__ import annotations

import argparse
import hashlib
import os
import socket
import ssl
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.util import (  # noqa: E402
    HASH_READ_SIZE,
    SHA256_LEN,
    Throughput,
    atomic_promote,
    line_buffered_stdout,
    recv_exact,
    recv_frame,
    send_frame,
)

# Wire header sent by the sender right after resume negotiation: total plaintext
# size and the byte offset the sender actually accepted to resume from.
_HEADER = struct.Struct(">QQ")


def build_server_context(certs_dir: str) -> ssl.SSLContext:
    """TLS 1.3, present receiver cert, REQUIRE + verify a CA-signed client cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # ECDHE-only => forward secrecy
    ctx.load_cert_chain(
        os.path.join(certs_dir, "receiver.crt"),
        os.path.join(certs_dir, "receiver.key"),
    )
    ctx.load_verify_locations(os.path.join(certs_dir, "ca.crt"))
    # This single line is the receiver's half of MUTUAL auth: no client cert
    # (or one not signed by our offline CA) => handshake fails closed.
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _hash_prefix(path: str, n: int, h: "hashlib._Hash") -> None:
    """Feed the first `n` bytes of `path` into `h` (used when resuming)."""
    remaining = n
    with open(path, "rb") as f:
        while remaining > 0:
            block = f.read(min(HASH_READ_SIZE, remaining))
            if not block:
                raise IOError("partial file shorter than expected during resume")
            h.update(block)
            remaining -= len(block)


def receive(tls: ssl.SSLSocket, out_path: str) -> int:
    part_path = out_path + ".part"

    # --- Resume negotiation ------------------------------------------------
    claimed_offset = os.path.getsize(part_path) if os.path.exists(part_path) else 0
    send_frame(tls, struct.pack(">Q", claimed_offset))
    total_size, accepted_offset = _HEADER.unpack(recv_frame(tls))

    h = hashlib.sha256()
    if accepted_offset != claimed_offset:
        # Sender rejected our partial (stale / too large). Start clean.
        if os.path.exists(part_path):
            os.remove(part_path)
        accepted_offset = 0
        print(f"[receiver] starting fresh transfer ({total_size} bytes)")
    elif accepted_offset:
        _hash_prefix(part_path, accepted_offset, h)
        print(f"[receiver] resuming at offset {accepted_offset}/{total_size}")
    else:
        print(f"[receiver] starting transfer ({total_size} bytes)")

    # --- Stream chunks into the .part file --------------------------------
    tput = Throughput()
    received = accepted_offset
    mode = "r+b" if accepted_offset else "wb"
    with open(part_path, mode) as f:
        f.seek(accepted_offset)
        try:
            while True:
                chunk = recv_frame(tls)
                if chunk == b"":  # explicit end-of-stream marker
                    break
                f.write(chunk)
                h.update(chunk)
                received += len(chunk)
                tput.add(len(chunk))
            # Trailer: 32-byte SHA-256 of the whole plaintext, from the sender.
            expected_digest = recv_exact(tls, SHA256_LEN)
        except (ConnectionError, ssl.SSLError, OSError) as e:
            # Connection dropped mid-transfer. Keep .part (under its temp name,
            # never the final name) so a re-run can RESUME -- fail-safe, not
            # fail-complete.
            f.flush()
            os.fsync(f.fileno())
            print(f"[receiver] connection dropped at {received}/{total_size} "
                  f"bytes: {e}")
            print(f"[receiver] partial saved to {part_path} -- re-run to resume.")
            return 1

    # --- Verify, then fail closed or promote ------------------------------
    actual_digest = h.digest()
    ok = received == total_size and actual_digest == expected_digest
    if not ok:
        os.remove(part_path)  # quarantine: never leave a bad partial on disk
        print("[receiver] TRANSFER REJECTED -- verification failed:")
        if received != total_size:
            print(f"  size mismatch: got {received}, expected {total_size}")
        if actual_digest != expected_digest:
            print(f"  sha256 mismatch:\n    got      {actual_digest.hex()}"
                  f"\n    expected {expected_digest.hex()}")
        print("  partial file deleted.")
        return 1

    atomic_promote(part_path, out_path)
    print(f"[receiver] OK  {tput.report()}")
    print(f"[receiver] sha256 verified: {actual_digest.hex()}")
    print(f"[receiver] wrote {out_path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach A mTLS receiver")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--out", required=True, help="output path for the received file")
    ap.add_argument("--certs-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "certs"))
    args = ap.parse_args()
    line_buffered_stdout()

    ctx = build_server_context(args.certs_dir)
    with socket.create_server((args.host, args.port)) as srv:
        srv.settimeout(120)
        print(f"[receiver] listening on {args.host}:{args.port} (TLS 1.3, mTLS) ...")
        try:
            raw, peer = srv.accept()
        except socket.timeout:
            print("[receiver] timed out waiting for a connection")
            return 1
        with raw:
            try:
                tls = ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, ConnectionError, OSError) as e:
                # A wrong/absent client cert lands here -- mutual auth fail-closed.
                print(f"[receiver] TLS handshake REJECTED from {peer}: {e}")
                return 1
            with tls:
                cert = tls.getpeercert()
                cn = next((v for ((k, v),) in cert.get("subject", ()) if k == "commonName"),
                          "<unknown>")
                print(f"[receiver] mutual TLS established; client CN={cn}")
                try:
                    return receive(tls, args.out)
                except (ConnectionError, ssl.SSLError, OSError) as e:
                    # Drop during resume negotiation (before any file bytes).
                    print(f"[receiver] connection lost during setup: {e}")
                    return 1


if __name__ == "__main__":
    sys.exit(main())
