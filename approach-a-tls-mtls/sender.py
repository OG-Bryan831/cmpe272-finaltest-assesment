#!/usr/bin/env python3
"""Approach A sender -- mutually-authenticated TLS 1.3 streaming client.

The sender presents sender.crt (CA-signed, CLIENT_AUTH) and verifies the
receiver's certificate against the same offline ca.crt with hostname checking
on. It streams the file in CHUNK_SIZE frames over the TLS channel and finishes
with a 32-byte SHA-256 of the whole plaintext so the receiver can verify the
file end-to-end, independent of TLS's own per-record integrity.

Run:  python sender.py --file test_4gb.bin [--host 127.0.0.1 --port 8443]
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
    CHUNK_SIZE,
    Throughput,
    line_buffered_stdout,
    recv_frame,
    send_frame,
)

_HEADER = struct.Struct(">QQ")  # (total_size, accepted_offset)


def build_client_context(certs_dir: str) -> ssl.SSLContext:
    """TLS 1.3 client: present sender cert, verify receiver cert + hostname."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # ECDHE-only => forward secrecy
    ctx.load_cert_chain(
        os.path.join(certs_dir, "sender.crt"),
        os.path.join(certs_dir, "sender.key"),
    )
    ctx.load_verify_locations(os.path.join(certs_dir, "ca.crt"))
    # PROTOCOL_TLS_CLIENT already sets verify_mode=CERT_REQUIRED and
    # check_hostname=True; we keep both ON -- that is the sender's half of
    # mutual auth and our defence against a spoofed receiver.
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def stream(tls: ssl.SSLSocket, file_path: str) -> int:
    file_size = os.path.getsize(file_path)

    # --- Resume negotiation -----------------------------------------------
    (claimed_offset,) = struct.unpack(">Q", recv_frame(tls))
    accepted_offset = claimed_offset if 0 <= claimed_offset <= file_size else 0
    send_frame(tls, _HEADER.pack(file_size, accepted_offset))
    if accepted_offset:
        print(f"[sender] resuming from offset {accepted_offset}/{file_size}")
    else:
        print(f"[sender] sending {file_size} bytes from the start")

    # --- Stream + hash in a single pass -----------------------------------
    # We always hash the WHOLE plaintext (bytes 0..EOF) but only transmit bytes
    # at/after accepted_offset. On a normal (offset 0) run that is one read.
    h = hashlib.sha256()
    tput = Throughput()
    with open(file_path, "rb") as f:
        remaining_prefix = accepted_offset
        while remaining_prefix > 0:  # hash-only the bytes the receiver already has
            block = f.read(min(CHUNK_SIZE, remaining_prefix))
            if not block:
                raise IOError("source file shorter than the resume offset")
            h.update(block)
            remaining_prefix -= len(block)
        while True:  # hash AND send the remainder
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            send_frame(tls, chunk)
            tput.add(len(chunk))

    send_frame(tls, b"")           # end-of-stream marker
    tls.sendall(h.digest())        # 32-byte plaintext SHA-256 trailer
    print(f"[sender] OK  {tput.report()}")
    print(f"[sender] sha256 of plaintext: {h.hexdigest()}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach A mTLS sender")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--file", required=True, help="path to the file to send")
    ap.add_argument("--server-name", default="localhost",
                    help="hostname to verify against the receiver cert SAN")
    ap.add_argument("--certs-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "certs"))
    args = ap.parse_args()
    line_buffered_stdout()

    if not os.path.isfile(args.file):
        print(f"[sender] no such file: {args.file}")
        return 1

    ctx = build_client_context(args.certs_dir)
    try:
        raw = socket.create_connection((args.host, args.port), timeout=120)
    except (ConnectionError, socket.timeout, OSError) as e:
        print(f"[sender] cannot reach receiver: {e}")
        return 1
    with raw:
        try:
            tls = ctx.wrap_socket(raw, server_hostname=args.server_name)
        except (ssl.SSLError, ConnectionError, OSError) as e:
            # A spoofed receiver (cert not chaining to our CA, or wrong
            # hostname) is rejected HERE, before a single file byte is sent.
            print(f"[sender] TLS handshake REJECTED: {e}")
            return 1
        with tls:
            print(f"[sender] mutual TLS established with "
                  f"{args.host}:{args.port} ({tls.version()})")
            try:
                return stream(tls, args.file)
            except (ConnectionError, ssl.SSLError, OSError) as e:
                # Mid-transfer drop (e.g. receiver aborted on a bad record).
                print(f"[sender] connection lost mid-transfer: {e}")
                return 1


if __name__ == "__main__":
    sys.exit(main())
