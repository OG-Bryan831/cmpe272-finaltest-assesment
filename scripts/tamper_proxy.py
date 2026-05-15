#!/usr/bin/env python3
"""A hostile-network simulator: a TCP proxy that sits between two endpoints and
either flips a byte mid-stream or truncates the connection.

This is the test harness's stand-in for "an active man-in-the-middle on the
wire" and "the connection drops at 80%". It is NOT part of either transfer
approach -- it exists only so the threat-model tests are reproducible.

Modes:
  --mode flip --at N        XOR byte N (in --direction) with 0xFF, then relay on
  --mode truncate --at N    relay N bytes (in --direction), then kill both sides
  --mode pass               plain relay (sanity check)

Directions: c2s (client->server, e.g. sender->receiver) or s2c.

Usage:
  python tamper_proxy.py --listen 127.0.0.1:8500 --target 127.0.0.1:8443 \
      --mode flip --at 5000 --direction c2s
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading


def _hostport(s: str) -> tuple[str, int]:
    host, port = s.rsplit(":", 1)
    return host, int(port)


def _relay(src: socket.socket, dst: socket.socket, *, tamper: bool,
           mode: str, at: int, peers: list) -> None:
    """Copy src->dst. If tamper, apply `mode` at byte offset `at`."""
    transferred = 0
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if tamper and mode == "truncate" and transferred + len(data) > at:
                # Relay just up to the cutoff, then drop everything.
                allow = max(0, at - transferred)
                if allow:
                    dst.sendall(data[:allow])
                print(f"[tamper_proxy] TRUNCATED after {at} bytes -- killing link")
                break
            if tamper and mode == "flip" and transferred <= at < transferred + len(data):
                idx = at - transferred
                buf = bytearray(data)
                buf[idx] ^= 0xFF
                data = bytes(buf)
                print(f"[tamper_proxy] FLIPPED byte at offset {at}")
            dst.sendall(data)
            transferred += len(data)
    except OSError:
        pass
    finally:
        for p in peers:
            try:
                p.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                p.close()
            except OSError:
                pass


def main() -> int:
    ap = argparse.ArgumentParser(description="man-in-the-middle test proxy")
    ap.add_argument("--listen", required=True, help="host:port to listen on")
    ap.add_argument("--target", required=True, help="host:port to forward to")
    ap.add_argument("--mode", choices=["flip", "truncate", "pass"], default="pass")
    ap.add_argument("--at", type=int, default=0, help="byte offset for flip/truncate")
    ap.add_argument("--direction", choices=["c2s", "s2c"], default="c2s")
    args = ap.parse_args()

    lhost, lport = _hostport(args.listen)
    thost, tport = _hostport(args.target)

    with socket.create_server((lhost, lport)) as srv:
        srv.settimeout(60)
        print(f"[tamper_proxy] {args.listen} -> {args.target} "
              f"mode={args.mode} at={args.at} dir={args.direction}")
        try:
            client, _ = srv.accept()
        except socket.timeout:
            print("[tamper_proxy] timed out waiting for a client")
            return 1
        upstream = socket.create_connection((thost, tport), timeout=60)
        peers = [client, upstream]
        t1 = threading.Thread(target=_relay, args=(client, upstream), kwargs=dict(
            tamper=(args.direction == "c2s"), mode=args.mode, at=args.at, peers=peers))
        t2 = threading.Thread(target=_relay, args=(upstream, client), kwargs=dict(
            tamper=(args.direction == "s2c"), mode=args.mode, at=args.at, peers=peers))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    print("[tamper_proxy] link closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
