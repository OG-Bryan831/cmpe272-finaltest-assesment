"""Client for the untrusted Approach B broker, with bounded retry + backoff.

Because the broker is untrusted *and* the wire is hostile, every call here is
treated as unreliable: a dropped connection or transient error is retried with
exponential backoff up to a bounded number of attempts (spec stretch goal:
"rate-limited retry and backoff" for the Availability leg of CIAA). The client
re-establishes the TCP connection on each retry.

Crucially, this client does NOT trust anything the broker returns -- integrity
and authenticity are enforced by the caller (signature + per-chunk hash + AEAD).
The retry logic here only buys Availability, never trust.
"""
from __future__ import annotations

import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.util import recv_frame, send_frame  # noqa: E402

MAX_ATTEMPTS = 5
BASE_BACKOFF_S = 0.25  # 0.25, 0.5, 1.0, 2.0 ... bounded by MAX_ATTEMPTS


class BrokerError(RuntimeError):
    pass


class BrokerClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None

    # --- connection management -------------------------------------------
    def _connect(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.create_connection((self.host, self.port), timeout=60)
        return self._sock

    def _drop(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def close(self) -> None:
        self._drop()

    def __enter__(self) -> "BrokerClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- retrying command runner -----------------------------------------
    def _run(self, send_fn, parse_fn):
        """send_fn(sock) issues the command; parse_fn(sock) reads the reply.
        The whole exchange is retried on connection-level failures."""
        last_err: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                sock = self._connect()
                send_fn(sock)
                return parse_fn(sock)
            except (ConnectionError, socket.timeout, OSError) as e:
                last_err = e
                self._drop()
                if attempt < MAX_ATTEMPTS - 1:
                    backoff = BASE_BACKOFF_S * (2 ** attempt)
                    print(f"[broker-client] {e}; retry {attempt + 1}/"
                          f"{MAX_ATTEMPTS - 1} in {backoff:.2f}s")
                    time.sleep(backoff)
        raise BrokerError(f"broker unreachable after {MAX_ATTEMPTS} attempts: {last_err}")

    # --- operations -------------------------------------------------------
    def put(self, key: str, data: bytes) -> None:
        def send(sock):
            send_frame(sock, f"PUT {key}".encode())
            send_frame(sock, data)

        def parse(sock):
            reply = recv_frame(sock)
            if reply != b"OK":
                raise BrokerError(f"PUT {key} failed: {reply!r}")
            return None

        self._run(send, parse)

    def get(self, key: str) -> bytes | None:
        def send(sock):
            send_frame(sock, f"GET {key}".encode())

        def parse(sock):
            status = recv_frame(sock)
            if status == b"MISSING":
                return None
            if status != b"OK":
                raise BrokerError(f"GET {key} unexpected status: {status!r}")
            return recv_frame(sock)

        return self._run(send, parse)

    def stat(self, key: str) -> int | None:
        def send(sock):
            send_frame(sock, f"STAT {key}".encode())

        def parse(sock):
            reply = recv_frame(sock).decode("utf-8", "replace")
            if reply == "MISSING":
                return None
            if reply.startswith("OK "):
                return int(reply[3:])
            raise BrokerError(f"STAT {key} unexpected reply: {reply!r}")

        return self._run(send, parse)

    def list(self, prefix: str) -> list[str]:
        def send(sock):
            send_frame(sock, f"LIST {prefix}".encode())

        def parse(sock):
            status = recv_frame(sock)
            if status != b"OK":
                raise BrokerError(f"LIST unexpected status: {status!r}")
            body = recv_frame(sock).decode("utf-8", "replace")
            return [k for k in body.split("\n") if k]

        return self._run(send, parse)
