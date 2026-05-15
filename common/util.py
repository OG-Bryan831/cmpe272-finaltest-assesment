"""Streaming, framing, and hashing helpers shared by both approaches.

Nothing in here is security-sensitive on its own -- it is the plumbing that
lets both approaches stream a 4 GB file without ever holding it in memory.
"""
from __future__ import annotations

import hashlib
import os
import socket
import struct
import sys
import time

# --- Named constants (spec 5.4: no "magic" buffers) -------------------------

# Fixed transfer chunk size. 1 MiB sits in the middle of the spec's 64 KiB-4 MiB
# range: large enough that per-syscall and per-chunk AEAD-tag overhead (16 bytes
# => 0.0015%) are negligible, small enough that a sender/receiver never needs
# more than a few MiB of resident memory for a 4 GB file.
CHUNK_SIZE = 1 * 1024 * 1024

# Streaming read size for whole-file hashing (independent of CHUNK_SIZE).
HASH_READ_SIZE = 1 * 1024 * 1024

# SHA-256 digest length in bytes.
SHA256_LEN = 32

# Length prefix used by the socket framing helpers below: 8-byte big-endian.
_LEN_PREFIX = struct.Struct(">Q")


# --- Streaming hashing ------------------------------------------------------

def sha256_file(path: str, *, end_offset: int | None = None) -> str:
    """Return the hex SHA-256 of a file, read in fixed-size blocks.

    `end_offset` lets a caller hash only the first N bytes (used when a
    resumed transfer must hash the already-present prefix of a partial file).
    """
    h = hashlib.sha256()
    remaining = end_offset if end_offset is not None else float("inf")
    with open(path, "rb") as f:
        while remaining > 0:
            block = f.read(min(HASH_READ_SIZE, int(min(remaining, HASH_READ_SIZE))))
            if not block:
                break
            h.update(block)
            remaining -= len(block)
    return h.hexdigest()


# --- Socket plumbing --------------------------------------------------------

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly `n` bytes from `sock` or raise ConnectionError.

    A short read here means the peer closed mid-message -- which both
    approaches must treat as a failure, never as a clean end-of-file.
    """
    buf = bytearray()
    while len(buf) < n:
        block = sock.recv(min(65536, n - len(buf)))
        if not block:
            raise ConnectionError(
                f"peer closed after {len(buf)}/{n} bytes (truncated message)"
            )
        buf.extend(block)
    return bytes(buf)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send a length-prefixed message (8-byte BE length, then payload)."""
    sock.sendall(_LEN_PREFIX.pack(len(payload)))
    sock.sendall(payload)


def recv_frame(sock: socket.socket) -> bytes:
    """Receive one length-prefixed message sent by `send_frame`."""
    (length,) = _LEN_PREFIX.unpack(recv_exact(sock, _LEN_PREFIX.size))
    return recv_exact(sock, length)


# --- Durability -------------------------------------------------------------

def fsync_path(path: str) -> None:
    """Flush a file's contents to stable storage (spec pitfall: 'missing fsync')."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_promote(temp_path: str, final_path: str) -> None:
    """fsync then rename temp -> final. The rename is atomic on POSIX, so the
    final filename only ever appears once the bytes are durable and verified."""
    fsync_path(temp_path)
    os.replace(temp_path, final_path)


# --- Reporting --------------------------------------------------------------

def line_buffered_stdout() -> None:
    """Flush stdout per line even when redirected to a file/pipe, so progress
    is visible live and log-tailing health checks work."""
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass


def human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PiB"


class Throughput:
    """Tiny stopwatch for the spec's optional MB/s reporting."""

    def __init__(self) -> None:
        self.start = time.monotonic()
        self.bytes = 0

    def add(self, n: int) -> None:
        self.bytes += n

    def report(self) -> str:
        elapsed = max(time.monotonic() - self.start, 1e-9)
        rate = self.bytes / elapsed
        return (
            f"{human_bytes(self.bytes)} in {elapsed:.2f}s "
            f"=> {human_bytes(rate)}/s"
        )
