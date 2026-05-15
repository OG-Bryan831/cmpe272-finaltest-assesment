"""Shared cryptographic envelope logic for Approach B's sender and receiver.

Keeping derivation, nonce construction, AAD construction, and manifest
canonicalisation in ONE module guarantees the sender and receiver agree
byte-for-byte -- a mismatch here is the classic source of nonce-reuse or
AEAD-failure bugs.

Crypto choices (all via PyCA `cryptography`; no hand-rolled primitives):
  * Key agreement : X25519 ECDH -- sender's EPHEMERAL key x receiver's
                    LONG-LIVED key. The ephemeral half gives forward secrecy.
  * KDF           : HKDF-SHA256, salted with the random transfer_id and bound
                    (via info) to the protocol version + both public keys.
  * Bulk cipher   : ChaCha20-Poly1305 AEAD, 256-bit key, 96-bit nonce, 128-bit tag.
  * Nonce         : 4 zero bytes || 8-byte big-endian chunk index. Safe because
                    the key is unique per transfer (fresh ephemeral ECDH) and the
                    index is unique + monotonic per chunk => (key, nonce) never
                    repeats.
  * AAD           : transfer_id || chunk index || total_chunks. Binds every
                    ciphertext to its position and the total count, so a moved,
                    duplicated, or dropped chunk fails to authenticate.
  * Manifest sig  : Ed25519 over the canonical JSON manifest.
"""
from __future__ import annotations

import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MANIFEST_VERSION = "cmpe272-approach-b/v1"
CIPHER_NAME = "ChaCha20-Poly1305"
KDF_NAME = "HKDF-SHA256"
SIG_NAME = "Ed25519"

KEY_LEN = 32          # ChaCha20-Poly1305 key
NONCE_LEN = 12        # ChaCha20-Poly1305 nonce
TAG_LEN = 16          # Poly1305 tag
TRANSFER_ID_LEN = 16  # random per-transfer id

# Replay defence: receiver rejects a manifest whose created_at is older than
# this (or set in the future beyond a small skew). Combined with the
# already-completed-transfer ledger, this stops replay of an old valid transfer.
FRESHNESS_WINDOW_S = 24 * 3600
CLOCK_SKEW_S = 300


# --- key material loading ---------------------------------------------------

def load_x25519_private(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_x25519_public(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_ed25519_private(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_ed25519_public(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def raw_public(pubkey) -> bytes:
    """Raw 32-byte encoding of an X25519/Ed25519 public key."""
    return pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# --- derivation / nonce / AAD ----------------------------------------------

def derive_chunk_key(
    shared_secret: bytes,
    transfer_id: bytes,
    ephemeral_pub_raw: bytes,
    receiver_pub_raw: bytes,
) -> bytes:
    """HKDF-SHA256 -> 32-byte ChaCha20-Poly1305 key, unique per transfer."""
    info = (
        MANIFEST_VERSION.encode() + b"|chunkkey|"
        + ephemeral_pub_raw + receiver_pub_raw
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=transfer_id,
        info=info,
    ).derive(shared_secret)


def chunk_nonce(index: int) -> bytes:
    """96-bit nonce = 4 zero bytes || 64-bit big-endian chunk index."""
    return b"\x00\x00\x00\x00" + index.to_bytes(8, "big")


def chunk_aad(transfer_id: bytes, index: int, total_chunks: int) -> bytes:
    """AAD binds a ciphertext to its transfer, its index, and the total count."""
    return transfer_id + index.to_bytes(8, "big") + total_chunks.to_bytes(8, "big")


# --- manifest ---------------------------------------------------------------

def canonical_manifest_bytes(manifest: dict) -> bytes:
    """Deterministic JSON encoding -- the EXACT bytes that get signed/verified."""
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


# --- broker key names -------------------------------------------------------

def manifest_key(transfer_id_hex: str) -> str:
    return f"{transfer_id_hex}/manifest"


def signature_key(transfer_id_hex: str) -> str:
    return f"{transfer_id_hex}/manifest.sig"


def chunk_key(transfer_id_hex: str, index: int) -> str:
    return f"{transfer_id_hex}/chunk_{index:08d}"
