#!/usr/bin/env python3
"""Approach B sender -- offline-encrypt the file into a signed envelope, then
push the ciphertext + signed manifest through the UNTRUSTED broker.

Pipeline (streaming; the 4 GB file is never fully in memory):
  1. Ephemeral X25519 keypair -> ECDH with the receiver's long-lived X25519
     public key -> HKDF-SHA256 -> a fresh 256-bit key for THIS transfer only
     (the ephemeral half is what gives forward secrecy).
  2. For each CHUNK_SIZE chunk: ChaCha20-Poly1305 encrypt with a
     counter-derived nonce and AAD = transfer_id||index||total_chunks.
  3. Build a manifest (file size, plaintext SHA-256, per-chunk ciphertext
     SHA-256, ephemeral public key, timestamp) and sign it with the sender's
     long-lived Ed25519 key.
  4. Upload every chunk + the manifest + the detached signature to the broker.

Resumable: per-file state (transfer_id + ephemeral key) is persisted so an
interrupted run re-uses the same key/nonces and only uploads missing chunks.
The state file is deleted on success -- which is also what restores forward
secrecy, since the ephemeral private key is then gone.

Run:  python sender.py --file test_4gb.bin [--broker-host 127.0.0.1 --broker-port 9000]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.util import CHUNK_SIZE, Throughput, line_buffered_stdout  # noqa: E402

import envelope as env  # noqa: E402
from broker_client import BrokerClient, BrokerError  # noqa: E402


def _state_path(state_dir: str, file_path: str) -> str:
    tag = hashlib.sha256(os.path.abspath(file_path).encode()).hexdigest()[:16]
    return os.path.join(state_dir, f"{tag}.json")


def _load_or_create_state(state_dir: str, file_path: str, file_size: int) -> dict:
    """Return persisted {transfer_id, created_at, ephemeral key}, creating it
    on first run. Persisting the ephemeral key is what makes the sender
    resumable; the file is 0600, git-ignored, and deleted on success."""
    os.makedirs(state_dir, exist_ok=True)
    path = _state_path(state_dir, file_path)
    if os.path.isfile(path):
        with open(path) as f:
            state = json.load(f)
        if state.get("file_size") == file_size:
            print(f"[sender] resuming transfer {state['transfer_id']}")
            return state
        print("[sender] stored state is stale (file changed); starting fresh")

    eph = X25519PrivateKey.generate()
    state = {
        "transfer_id": os.urandom(env.TRANSFER_ID_LEN).hex(),
        "created_at": int(time.time()),
        "file_size": file_size,
        "ephemeral_x25519_key_pem": eph.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)
    return state


def send(args) -> int:
    file_path = args.file
    if not os.path.isfile(file_path):
        print(f"[sender] no such file: {file_path}")
        return 1
    file_size = os.path.getsize(file_path)
    total_chunks = math.ceil(file_size / CHUNK_SIZE) if file_size else 0

    # --- identities + per-transfer state ----------------------------------
    signing_key = env.load_ed25519_private(
        os.path.join(args.keys_dir, "sender_ed25519.key"))
    receiver_pub = env.load_x25519_public(
        os.path.join(args.keys_dir, "receiver_x25519.pub"))
    state = _load_or_create_state(args.state_dir, file_path, file_size)
    transfer_id_hex = state["transfer_id"]
    transfer_id = bytes.fromhex(transfer_id_hex)

    ephemeral_key = serialization.load_pem_private_key(
        state["ephemeral_x25519_key_pem"].encode(), password=None)
    ephemeral_pub_raw = env.raw_public(ephemeral_key.public_key())
    receiver_pub_raw = env.raw_public(receiver_pub)

    # --- ECDH -> HKDF -> per-transfer ChaCha20-Poly1305 key ---------------
    shared = ephemeral_key.exchange(receiver_pub)
    chunk_key = env.derive_chunk_key(
        shared, transfer_id, ephemeral_pub_raw, receiver_pub_raw)
    aead = ChaCha20Poly1305(chunk_key)

    broker = BrokerClient(args.broker_host, args.broker_port)
    # Chunks already on the broker (resume): skip re-uploading these.
    already = set(broker.list(transfer_id_hex + "/"))
    if already:
        print(f"[sender] broker already holds {len(already)} blob(s) for this transfer")

    # --- stream: read -> encrypt -> (maybe) upload ------------------------
    plaintext_hash = hashlib.sha256()
    chunk_records = []
    tput = Throughput()
    uploaded = 0
    with open(file_path, "rb") as f:
        for index in range(total_chunks):
            plain = f.read(CHUNK_SIZE)
            plaintext_hash.update(plain)
            nonce = env.chunk_nonce(index)
            aad = env.chunk_aad(transfer_id, index, total_chunks)
            ct = aead.encrypt(nonce, plain, aad)
            ct_digest = hashlib.sha256(ct).hexdigest()
            chunk_records.append({
                "index": index,
                "plaintext_len": len(plain),
                "ciphertext_sha256": ct_digest,
            })
            key_name = env.chunk_key(transfer_id_hex, index)
            if key_name not in already:
                broker.put(key_name, ct)
                uploaded += 1
            tput.add(len(plain))

    # --- build + sign the manifest ----------------------------------------
    manifest = {
        "version": env.MANIFEST_VERSION,
        "transfer_id": transfer_id_hex,
        "created_at": state["created_at"],
        "filename": os.path.basename(file_path),
        "file_size": file_size,
        "chunk_size": CHUNK_SIZE,
        "total_chunks": total_chunks,
        "cipher": env.CIPHER_NAME,
        "kdf": env.KDF_NAME,
        "signature_alg": env.SIG_NAME,
        "ephemeral_x25519_pub": ephemeral_pub_raw.hex(),
        "plaintext_sha256": plaintext_hash.hexdigest(),
        "chunks": chunk_records,
    }
    manifest_bytes = env.canonical_manifest_bytes(manifest)
    signature = signing_key.sign(manifest_bytes)

    broker.put(env.manifest_key(transfer_id_hex), manifest_bytes)
    broker.put(env.signature_key(transfer_id_hex), signature)
    broker.close()

    # --- success: drop the state file (also wipes the ephemeral key) ------
    os.remove(_state_path(args.state_dir, file_path))

    print(f"[sender] OK  {tput.report()}")
    print(f"[sender] uploaded {uploaded} new chunk(s), "
          f"{total_chunks - uploaded} already present")
    print(f"[sender] plaintext sha256: {manifest['plaintext_sha256']}")
    print(f"[sender] transfer id (give this to the receiver): {transfer_id_hex}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach B envelope sender")
    ap.add_argument("--file", required=True, help="path to the file to send")
    ap.add_argument("--broker-host", default="127.0.0.1")
    ap.add_argument("--broker-port", type=int, default=9000)
    ap.add_argument("--keys-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "keys"))
    ap.add_argument("--state-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".send-state"))
    args = ap.parse_args()
    line_buffered_stdout()
    try:
        return send(args)
    except BrokerError as e:
        # Broker unreachable / dropped us. Per-file state is preserved, so a
        # later re-run resumes the upload from where it stopped.
        print(f"[sender] upload interrupted: {e}")
        print("[sender] state preserved -- re-run with the same --file to resume.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
