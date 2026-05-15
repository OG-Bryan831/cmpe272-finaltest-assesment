#!/usr/bin/env python3
"""Approach B receiver -- pull the signed envelope from the UNTRUSTED broker,
verify it end to end, and only then reconstruct the plaintext file.

Verification order is deliberate -- nothing is trusted until it is checked:
  1. Fetch manifest + detached signature; verify the Ed25519 signature with
     the sender's PRE-DISTRIBUTED public key. A bad signature => abort.
     (This is authenticity + integrity of the manifest itself.)
  2. Replay defence: reject a manifest outside the freshness window or whose
     transfer_id is already in the completed-transfer ledger.
  3. ECDH(our long-lived X25519 key, manifest's ephemeral pub) -> HKDF -> key.
  4. Per chunk: fetch ciphertext, check its SHA-256 against the SIGNED manifest
     BEFORE decrypting, then ChaCha20-Poly1305-decrypt (AEAD tag + AAD bind
     index/total, so a swapped/dropped/modified chunk fails closed).
  5. Reassemble into a .part file; verify the whole-file plaintext SHA-256
     against the signed manifest; only then fsync + atomic-rename to --out.

Resumable: verified chunk indices are tracked in <out>.part.progress, so a
re-run after a drop skips what is already done.

Run:  python receiver.py --out received.bin [--transfer-id <hex>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.util import (  # noqa: E402
    CHUNK_SIZE,
    Throughput,
    atomic_promote,
    line_buffered_stdout,
    sha256_file,
)

import envelope as env  # noqa: E402
from broker_client import BrokerClient, BrokerError  # noqa: E402

FSYNC_EVERY_CHUNKS = 64  # flush progress + data to disk every 64 MiB


class VerificationError(RuntimeError):
    """Raised for any fail-closed condition; the caller never promotes .part."""


# --- replay-defence ledger --------------------------------------------------

def _ledger_path(state_dir: str) -> str:
    return os.path.join(state_dir, "seen_transfers.json")


def _load_ledger(state_dir: str) -> set:
    try:
        with open(_ledger_path(state_dir)) as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def _record_completed(state_dir: str, transfer_id_hex: str) -> None:
    os.makedirs(state_dir, exist_ok=True)
    seen = _load_ledger(state_dir)
    seen.add(transfer_id_hex)
    with open(_ledger_path(state_dir), "w") as f:
        json.dump(sorted(seen), f)


# --- resume progress --------------------------------------------------------

def _load_progress(progress_path: str, transfer_id_hex: str) -> set:
    try:
        with open(progress_path) as f:
            data = json.load(f)
        if data.get("transfer_id") == transfer_id_hex:
            return set(data.get("done", []))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return set()


def _save_progress(progress_path: str, transfer_id_hex: str, done: set) -> None:
    tmp = progress_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"transfer_id": transfer_id_hex, "done": sorted(done)}, f)
    os.replace(tmp, progress_path)


# --- manifest fetch + verify ------------------------------------------------

def _resolve_transfer_id(broker: BrokerClient, given: str | None) -> str:
    if given:
        return given
    manifests = [k for k in broker.list("") if k.endswith("/manifest")]
    ids = sorted({k.split("/", 1)[0] for k in manifests})
    if len(ids) == 1:
        print(f"[receiver] auto-selected the only transfer on the broker: {ids[0]}")
        return ids[0]
    if not ids:
        raise VerificationError("broker holds no transfers")
    raise VerificationError(
        "broker holds multiple transfers; pass --transfer-id <hex>:\n  "
        + "\n  ".join(ids))


def _fetch_verified_manifest(broker, transfer_id_hex, verify_key, allow_redeliver,
                             state_dir):
    manifest_bytes = broker.get(env.manifest_key(transfer_id_hex))
    signature = broker.get(env.signature_key(transfer_id_hex))
    if manifest_bytes is None or signature is None:
        raise VerificationError("manifest or signature not found on broker")

    # (1) authenticity + integrity of the manifest: signature is checked with
    # our PRE-DISTRIBUTED copy of the sender key, NOT anything from the wire.
    try:
        verify_key.verify(signature, manifest_bytes)
    except InvalidSignature:
        raise VerificationError(
            "manifest signature INVALID -- not from the trusted sender, or tampered")

    manifest = json.loads(manifest_bytes)
    if manifest.get("version") != env.MANIFEST_VERSION:
        raise VerificationError(f"unsupported manifest version {manifest.get('version')!r}")
    if manifest.get("transfer_id") != transfer_id_hex:
        raise VerificationError("manifest transfer_id does not match requested id")

    # (2) replay defence: freshness window + completed-transfer ledger.
    now = int(time.time())
    age = now - int(manifest["created_at"])
    if not allow_redeliver:
        if age > env.FRESHNESS_WINDOW_S:
            raise VerificationError(
                f"manifest is {age}s old (> {env.FRESHNESS_WINDOW_S}s window) "
                "-- possible replay; use --allow-redeliver to override")
        if age < -env.CLOCK_SKEW_S:
            raise VerificationError("manifest created_at is in the future -- rejected")
        if transfer_id_hex in _load_ledger(state_dir):
            raise VerificationError(
                "transfer_id already completed here -- replay; "
                "use --allow-redeliver to override")
    print(f"[receiver] manifest signature OK, age {age}s, "
          f"{manifest['total_chunks']} chunk(s), {manifest['file_size']} bytes")
    return manifest


# --- main receive flow ------------------------------------------------------

def receive(args) -> int:
    receiver_priv = env.load_x25519_private(
        os.path.join(args.keys_dir, "receiver_x25519.key"))
    sender_verify_key = env.load_ed25519_public(
        os.path.join(args.keys_dir, "sender_ed25519.pub"))

    broker = BrokerClient(args.broker_host, args.broker_port)
    transfer_id_hex = _resolve_transfer_id(broker, args.transfer_id)
    transfer_id = bytes.fromhex(transfer_id_hex)

    manifest = _fetch_verified_manifest(
        broker, transfer_id_hex, sender_verify_key, args.allow_redeliver,
        args.state_dir)

    total_chunks = manifest["total_chunks"]
    records = {r["index"]: r for r in manifest["chunks"]}
    if len(records) != total_chunks or set(records) != set(range(total_chunks)):
        raise VerificationError("manifest chunk list is incomplete or misindexed")

    # (3) ECDH with the manifest's ephemeral public key -> HKDF -> key.
    ephemeral_pub_raw = bytes.fromhex(manifest["ephemeral_x25519_pub"])
    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_raw)
    receiver_pub_raw = env.raw_public(receiver_priv.public_key())
    shared = receiver_priv.exchange(ephemeral_pub)
    chunk_key = env.derive_chunk_key(
        shared, transfer_id, ephemeral_pub_raw, receiver_pub_raw)
    aead = ChaCha20Poly1305(chunk_key)

    # Resume bookkeeping.
    part_path = args.out + ".part"
    progress_path = part_path + ".progress"
    done = _load_progress(progress_path, transfer_id_hex)
    if done and not os.path.exists(part_path):
        done = set()  # progress without data -> start clean
    if not done and os.path.exists(part_path):
        os.remove(part_path)  # stale partial with no progress -> discard
    if not os.path.exists(part_path):
        open(part_path, "wb").close()
    if done:
        print(f"[receiver] resuming: {len(done)}/{total_chunks} chunks already verified")

    # (4) per-chunk: fetch -> hash-check vs signed manifest -> AEAD-decrypt.
    tput = Throughput()
    try:
        with open(part_path, "r+b") as f:
            for index in range(total_chunks):
                if index in done:
                    continue
                rec = records[index]
                ct = broker.get(env.chunk_key(transfer_id_hex, index))
                if ct is None:
                    raise VerificationError(
                        f"chunk {index} missing on broker -- transfer incomplete")
                if hashlib.sha256(ct).hexdigest() != rec["ciphertext_sha256"]:
                    raise VerificationError(
                        f"chunk {index} ciphertext SHA-256 mismatch -- broker tampered")
                try:
                    plain = aead.decrypt(
                        env.chunk_nonce(index),
                        ct,
                        env.chunk_aad(transfer_id, index, total_chunks),
                    )
                except InvalidTag:
                    raise VerificationError(
                        f"chunk {index} AEAD tag invalid -- modified or misplaced")
                if len(plain) != rec["plaintext_len"]:
                    raise VerificationError(f"chunk {index} plaintext length mismatch")

                f.seek(index * CHUNK_SIZE)
                f.write(plain)
                done.add(index)
                tput.add(len(plain))
                # Checkpoint progress after every chunk (cheap: atomic rename of
                # a tiny JSON file) so a clean interruption resumes precisely.
                # The large data file is fsync'd less often -- see DESIGN.md on
                # the resume/durability trade-off.
                if len(done) % FSYNC_EVERY_CHUNKS == 0:
                    f.flush()
                    os.fsync(f.fileno())
                _save_progress(progress_path, transfer_id_hex, done)
            f.flush()
            os.fsync(f.fileno())
        _save_progress(progress_path, transfer_id_hex, done)
    finally:
        broker.close()

    # (5) whole-file plaintext hash vs the SIGNED manifest value.
    actual = sha256_file(part_path)
    if os.path.getsize(part_path) != manifest["file_size"]:
        raise VerificationError("reassembled file size does not match manifest")
    if actual != manifest["plaintext_sha256"]:
        raise VerificationError(
            f"whole-file SHA-256 mismatch:\n  got      {actual}"
            f"\n  expected {manifest['plaintext_sha256']}")

    atomic_promote(part_path, args.out)
    if os.path.exists(progress_path):
        os.remove(progress_path)
    _record_completed(args.state_dir, transfer_id_hex)

    print(f"[receiver] OK  {tput.report()}")
    print(f"[receiver] plaintext sha256 verified: {actual}")
    print(f"[receiver] wrote {args.out}  (original name: {manifest['filename']})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach B envelope receiver")
    ap.add_argument("--out", required=True, help="output path for the received file")
    ap.add_argument("--transfer-id", default=None,
                    help="transfer id to fetch; if omitted and the broker holds "
                         "exactly one transfer, it is auto-selected")
    ap.add_argument("--broker-host", default="127.0.0.1")
    ap.add_argument("--broker-port", type=int, default=9000)
    ap.add_argument("--keys-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "keys"))
    ap.add_argument("--state-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".recv-state"))
    ap.add_argument("--allow-redeliver", action="store_true",
                    help="bypass the freshness window and completed-transfer "
                         "ledger (legitimate re-delivery / testing)")
    args = ap.parse_args()
    line_buffered_stdout()
    try:
        return receive(args)
    except VerificationError as e:
        print(f"[receiver] TRANSFER REJECTED -- {e}")
        print("[receiver] no file promoted to the final name.")
        return 1
    except BrokerError as e:
        # Broker unreachable. Any verified chunks remain in <out>.part with a
        # progress file, so a later re-run resumes -- nothing is promoted.
        print(f"[receiver] download interrupted: {e}")
        print("[receiver] partial (if any) left under the .part name -- re-run to resume.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
