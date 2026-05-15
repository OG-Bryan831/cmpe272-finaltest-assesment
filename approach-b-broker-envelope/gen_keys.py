#!/usr/bin/env python3
"""Generate the long-lived key material for Approach B (encrypted envelope).

Out-of-band trust assumption (spec 4.3 allows pre-shared key files, as long as
we document how they got there): before any transfer, two long-lived keypairs
are generated and their PUBLIC halves are exchanged out of band:

  * Receiver owns an X25519 keypair. Its PUBLIC key is given to the sender.
    -> lets the sender encrypt so that ONLY the receiver can decrypt
       (this is the sender's assurance of the receiver's identity).
  * Sender owns an Ed25519 keypair. Its PUBLIC key is given to the receiver.
    -> lets the receiver verify the signed manifest
       (this is the receiver's assurance of the sender's identity).

Private keys never move. The broker is given NEITHER private key and never sees
plaintext, so it stays fully untrusted.

Run once per fresh clone:  python gen_keys.py
Writes into ./keys/ :
  receiver_x25519.key  receiver_x25519.pub      (receiver keeps both; sender gets .pub)
  sender_ed25519.key   sender_ed25519.pub       (sender keeps both; receiver gets .pub)
"""
from __future__ import annotations

import argparse
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

DEFAULT_KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


def _write(keys_dir: str, name: str, data: bytes, *, secret: bool) -> None:
    path = os.path.join(keys_dir, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if secret else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    print(f"  wrote {path}{'  (PRIVATE, 0600)' if secret else '  (public)'}")


def _priv_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _pub_pem(key) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach B key-material generator")
    ap.add_argument("--out-dir", default=DEFAULT_KEYS_DIR,
                    help="directory to write the keypairs into")
    keys_dir = ap.parse_args().out_dir

    os.makedirs(keys_dir, exist_ok=True)

    # Receiver's long-lived X25519 keypair (key agreement / decryption).
    recv_x = X25519PrivateKey.generate()
    _write(keys_dir, "receiver_x25519.key", _priv_pem(recv_x), secret=True)
    _write(keys_dir, "receiver_x25519.pub", _pub_pem(recv_x.public_key()), secret=False)

    # Sender's long-lived Ed25519 keypair (manifest signing / identity).
    send_ed = Ed25519PrivateKey.generate()
    _write(keys_dir, "sender_ed25519.key", _priv_pem(send_ed), secret=True)
    _write(keys_dir, "sender_ed25519.pub", _pub_pem(send_ed.public_key()), secret=False)

    print(f"\nDone. Key material is in {keys_dir} (git-ignored).")
    print("Sender needs:   sender_ed25519.key  receiver_x25519.pub")
    print("Receiver needs: receiver_x25519.key  sender_ed25519.pub")
    print("Broker needs:   NOTHING -- it never holds a key or plaintext.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
