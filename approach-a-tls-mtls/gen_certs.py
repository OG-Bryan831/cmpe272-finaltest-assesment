#!/usr/bin/env python3
"""Generate the X.509 trust material for Approach A (mutually-authenticated TLS).

Out-of-band trust assumption (spec 4.3 allows a self-signed cert pair, as long
as we document how it got there): both endpoints are provisioned, before any
transfer, with the SAME offline CA certificate `ca.crt`. That CA signs exactly
two leaf certificates -- one for the receiver (TLS server role) and one for the
sender (TLS client role). Neither private key ever leaves its owner; only
`ca.crt` is "shared". In a real deployment the CA key would live on an offline
host -- here we generate everything locally for a self-contained demo and then
the CA key is irrelevant to the transfer itself.

Run once per fresh clone:  python gen_certs.py
Writes into ./certs/ :  ca.crt ca.key  receiver.crt receiver.key  sender.crt sender.key
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
# P-256 leaf/CA keys: widely reviewed, fast, and pairs naturally with the
# ECDHE-only TLS 1.3 suites the transfer enforces.
CURVE = ec.SECP256R1()
VALIDITY_DAYS = 365


def _write(certs_dir: str, name: str, data: bytes, *, secret: bool) -> None:
    path = os.path.join(certs_dir, name)
    # Private keys are written 0600 so they are never world-readable on disk.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600 if secret else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    print(f"  wrote {path}")


def _key_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def main() -> int:
    ap = argparse.ArgumentParser(description="Approach A trust-material generator")
    ap.add_argument("--out-dir", default=DEFAULT_CERTS_DIR,
                    help="directory to write CA + leaf certs into")
    certs_dir = ap.parse_args().out_dir

    os.makedirs(certs_dir, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=VALIDITY_DAYS)

    # --- 1. Offline root CA (self-signed) ---------------------------------
    ca_key = ec.generate_private_key(CURVE)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cmpe272-demo-CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write(certs_dir, "ca.key", _key_pem(ca_key), secret=True)
    _write(certs_dir, "ca.crt", _cert_pem(ca_cert), secret=False)

    # --- 2. Leaf certs for receiver (server) and sender (client) ----------
    def issue_leaf(cn: str, eku: x509.ExtendedKeyUsage, sans: list) -> tuple:
        leaf_key = ec.generate_private_key(CURVE)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(eku, critical=False)
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        return leaf_key, builder.sign(ca_key, hashes.SHA256())

    # Receiver acts as the TLS server; SANs let the sender verify hostname.
    recv_key, recv_cert = issue_leaf(
        "transfer-receiver",
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
    )
    _write(certs_dir, "receiver.key", _key_pem(recv_key), secret=True)
    _write(certs_dir, "receiver.crt", _cert_pem(recv_cert), secret=False)

    # Sender acts as the TLS client; CLIENT_AUTH EKU + CA signature is what the
    # receiver checks to authenticate the sender.
    send_key, send_cert = issue_leaf(
        "transfer-sender",
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        [],
    )
    _write(certs_dir, "sender.key", _key_pem(send_key), secret=True)
    _write(certs_dir, "sender.crt", _cert_pem(send_cert), secret=False)

    print(f"\nDone. Trust material is in {certs_dir} (git-ignored).")
    print("Receiver needs: receiver.crt receiver.key ca.crt")
    print("Sender needs:   sender.crt sender.key ca.crt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
