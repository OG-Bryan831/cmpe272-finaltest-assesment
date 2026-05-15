# CMPE 272 — Secure 4 GB File Transfer (two approaches)

Two **architecturally distinct** end-to-end-secure file transfer
implementations, each satisfying **CIAA** (Confidentiality, Integrity,
Authenticity, Availability) over a fully hostile network.

| | Approach A | Approach B |
|---|---|---|
| Directory | [`approach-a-tls-mtls/`](approach-a-tls-mtls/) | [`approach-b-broker-envelope/`](approach-b-broker-envelope/) |
| Security layer | **Transport** — mutually-authenticated TLS 1.3 | **Application** — offline-encrypted signed envelope |
| Key management | Interactive ECDHE handshake + X.509 certs | Pre-distributed long-lived public keys (X25519 + Ed25519) |
| Topology | Direct sender ↔ receiver | sender → **untrusted broker** → receiver |
| Channel | One streamed TLS connection | Chunked blobs + a signed manifest, store-and-forward |
| Design doc | [`approach-a-tls-mtls/DESIGN.md`](approach-a-tls-mtls/DESIGN.md) | [`approach-b-broker-envelope/DESIGN.md`](approach-b-broker-envelope/DESIGN.md) |

Both stream the file in fixed **1 MiB** chunks (never loading 4 GB into
memory), verify a whole-file **SHA-256 of the plaintext** end to end, use only
**AEAD** ciphers from the well-reviewed PyCA `cryptography` library, mutually
authenticate both endpoints, and **fail closed** — a verification failure or a
dropped connection never leaves a valid-looking file under the final name.

## Repository layout

```
common/                      shared, security-agnostic plumbing (chunking, framing, hashing)
approach-a-tls-mtls/
    gen_certs.py             one-time: offline CA + sender/receiver leaf certs
    sender.py  receiver.py   the two programs
    DESIGN.md                architecture + threat-model table
approach-b-broker-envelope/
    gen_keys.py              one-time: X25519 + Ed25519 long-lived keypairs
    envelope.py              shared crypto: ECDH/HKDF, nonce/AAD, manifest format
    broker.py                the UNTRUSTED relay/blob store
    broker_client.py         retrying broker client (no trust, just availability)
    sender.py  receiver.py   the two programs
    DESIGN.md                architecture + threat-model table
scripts/
    gen_test_file.sh         make the local 4 GB test file (never committed)
    tamper_proxy.py          MITM simulator used by the test harness
    run_tests.sh             11 automated threat-model tests (both approaches)
requirements.txt   AI_NOTES.md   .gitignore
```

Generated material (certs, keys, the test file, broker storage, `.part` files,
resume state) is **git-ignored** — nothing secret is committed. A fresh clone
regenerates all of it with the `gen_*` scripts below.

## Install (≈1 minute)

Requires Python 3.9+ (developed on 3.13). One dependency: PyCA `cryptography`.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

All commands below assume the venv is active (or prefix with `./.venv/bin/`).

## Generate the 4 GB test file (spec §5.2)

Never committed (`.gitignore` excludes it). Pick either:

```bash
scripts/gen_test_file.sh test_4gb.bin 4          # 4 GiB of random bytes
# or the spec's one-liner:
dd if=/dev/urandom of=test_4gb.bin bs=1m count=4096
```

For a quick smoke run, a tiny file works the same way:
`scripts/gen_test_file.sh small.bin 0.01`.

---

## Approach A — run end to end

```bash
cd approach-a-tls-mtls
python gen_certs.py                              # once: writes ./certs/ (git-ignored)

# terminal 1 — receiver (TLS server, requires a client cert):
python receiver.py --out received_A.bin --port 8443

# terminal 2 — sender (TLS client, presents a client cert):
python sender.py --file ../test_4gb.bin --port 8443

# verify the two files are byte-identical:
shasum -a 256 ../test_4gb.bin received_A.bin
```

The receiver prints `sha256 verified: …`; both hashes must match. If the
connection drops, just re-run both commands — the receiver resumes from
`received_A.bin.part`.

## Approach B — run end to end

```bash
cd approach-b-broker-envelope
python gen_keys.py                               # once: writes ./keys/ (git-ignored)

# terminal 1 — the UNTRUSTED broker (holds ciphertext only, no keys):
python broker.py --port 9000

# terminal 2 — sender: encrypt + sign + upload. Prints a transfer id.
python sender.py --file ../test_4gb.bin --broker-port 9000

# terminal 3 — receiver: download + verify + decrypt.
#   (omit --transfer-id if the broker holds exactly one transfer)
python receiver.py --out received_B.bin --broker-port 9000 --transfer-id <id-from-sender>

# verify:
shasum -a 256 ../test_4gb.bin received_B.bin
```

If the upload or download is interrupted, re-run the same command — the sender
resumes from `.send-state/`, the receiver from `received_B.bin.part.progress`.

---

## Run the threat-model test suite

Exercises every row of the spec §6 threat-model table on both approaches
(byte-flip, rogue cert, wrong signing key, tampered manifest, truncated
connection, missing chunk, hostile broker, replay) — all on loopback with a
small file, in ~30 seconds:

```bash
bash scripts/run_tests.sh
```

Expected tail:

```
 RESULTS:  11 passed, 0 failed
```

## Notes
- **Network:** loopback (`127.0.0.1`) by default; pass `--host` to run sender and
  receiver on separate machines. TCP only.
- **Crypto:** only PyCA `cryptography` (OpenSSL-backed) and Python's stdlib
  `ssl` — no hand-rolled ciphers, no broken primitives, no raw CBC/CTR.
- **AI usage:** see [`AI_NOTES.md`](AI_NOTES.md).
