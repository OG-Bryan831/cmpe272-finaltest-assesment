# Approach B — Signed Encrypted Envelope via an Untrusted Broker

## 1. One-page design

An **application-layer** solution that is architecturally distinct from
Approach A in three ways: (1) the security lives in an *offline-built envelope*,
not in the transport; (2) keys are *pre-distributed long-lived public keys*, not
an interactive handshake; (3) the file flows **sender → untrusted broker →
receiver**, so no online contact between the two endpoints is required.

### Architecture

```
                          ┌───────────────────────────────────┐
                          │  broker.py  — UNTRUSTED relay/store│
                          │  holds: ciphertext chunks + signed │
                          │         manifest + signature       │
                          │  holds NO keys, NEVER sees plaintext│
                          └───────▲───────────────────┬────────┘
              PUT (TCP)           │                   │   GET (TCP)
       ┌──────────────────────────┘                   └───────────────────────┐
       │                                                                      │
┌──────┴────────────────────┐                              ┌──────────────────┴───────────┐
│ sender.py                 │                              │ receiver.py                  │
│  ephemeral X25519 ────┐    │                              │  long-lived X25519 priv ──┐  │
│  X25519 ECDH ─────────┼──▶ HKDF-SHA256 ──▶ 256-bit key    │  X25519 ECDH ─────────────┼─▶ same key
│  receiver X25519 pub ─┘    │  (per transfer)              │  manifest ephemeral pub ──┘  │
│                            │                              │                              │
│  per 1 MiB chunk:          │                              │  per chunk: SHA-256 vs signed │
│   ChaCha20-Poly1305 enc    │                              │   manifest → ChaCha20-Poly1305│
│  build manifest (hashes,   │                              │   decrypt → write at offset   │
│   sizes, ephemeral pub,    │                              │  verify whole-file SHA-256    │
│   timestamp)               │                              │  fsync → atomic rename        │
│  Ed25519-SIGN the manifest │                              │  Ed25519-VERIFY w/ sender pub │
└────────────────────────────┘                              └──────────────────────────────┘

  Key material, created ONCE by gen_keys.py, public halves distributed out of band:
     receiver X25519 keypair  — receiver keeps priv; sender gets receiver_x25519.pub
     sender   Ed25519 keypair — sender keeps priv;  receiver gets sender_ed25519.pub
     broker gets NOTHING.
```

### Key exchange / key management
- **Long-lived keys** (`gen_keys.py`): the receiver owns an **X25519** keypair
  (for key agreement); the sender owns an **Ed25519** keypair (for signing).
  Only the *public* halves are pre-distributed, out of band, and each side
  cross-checks against its **own pre-distributed copy** — never a key off the
  wire. Out of scope per spec §4.3 — we generate them locally and document it.
- **Per-transfer key:** the sender generates a fresh **ephemeral X25519**
  keypair, does ECDH against the receiver's long-lived X25519 public key, and
  runs the result through **HKDF-SHA256** (salt = random `transfer_id`,
  info = protocol version ‖ ephemeral pub ‖ receiver pub) to get a **256-bit**
  ChaCha20-Poly1305 key used only for this one transfer. The ephemeral half
  gives **forward secrecy**: it is deleted on success, after which a compromise
  of the receiver's *long-lived* key still cannot derive the old key (it would
  need the ephemeral private key, which is gone).
- **Mutual authentication, without a handshake:**
  - *Receiver authenticates sender* explicitly — the manifest is **Ed25519-
    signed**; the receiver verifies it with its pre-distributed `sender_ed25519.pub`.
  - *Sender authenticates receiver* implicitly — the envelope is encrypted to
    the receiver's known X25519 public key, so **only** the holder of the
    matching private key can derive the key and decrypt.

### Chunking and framing
- File split into **`CHUNK_SIZE = 1 MiB`** plaintext chunks; streamed, never
  fully in memory.
- Each chunk → **ChaCha20-Poly1305** ciphertext, stored as one broker blob
  (`<transfer_id>/chunk_NNNNNNNN`).
- A **manifest** (canonical JSON) records: `transfer_id`, `created_at`,
  `file_size`, `chunk_size`, `total_chunks`, ephemeral X25519 public key,
  whole-file `plaintext_sha256`, and for every chunk its index, plaintext
  length, and **ciphertext SHA-256**. The manifest is **Ed25519-signed**; the
  detached signature is a separate blob (`<transfer_id>/manifest.sig`).
- **Broker wire protocol** (TCP, length-prefixed frames): `PUT/GET/STAT/LIST`.
  The broker validates blob keys against a strict regex (no path traversal) and
  writes blobs via temp-file + atomic rename.

### Exact algorithms and parameters
| Element | Choice |
|---|---|
| Key agreement | **X25519** ECDH — ephemeral (sender) × long-lived (receiver) |
| KDF | **HKDF-SHA256** → 32-byte key; salt = `transfer_id`, info binds version + both public keys |
| Bulk cipher (AEAD) | **ChaCha20-Poly1305**, 256-bit key, **96-bit nonce**, 128-bit tag |
| Nonce construction | `4 zero bytes ‖ 8-byte big-endian chunk index`. Unique because the key is unique per transfer and the index is unique+monotonic — `(key, nonce)` never repeats |
| AEAD AAD | `transfer_id ‖ chunk_index ‖ total_chunks` — binds each ciphertext to its position and the total count (anti-reorder, anti-truncate) |
| Per-chunk integrity | SHA-256 of each ciphertext, listed in the **signed** manifest and checked *before* decryption |
| End-to-end integrity | **SHA-256** of the whole *plaintext*, in the signed manifest |
| Manifest signature | **Ed25519** over the canonical JSON manifest bytes |
| Replay window | `created_at` within 24 h (±5 min skew) **and** `transfer_id` not in the completed-transfer ledger |

### Failure handling, resumability, durability
- Receiver assembles into **`received.bin.part`**; verified chunk indices are
  checkpointed (atomic write) to `received.bin.part.progress` after every chunk,
  so a clean interruption **resumes** exactly. The large data file is `fsync`ed
  every 64 MiB; worst case after an *unclean* crash, the receiver re-fetches the
  chunks since the last `fsync` (harmless — they are re-verified) or, if the
  final whole-file hash fails, deletes the `.part` and restarts. Either way it
  is **fail-safe**: the final name only appears after the signed whole-file
  SHA-256 matches.
- Sender persists `transfer_id` + the ephemeral key in `.send-state/` so an
  interrupted upload resumes (re-using the same key/nonces, uploading only
  missing chunks). The state file — the one place the ephemeral private key
  touches disk — is **deleted on success**, which is what restores forward
  secrecy.
- Broker calls go through `broker_client.py`, which retries with exponential
  backoff (bounded, 5 attempts) — the Availability leg, without ever trusting
  what the broker returns.

## 2. Threat-model response (spec §6)

| Threat | CIAA | How Approach B addresses it |
|---|---|---|
| Passive eavesdropper records the whole TCP stream | **C** | Every chunk on the wire (and at rest on the broker) is ChaCha20-Poly1305 ciphertext under a key derived from X25519 ECDH; the key is never transmitted — only the ephemeral *public* key travels, inside the signed manifest. An eavesdropper (or the broker) sees ciphertext + metadata only. Verified by **B1**. |
| Active MITM modifies bytes mid-flight | **I** | Three independent layers: (1) each ciphertext's SHA-256 is in the **signed** manifest and is checked *before* decryption; (2) ChaCha20-Poly1305's AEAD tag fails on any modified ciphertext; (3) the whole-file plaintext SHA-256 in the signed manifest is verified before promotion. Any mismatch ⇒ abort, `.part` not promoted. Verified by **B2** (corrupted chunk → `SHA-256 mismatch`). |
| Attacker spoofs the sender or the receiver | **A (auth)** | The receiver verifies the Ed25519 manifest signature with its **pre-distributed** `sender_ed25519.pub` — a manifest from any other signer is rejected before decryption. The sender encrypts to the receiver's **pre-distributed** X25519 public key, so a spoofed receiver without the matching private key cannot derive the key. Verified by **B4** (manifest signed by a different identity → `signature INVALID`, no file) and **B3** (tampered manifest → signature fails). |
| Replay of an earlier valid transfer | **I / A** | The manifest carries a random `transfer_id` and a `created_at` timestamp, both covered by the Ed25519 signature (so neither can be altered). The receiver rejects a manifest outside a 24 h freshness window and rejects any `transfer_id` already in its completed-transfer ledger. Verified by **B7** (re-delivering a completed transfer → rejected as `replay`). |
| Connection drops at 80% transferred | **A (avail)** | Receiver side: verified chunks are checkpointed per-chunk in `.part.progress`; a re-run skips them and finishes — the `.part` is never promoted until the signed whole-file hash matches. Sender side: `transfer_id` + ephemeral key are persisted, so a re-run uploads only the missing chunks. Verified by **B5** (missing chunk → resumable `.part`, re-run completes) and **B6** (hostile broker cuts the upload after 3 PUTs → re-run resumes, `already present`). |
| Untrusted intermediary (broker / object store) | **C / I** | The broker is the *core* of this design and is fully untrusted. It receives only ciphertext blobs + a signed manifest + a detached signature — **no key material, no plaintext**. A broker compromise leaks only ciphertext. A broker that drops, reorders, duplicates, or modifies blobs is caught: missing/short ⇒ `chunk missing` abort; modified chunk ⇒ signed-hash mismatch then AEAD-tag failure; modified manifest ⇒ Ed25519 signature failure; reorder ⇒ AAD-bound chunk index. All fail closed. Verified by **B2**, **B3**, **B6**. |
