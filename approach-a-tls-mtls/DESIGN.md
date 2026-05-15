# Approach A — Mutually-Authenticated TLS 1.3 Streaming

## 1. One-page design

A **transport-layer** solution: the sender and receiver speak directly to each
other over a single TLS 1.3 connection in which **both** sides present
certificates. The security envelope *is* the TLS channel; the application layer
adds only an end-to-end plaintext hash and a temp-file/atomic-rename discipline.

### Architecture

```
   ┌─────────────────────┐                         ┌───────────────────────┐
   │  sender.py          │   TLS 1.3 (mutual auth) │  receiver.py          │
   │  (TLS client)       │◀═══════════════════════▶│  (TLS server)         │
   │                     │   single TCP connection │                       │
   │  presents           │                         │  presents             │
   │   sender.crt + key  │                         │   receiver.crt + key  │
   │  verifies peer with │                         │  verifies peer with   │
   │   ca.crt + hostname │                         │   ca.crt (CERT_REQ.)  │
   └─────────┬───────────┘                         └───────────┬───────────┘
             │ reads file in 1 MiB chunks                      │ writes received.bin.part
             │ frames: [8-byte len][payload] ... [len=0]       │ verifies SHA-256, fsync,
             │ then 32-byte SHA-256(plaintext) trailer         │ atomic rename → received.bin
             ▼                                                 ▼
        test_4gb.bin                                      received.bin

   Trust material, created ONCE by gen_certs.py, distributed out of band:
        offline CA  ──signs──▶ receiver.crt (SERVER_AUTH, SAN localhost/127.0.0.1)
                    ──signs──▶ sender.crt   (CLIENT_AUTH)
        both endpoints hold ca.crt; neither private key ever moves.
```

### Key exchange / key management
- **Long-lived identity:** an offline root CA (`gen_certs.py`) issues one leaf
  cert per role. `ca.crt` is the only shared, pre-distributed item; the three
  private keys (`ca.key`, `sender.key`, `receiver.key`) never leave their host.
  Out of scope per spec §4.3 — we generate a self-signed CA locally and document
  it here.
- **Session keys:** established by the **TLS 1.3 handshake** — ephemeral ECDHE
  on every connection. The long-lived cert keys only *sign* the handshake; they
  never encrypt data, so a later key compromise cannot decrypt a recorded
  session (**forward secrecy**). We pin `minimum_version = TLSv1_3`, which is
  ECDHE-only, and we do **not** enable 0-RTT early data (which would be
  replayable).
- **Mutual authentication:** the receiver sets `verify_mode = CERT_REQUIRED`, so
  a client with no cert or a cert not chaining to `ca.crt` fails the handshake.
  The sender uses `PROTOCOL_TLS_CLIENT` with `check_hostname = True`, so a
  receiver presenting the wrong cert or hostname is rejected before any bytes
  flow.

### Chunking and framing
- The file is streamed in **`CHUNK_SIZE = 1 MiB`** reads (`common/util.py`); the
  4 GB file is never resident in memory on either side.
- On top of the TLS byte-stream the application frames each chunk as
  **`[8-byte big-endian length][payload]`**. A **zero-length frame** marks
  end-of-stream, followed by a **32-byte raw SHA-256** trailer of the whole
  plaintext.
- **Resume negotiation** (right after the handshake): the receiver sends its
  current `.part` size (8-byte BE); the sender replies with
  `[8-byte total_size][8-byte accepted_offset]` and streams from that offset.

### Exact algorithms and parameters
| Element | Choice |
|---|---|
| Channel | TLS 1.3 (`ssl` stdlib, OpenSSL), `minimum_version = TLSv1_3` |
| Bulk cipher (AEAD) | TLS 1.3 negotiates AES-256-GCM / AES-128-GCM / ChaCha20-Poly1305 — all AEAD; never CBC/CTR-without-MAC |
| Key exchange | Ephemeral ECDHE (TLS 1.3 default groups: X25519 / secp256r1) |
| Certificate keys | ECDSA **secp256r1 (P-256)**, SHA-256 signatures, 365-day validity, `BasicConstraints`/`KeyUsage`/`ExtendedKeyUsage` set |
| End-to-end integrity | **SHA-256** over the full *plaintext*, sent as a trailer and recomputed by the receiver |
| Mutual auth | X.509 cert chain validation to a shared offline CA, both directions; hostname check on the client |

### Failure handling (fail-closed / fail-safe)
- Receiver writes to **`received.bin.part`**, never the final name.
- On verification failure (size or SHA-256 mismatch) the `.part` file is
  **deleted** — a corrupt partial is never left on disk.
- On a mid-transfer connection drop the `.part` file is **kept** (under its temp
  name only) so a re-run **resumes**; it is still never promoted until the full
  hash verifies. A TCP FIN is *not* treated as proof of completion — only the
  explicit zero-length frame + matching SHA-256 is.
- `fsync` before the atomic `os.replace()` so the final file is durable.

## 2. Threat-model response (spec §6)

| Threat | CIAA | How Approach A addresses it |
|---|---|---|
| Passive eavesdropper records the whole TCP stream | **C** | Every application byte travels inside TLS 1.3 AEAD records. The handshake transcript and ECDHE key shares are exchanged before any file byte; the symmetric keys are derived, never transmitted. The eavesdropper sees only ciphertext + handshake metadata. Verified by test **A1** (transfer works) and the fact that `--port` traffic is a TLS stream. |
| Active MITM modifies bytes mid-flight | **I** | Every TLS 1.3 record carries an AEAD tag keyed by the session keys; a flipped byte makes the record fail to authenticate and the connection aborts. The receiver additionally recomputes the **plaintext SHA-256** and compares it to the sender's signed-over-the-channel trailer. The `.part` file is never promoted. Verified by test **A2** (`tamper_proxy --mode flip` → both sides abort, no final file). |
| Attacker spoofs the sender or the receiver | **A (auth)** | Mutual X.509 auth: the receiver requires a client cert chaining to the offline CA (`CERT_REQUIRED`); the sender verifies the server cert chain **and** hostname. A cert not signed by the CA fails the handshake before any data. Verified by test **A3** (rogue non-CA cert → handshake `REJECTED`, no file). |
| Replay of an earlier valid transfer | **I / A** | TLS 1.3 runs a fresh ECDHE handshake per connection with fresh random nonces and per-record sequence numbers; a recorded ciphertext stream cannot be decrypted or re-injected into a new session. 0-RTT early data (the one replayable TLS 1.3 feature) is **not enabled**. |
| Connection drops at 80% transferred | **A (avail)** | The receiver streams into `received.bin.part`. A drop raises a connection error that is caught: the `.part` is flushed + kept, nothing is promoted, exit code is non-zero. Re-running sender + receiver negotiates a resume offset and continues; the receiver re-hashes the existing prefix so the end-to-end SHA-256 still covers the whole file. Verified by test **A4** (`tamper_proxy --mode truncate` then resume → final hash matches). |
| Untrusted intermediary (broker / object store) | **C / I** | Not applicable — Approach A is a *direct* sender↔receiver connection with no intermediary. (Approach B is the one that addresses an untrusted broker.) |
