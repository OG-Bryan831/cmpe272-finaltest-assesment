# AI Usage Notes

## Tools used

Claude (Anthropic, **Opus 4.7**) via the **Claude Code CLI** was the primary
tool — it drafted essentially all the code and the threat-model tables. After
my Claude Code usage limit hit, I switched to **Cursor (also Opus 4.7)** for
the verification / debug pass. 

## ChatGPT prompt
Since ChatGPT is free I used it to create better prompts to allow Claude to 
not utilize as many tokens. As well as, to ensure all my architectural choices
were properly followed by claude throughout development.

## What Claude wrote end to end

Under my architectural direction, Claude scaffolded and wrote the `common/`
plumbing, both sender/receiver pairs, the key/cert generators, the untrusted
broker + retrying client, the shared `envelope.py` crypto module, and the
`scripts/` test harness + MITM proxy. I made the architectural calls —
Python + PyCA `cryptography`, Approach A = mutual TLS 1.3 streaming,
Approach B = offline-encrypted Ed25519-signed envelope through an untrusted
broker — and Claude implemented within those constraints.

## Pitfalls I checked against the code (Section 12)

- **Nonce reuse** — fresh per-transfer ChaCha20-Poly1305 key from ephemeral
X25519 ECDH (`envelope.derive_chunk_key`); nonce = 64-bit chunk index, so
`(key, nonce)` cannot repeat.
- **AEAD tag truncation / integer overflow** — PyCA `ChaCha20Poly1305` always
emits the full 16-byte tag; chunk index is a 64-bit BE int (safe to 2^64).
- **Chunk-boundary attacks** — AAD = `transfer_id ‖ index ‖ total_chunks`, and
`total_chunks` is in the *signed* manifest, so reorder/duplicate/truncate
fail the tag.
- **Missing fsync / partial-file leakage** — receivers write to `*.part`,
fsync, verify the whole-file SHA-256, *then* atomically rename. Failure ⇒
`.part` deleted; TCP FIN is never proof of completion.
- **Plaintext vs ciphertext hash** — SHA-256 is over the plaintext on both
approaches (spec pitfall).

## Concrete example of catching Claude getting it wrong

1. **Security pushback — nonce reuse.** Claude's first envelope sketch
   reached for a single long-lived ChaCha20-Poly1305 key with a chunk-counter
   nonce. That's the canonical AEAD footgun: the second the same long-lived
   key is used for any other transfer the counter restarts at 0 and you have
   catastrophic `(key, nonce)` reuse — Section 12's first pitfall by name. I
   pushed back: derive a **fresh per-transfer key** from an ephemeral X25519
   ECDH, then HKDF-SHA256 it (`envelope.derive_chunk_key`). The counter
   nonce is only safe *because* the key is unique per transfer; this also
   buys forward secrecy as a side effect.
2. **Robustness bug — wrong chunk-key format.** The harness referenced
   `chunk_00000`, but `envelope.chunk_key` is `chunk_%08d` →
   `chunk_00000000`. The integrity test was silently a no-op until I ran the
   suite and the tamper case failed to trip.
3. **Robustness bug — block-buffered stdout.** The long-lived programs
   (broker, receivers) were block-buffering stdout, so the harness's
   readiness check timed out with `(broker failed to start)` even though the
   broker had started. Fix: wire `common.util.line_buffered_stdout()` into
   every long-lived process.

The robustness bugs were only caught by actually running the suite — a
reminder that *"Claude said it would work"* is not acceptable evidence.

## Threat-table verification

Claude drafted the threat-model rows in each `DESIGN.md`. I verified each
row maps to a concrete code path and a passing test (A1–A4, B1–B7 in
`scripts/run_tests.sh`) before accepting them.

## One thing Claude did better than expected

The test harness itself — Claude turned every abstract threat-row into a
deterministic, self-checking test, including a byte-flipping MITM proxy and
a `--fail-after-puts` "hostile broker" switch. The default crypto picks
(ChaCha20-Poly1305, X25519, Ed25519, ephemeral-static ECDH for forward
secrecy) also matched the calls I'd have made by hand.

## One thing Claude did worse

Robustness bugs that only surface on running (the `chunk_00000` typo and the
block-buffered stdout above), and Claude took several extra prompts and added guidance to 
complete the assesment. 