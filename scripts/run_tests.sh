#!/usr/bin/env bash
# Threat-model test harness for both approaches (spec section 6 + section 13:
# "test the failure paths on purpose"). Runs entirely on loopback with a small
# file, but exercises EVERY row of the threat-model table:
#
#   happy path .......... file transfers, SHA-256 matches end to end
#   integrity ........... a flipped byte / corrupted blob is rejected, no file
#   authenticity ........ wrong cert / wrong signing key fails closed
#   availability ........ a dropped connection resumes; no partial promoted
#   replay .............. a re-delivered transfer is rejected
#
# Each test uses its own TCP port so the cases are fully independent.
# Exit code 0 iff every check passes. Set KEEP_TMP=1 to keep the work dir.
set -uo pipefail   # deliberately NOT -e: several commands are EXPECTED to fail.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
A="$ROOT/approach-a-tls-mtls"
B="$ROOT/approach-b-broker-envelope"
PROXY="$ROOT/scripts/tamper_proxy.py"
TMP="$(mktemp -d /tmp/cmpe272_tests.XXXXXX)"

PASS=0
FAIL=0
ok() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
no() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

cleanup() {
    kill $(jobs -p) 2>/dev/null
    if [ "${KEEP_TMP:-0}" = "1" ]; then
        echo "(KEEP_TMP=1 -- work dir kept at $TMP)"
    else
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT

sha() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }

wait_log() {  # <file> <substring> [timeout_s]
    local f="$1" s="$2" t="${3:-10}" i=0
    while [ "$i" -lt "$((t * 20))" ]; do
        [ -f "$f" ] && grep -q -- "$s" "$f" 2>/dev/null && return 0
        sleep 0.05; i=$((i + 1))
    done
    return 1
}

flip_byte() {  # <file> <offset>
    "$PY" - "$1" "$2" <<'PY'
import sys
path, off = sys.argv[1], int(sys.argv[2])
with open(path, "r+b") as f:
    f.seek(off); b = f.read(1)
    f.seek(off); f.write(bytes([b[0] ^ 0xFF]))
PY
}

echo "=============================================================="
echo " CMPE 272 secure-transfer threat-model test harness"
echo " temp dir: $TMP"
echo "=============================================================="

# --- one-time setup --------------------------------------------------------
echo "[setup] generating fresh trust material + a small test file ..."
"$PY" "$A/gen_certs.py" >/dev/null
"$PY" "$B/gen_keys.py"  >/dev/null
SRC="$TMP/src.bin"
"$PY" - "$SRC" <<'PY'
import os, sys
# 5 MiB + a partial chunk: exercises multi-chunk AND a short final chunk.
open(sys.argv[1], "wb").write(os.urandom(5 * 1024 * 1024 + 12345))
PY
SRC_HASH="$(sha "$SRC")"
echo "[setup] test file: $(wc -c < "$SRC" | tr -d ' ') bytes  sha256=$SRC_HASH"
echo

############################################################################
echo "### APPROACH A -- mutually-authenticated TLS 1.3 streaming ###"
############################################################################

# --- A1: happy path --------------------------------------------------------
OUT="$TMP/a1.bin"; PORT=8601
"$PY" "$A/receiver.py" --out "$OUT" --port "$PORT" >"$TMP/a1.recv.log" 2>&1 &
RPID=$!
wait_log "$TMP/a1.recv.log" listening
"$PY" "$A/sender.py" --file "$SRC" --port "$PORT" >"$TMP/a1.send.log" 2>&1
SC=$?
wait $RPID; RC=$?
if [ "$SC" -eq 0 ] && [ "$RC" -eq 0 ] && [ -f "$OUT" ] && [ "$(sha "$OUT")" = "$SRC_HASH" ]; then
    ok "A1 happy path: 4-program transfer, end-to-end SHA-256 matches"
else
    no "A1 happy path"; cat "$TMP/a1.recv.log" "$TMP/a1.send.log"
fi

# --- A2: integrity -- active MITM flips a byte mid-stream ------------------
OUT="$TMP/a2.bin"; PORT=8602; PXP=8612
"$PY" "$A/receiver.py" --out "$OUT" --port "$PORT" >"$TMP/a2.recv.log" 2>&1 &
RPID=$!
wait_log "$TMP/a2.recv.log" listening
"$PY" "$PROXY" --listen "127.0.0.1:$PXP" --target "127.0.0.1:$PORT" \
    --mode flip --at 5000 --direction c2s >"$TMP/a2.proxy.log" 2>&1 &
PXID=$!
wait_log "$TMP/a2.proxy.log" "mode="
"$PY" "$A/sender.py" --file "$SRC" --port "$PXP" >"$TMP/a2.send.log" 2>&1
SC=$?
wait $RPID; RC=$?
kill $PXID 2>/dev/null
if [ "$RC" -ne 0 ] && [ "$SC" -ne 0 ] && [ ! -f "$OUT" ]; then
    ok "A2 integrity: TLS rejects the flipped byte, no file promoted"
else
    no "A2 integrity (rc=$RC sc=$SC)"; cat "$TMP/a2.recv.log" "$TMP/a2.send.log"
fi

# --- A3: authenticity -- sender presents a cert NOT signed by the CA -------
OUT="$TMP/a3.bin"; PORT=8603
"$PY" "$A/gen_certs.py" --out-dir "$TMP/rogue_certs" >/dev/null   # independent rogue CA
"$PY" "$A/receiver.py" --out "$OUT" --port "$PORT" >"$TMP/a3.recv.log" 2>&1 &
RPID=$!
wait_log "$TMP/a3.recv.log" listening
"$PY" "$A/sender.py" --file "$SRC" --port "$PORT" \
    --certs-dir "$TMP/rogue_certs" >"$TMP/a3.send.log" 2>&1
SC=$?
wait $RPID; RC=$?
if [ "$RC" -ne 0 ] && [ "$SC" -ne 0 ] && [ ! -f "$OUT" ] \
   && grep -q "REJECTED" "$TMP/a3.recv.log" "$TMP/a3.send.log"; then
    ok "A3 authenticity: rogue (non-CA) cert -> mutual TLS fails closed"
else
    no "A3 authenticity"; cat "$TMP/a3.recv.log" "$TMP/a3.send.log"
fi

# --- A4: availability -- connection truncated, then resumed ----------------
OUT="$TMP/a4.bin"; PORT=8604; PXP=8614
# round 1: proxy truncates the stream at ~2 MiB
"$PY" "$A/receiver.py" --out "$OUT" --port "$PORT" >"$TMP/a4.recv1.log" 2>&1 &
RPID=$!
wait_log "$TMP/a4.recv1.log" listening
"$PY" "$PROXY" --listen "127.0.0.1:$PXP" --target "127.0.0.1:$PORT" \
    --mode truncate --at 2097152 --direction c2s >"$TMP/a4.proxy.log" 2>&1 &
PXID=$!
wait_log "$TMP/a4.proxy.log" "mode="
"$PY" "$A/sender.py" --file "$SRC" --port "$PXP" >"$TMP/a4.send1.log" 2>&1
wait $RPID; RC1=$?
kill $PXID 2>/dev/null
PART_OK=0; [ "$RC1" -ne 0 ] && [ ! -f "$OUT" ] && [ -f "$OUT.part" ] && PART_OK=1
# round 2: direct connection, resumes from the .part offset
"$PY" "$A/receiver.py" --out "$OUT" --port "$PORT" >"$TMP/a4.recv2.log" 2>&1 &
RPID=$!
wait_log "$TMP/a4.recv2.log" listening
"$PY" "$A/sender.py" --file "$SRC" --port "$PORT" >"$TMP/a4.send2.log" 2>&1
SC=$?
wait $RPID; RC2=$?
if [ "$PART_OK" -eq 1 ] && [ "$SC" -eq 0 ] && [ "$RC2" -eq 0 ] \
   && [ -f "$OUT" ] && [ ! -f "$OUT.part" ] && [ "$(sha "$OUT")" = "$SRC_HASH" ] \
   && grep -q resuming "$TMP/a4.recv2.log"; then
    ok "A4 availability: truncated transfer left a .part, re-run resumed + verified"
else
    no "A4 availability (part_ok=$PART_OK rc1=$RC1 rc2=$RC2 sc=$SC)"
    cat "$TMP/a4.recv1.log" "$TMP/a4.recv2.log"
fi

echo
############################################################################
echo "### APPROACH B -- signed encrypted envelope via an UNTRUSTED broker ###"
############################################################################

# start_broker <port> <storage_dir> <log> [extra args...]   ; sets BPID
start_broker() {
    local port="$1" storage="$2" log="$3"; shift 3
    "$PY" "$B/broker.py" --port "$port" --storage "$storage" "$@" >"$log" 2>&1 &
    BPID=$!
    wait_log "$log" "blob store" || { echo "  (broker failed to start)"; cat "$log"; }
}
stop_broker() { kill $BPID 2>/dev/null; wait $BPID 2>/dev/null; }

# upload <port> <state_dir> <log>   ; echoes the transfer id
upload() {
    "$PY" "$B/sender.py" --file "$SRC" --broker-port "$1" --state-dir "$2" >"$3" 2>&1
    grep "transfer id" "$3" | awk '{print $NF}'
}

# --- B1: happy path --------------------------------------------------------
OUT="$TMP/b1.bin"; PORT=8701
start_broker "$PORT" "$TMP/b1_store" "$TMP/b1.broker.log"
TID="$(upload "$PORT" "$TMP/b1_send" "$TMP/b1.send.log")"
"$PY" "$B/receiver.py" --out "$OUT" --broker-port "$PORT" --transfer-id "$TID" \
    --state-dir "$TMP/b1_recv" >"$TMP/b1.recv.log" 2>&1
RC=$?
stop_broker
if [ -n "$TID" ] && [ "$RC" -eq 0 ] && [ -f "$OUT" ] && [ "$(sha "$OUT")" = "$SRC_HASH" ]; then
    ok "B1 happy path: encrypt -> broker -> verify, end-to-end SHA-256 matches"
else
    no "B1 happy path"; cat "$TMP/b1.broker.log" "$TMP/b1.send.log" "$TMP/b1.recv.log"
fi

# --- B2: integrity -- a malicious broker corrupts a ciphertext chunk -------
OUT="$TMP/b2.bin"; PORT=8702
start_broker "$PORT" "$TMP/b2_store" "$TMP/b2.broker.log"
TID="$(upload "$PORT" "$TMP/b2_send" "$TMP/b2.send.log")"
flip_byte "$TMP/b2_store/$TID/chunk_00000000" 40      # broker tampers with a chunk
"$PY" "$B/receiver.py" --out "$OUT" --broker-port "$PORT" --transfer-id "$TID" \
    --state-dir "$TMP/b2_recv" >"$TMP/b2.recv.log" 2>&1
RC=$?
stop_broker
if [ "$RC" -ne 0 ] && [ ! -f "$OUT" ] && grep -q "SHA-256 mismatch" "$TMP/b2.recv.log"; then
    ok "B2 integrity: corrupted chunk caught by signed manifest hash, no file"
else
    no "B2 integrity"; cat "$TMP/b2.broker.log" "$TMP/b2.recv.log"
fi

# --- B3: integrity -- a malicious broker tampers with the manifest --------
OUT="$TMP/b3.bin"; PORT=8703
start_broker "$PORT" "$TMP/b3_store" "$TMP/b3.broker.log"
TID="$(upload "$PORT" "$TMP/b3_send" "$TMP/b3.send.log")"
flip_byte "$TMP/b3_store/$TID/manifest" 30            # broker tampers with metadata
"$PY" "$B/receiver.py" --out "$OUT" --broker-port "$PORT" --transfer-id "$TID" \
    --state-dir "$TMP/b3_recv" >"$TMP/b3.recv.log" 2>&1
RC=$?
stop_broker
if [ "$RC" -ne 0 ] && [ ! -f "$OUT" ] && grep -q "signature INVALID" "$TMP/b3.recv.log"; then
    ok "B3 integrity: tampered manifest fails the Ed25519 signature check"
else
    no "B3 integrity"; cat "$TMP/b3.broker.log" "$TMP/b3.recv.log"
fi

# --- B4: authenticity -- manifest signed by the wrong identity -------------
OUT="$TMP/b4.bin"; PORT=8704
start_broker "$PORT" "$TMP/b4_store" "$TMP/b4.broker.log"
TID="$(upload "$PORT" "$TMP/b4_send" "$TMP/b4.send.log")"
# Receiver is provisioned with a DIFFERENT sender public key (attacker identity).
mkdir -p "$TMP/b4_recvkeys"
cp "$B/keys/receiver_x25519.key" "$TMP/b4_recvkeys/"
"$PY" "$B/gen_keys.py" --out-dir "$TMP/b4_rogue" >/dev/null
cp "$TMP/b4_rogue/sender_ed25519.pub" "$TMP/b4_recvkeys/"
"$PY" "$B/receiver.py" --out "$OUT" --broker-port "$PORT" --transfer-id "$TID" \
    --keys-dir "$TMP/b4_recvkeys" --state-dir "$TMP/b4_recv" >"$TMP/b4.recv.log" 2>&1
RC=$?
stop_broker
if [ "$RC" -ne 0 ] && [ ! -f "$OUT" ] && grep -q "signature INVALID" "$TMP/b4.recv.log"; then
    ok "B4 authenticity: manifest from an untrusted signer is rejected"
else
    no "B4 authenticity"; cat "$TMP/b4.broker.log" "$TMP/b4.recv.log"
fi

# --- B5: availability -- receiver resumes after a missing chunk -----------
OUT="$TMP/b5.bin"; PORT=8705
start_broker "$PORT" "$TMP/b5_store" "$TMP/b5.broker.log"
TID="$(upload "$PORT" "$TMP/b5_send" "$TMP/b5.send.log")"
mv "$TMP/b5_store/$TID/chunk_00000003" "$TMP/b5_chunk3.bak"   # chunk unavailable
"$PY" "$B/receiver.py" --out "$OUT" --broker-port "$PORT" --transfer-id "$TID" \
    --state-dir "$TMP/b5_recv" >"$TMP/b5.recv1.log" 2>&1
RC1=$?
RESUMABLE=0
[ "$RC1" -ne 0 ] && [ ! -f "$OUT" ] && [ -f "$OUT.part" ] \
    && [ -f "$OUT.part.progress" ] && RESUMABLE=1
mv "$TMP/b5_chunk3.bak" "$TMP/b5_store/$TID/chunk_00000003"   # chunk reappears
"$PY" "$B/receiver.py" --out "$OUT" --broker-port "$PORT" --transfer-id "$TID" \
    --state-dir "$TMP/b5_recv" >"$TMP/b5.recv2.log" 2>&1
RC2=$?
stop_broker
if [ "$RESUMABLE" -eq 1 ] && [ "$RC2" -eq 0 ] && [ -f "$OUT" ] \
   && [ "$(sha "$OUT")" = "$SRC_HASH" ] && grep -q resuming "$TMP/b5.recv2.log"; then
    ok "B5 availability: missing chunk left a resumable .part, re-run finished it"
else
    no "B5 availability (resumable=$RESUMABLE rc1=$RC1 rc2=$RC2)"
    cat "$TMP/b5.broker.log" "$TMP/b5.recv1.log" "$TMP/b5.recv2.log"
fi

# --- B6: availability -- sender resumes after the broker drops it ---------
OUT="$TMP/b6.bin"; PORT1=8706; PORT2=8716
# Broker is rigged to drop the connection + exit after 3 PUTs (hostile broker).
start_broker "$PORT1" "$TMP/b6_store" "$TMP/b6.broker1.log" --fail-after-puts 3
"$PY" "$B/sender.py" --file "$SRC" --broker-port "$PORT1" \
    --state-dir "$TMP/b6_send" >"$TMP/b6.send1.log" 2>&1
SC1=$?
SENDER_RESUMABLE=0
[ "$SC1" -ne 0 ] && [ -n "$(ls -A "$TMP/b6_send" 2>/dev/null)" ] && SENDER_RESUMABLE=1
start_broker "$PORT2" "$TMP/b6_store" "$TMP/b6.broker2.log"   # fresh, healthy broker
TID="$(upload "$PORT2" "$TMP/b6_send" "$TMP/b6.send2.log")"
"$PY" "$B/receiver.py" --out "$OUT" --broker-port "$PORT2" --transfer-id "$TID" \
    --state-dir "$TMP/b6_recv" >"$TMP/b6.recv.log" 2>&1
RC=$?
stop_broker
if [ "$SENDER_RESUMABLE" -eq 1 ] && [ "$RC" -eq 0 ] && [ -f "$OUT" ] \
   && [ "$(sha "$OUT")" = "$SRC_HASH" ] && grep -q "already present" "$TMP/b6.send2.log"; then
    ok "B6 availability: broker cut the sender off, re-run resumed the upload"
else
    no "B6 availability (resumable=$SENDER_RESUMABLE rc=$RC)"
    cat "$TMP/b6.send1.log" "$TMP/b6.send2.log" "$TMP/b6.recv.log"
fi

# --- B7: replay -- re-delivering a completed transfer is rejected ---------
OUT="$TMP/b7.bin"; PORT=8707
start_broker "$PORT" "$TMP/b7_store" "$TMP/b7.broker.log"
TID="$(upload "$PORT" "$TMP/b7_send" "$TMP/b7.send.log")"
"$PY" "$B/receiver.py" --out "$OUT" --broker-port "$PORT" --transfer-id "$TID" \
    --state-dir "$TMP/b7_recv" >"$TMP/b7.recv1.log" 2>&1
RC1=$?
# attacker replays the exact same (still-valid, still-fresh) transfer
"$PY" "$B/receiver.py" --out "$TMP/b7_replay.bin" --broker-port "$PORT" \
    --transfer-id "$TID" --state-dir "$TMP/b7_recv" >"$TMP/b7.recv2.log" 2>&1
RC2=$?
stop_broker
if [ "$RC1" -eq 0 ] && [ "$RC2" -ne 0 ] && [ ! -f "$TMP/b7_replay.bin" ] \
   && grep -q "replay" "$TMP/b7.recv2.log"; then
    ok "B7 replay: re-delivered transfer rejected by the completed-transfer ledger"
else
    no "B7 replay (rc1=$RC1 rc2=$RC2)"; cat "$TMP/b7.recv1.log" "$TMP/b7.recv2.log"
fi

echo
echo "=============================================================="
echo " RESULTS:  $PASS passed, $FAIL failed"
echo "=============================================================="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
