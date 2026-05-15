#!/usr/bin/env bash
# Generate the local test file (spec section 5.2). NEVER commit it -- the repo
# .gitignore already excludes test_*.bin / test_4gb.bin.
#
# Usage:
#   scripts/gen_test_file.sh                  # -> ./test_4gb.bin  (4 GiB, random)
#   scripts/gen_test_file.sh out.bin 4        # -> ./out.bin       (4 GiB, random)
#   scripts/gen_test_file.sh small.bin 0.01   # -> tiny file for a quick check
#
# Random bytes are written 1 MiB at a time, so this never holds the whole file
# in memory -- mirroring how the transfer programs themselves stream.
set -euo pipefail

OUT="${1:-test_4gb.bin}"
SIZE_GIB="${2:-4}"

echo "Generating ${OUT} (${SIZE_GIB} GiB of random bytes) ..."
python3 - "$OUT" "$SIZE_GIB" <<'PY'
import os, sys
out_path, size_gib = sys.argv[1], float(sys.argv[2])
mib_total = int(size_gib * 1024)
with open(out_path, "wb") as f:
    for i in range(mib_total):
        f.write(os.urandom(1024 * 1024))
        if mib_total >= 64 and (i + 1) % 512 == 0:
            print(f"  {i + 1}/{mib_total} MiB", flush=True)
print(f"done: {out_path}")
PY

echo "SHA-256:"
if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$OUT"
else
    sha256sum "$OUT"
fi
