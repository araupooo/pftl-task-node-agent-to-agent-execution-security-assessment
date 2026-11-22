#!/bin/bash
# clean_reproduce.sh — full reproduce pipeline from a fresh copy of the pack.
#
# Copies the pack (excluding fresh-clone logs, __pycache__, PACK-READY.md)
# to a temp dir, runs the whole pipeline there, compares the fresh outputs
# against the committed ones with scripts/compare_reproduce.py, and copies
# the fresh logs back into outputs/ as fresh-clone-* logs.
# Exits 0 only if all 15 comparison checks pass.
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
WORK="$(mktemp -d /tmp/pftl-a2a-repro.XXXXXX)"
echo "clean_reproduce.sh: workdir $WORK"

# copy the pack, excluding generated fresh-clone logs, bytecode, and the
# internal PACK-READY.md
rsync -a --exclude '__pycache__' --exclude 'outputs/fresh-clone-*' \
  --exclude 'PACK-READY.md' --exclude '.git' \
  "$PACK_ROOT/" "$WORK/" || { echo "copy failed"; exit 1; }

cd "$WORK" || exit 1
FAIL=0

echo "--- probe (read-only public fetches) ---"
bash scripts/probe_all.sh || FAIL=1

echo "--- pinned source excerpts ---"
if [ -d /tmp/pftl-a2a/postfiatd ]; then
  python3 -B scripts/extract_excerpts.py --repo /tmp/pftl-a2a/postfiatd || FAIL=1
else
  python3 -B scripts/extract_excerpts.py || FAIL=1
fi

echo "--- Ed25519 self-test (RFC 8032 TEST 1-3) ---"
python3 -B scripts/ed25519_selftest.py || FAIL=1

echo "--- lab drill (16 cases) ---"
python3 -B scripts/drill.py --out outputs/derived/drill-results.json --log outputs/drill-run.log || FAIL=1

echo "--- auth model ---"
python3 -B src/auth_model.py || FAIL=1

echo "--- analysis (findings, manifest, docs, fixtures) ---"
python3 -B scripts/analyze.py || FAIL=1

echo "--- compare fresh outputs vs committed pack ---"
python3 -B scripts/compare_reproduce.py "$WORK" "$PACK_ROOT" || FAIL=1

echo "--- copy fresh logs into the pack ---"
cp "$WORK/outputs/drill-run.log" \
   "$PACK_ROOT/outputs/fresh-clone-drill-run.log"
cp "$WORK/outputs/ed25519-test-vectors.log" \
   "$PACK_ROOT/outputs/fresh-clone-ed25519-test-vectors.log"
cp "$WORK/outputs/PROBE-MANIFEST.md" \
   "$PACK_ROOT/outputs/fresh-clone-probe-manifest.md"
cp "$WORK/outputs/derived/drill-results.json" \
   "$PACK_ROOT/outputs/fresh-clone-drill-results.json"

if [ "$FAIL" -ne 0 ]; then
  echo "clean_reproduce.sh: FAILED (see output above)"
  exit 1
fi
echo "clean_reproduce.sh: ALL CHECKS PASSED"
exit 0
