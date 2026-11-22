#!/bin/bash
# make_sha256sums.sh — regenerate SHA256SUMS for the pack.
# Excludes: SHA256SUMS itself, PACK-READY.md (internal-only),
# __pycache__ bytecode, and outputs/fresh-clone-* logs (regenerated
# by clean_reproduce.sh after SHA256SUMS is made).
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK_ROOT" || exit 1
find . -type f \
  ! -name SHA256SUMS \
  ! -name PACK-READY.md \
  ! -path '*/__pycache__/*' \
  ! -path './outputs/fresh-clone-*' \
  ! -path './.git/*' \
  | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
wc -l SHA256SUMS
