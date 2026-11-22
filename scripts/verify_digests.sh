#!/bin/bash
# verify_digests.sh — verify SHA256SUMS for the pack.
# Exits 0 only if every listed file matches its recorded hash.
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK_ROOT" || exit 1
sha256sum -c SHA256SUMS
