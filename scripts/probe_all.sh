#!/bin/bash
# probe_all.sh — read-only public-source probes for this pack.
#
# Fetches only public pages (no credentials, no sessions, no signing):
#   postfiat.org homepage, /task-node/ page, docs.postfiat.org,
#   postfiat.org/whitepaper/
# Writes the verbatim fetches to outputs/ and a manifest with HTTP
# status, byte size, SHA-256, and fetch time. Exits 0 only if every
# fetch returns HTTP 200.
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$PACK_ROOT/outputs"
mkdir -p "$OUT"
cd "$OUT" || exit 1

fetch() { # fetch <url> <outfile>
  local url="$1" out="$2"
  local code
  code=$(curl -s -o "$out" -w "%{http_code}" -L --max-time 90 "$url")
  local bytes sha
  bytes=$(stat -c%s "$out" 2>/dev/null || echo 0)
  sha=$(sha256sum "$out" 2>/dev/null | cut -d' ' -f1)
  echo "$url $code $bytes $sha" >> PROBE-MANIFEST.md.tmp
  echo "  $out: HTTP $code, $bytes bytes"
  [ "$code" = "200" ] || return 1
}

: > PROBE-MANIFEST.md.tmp
echo "probe manifest — read-only public fetches (UTC $(date -u +%Y-%m-%dT%H:%M:%SZ))" >> PROBE-MANIFEST.md.tmp
echo "url http_code bytes sha256" >> PROBE-MANIFEST.md.tmp

FAIL=0
fetch "https://postfiat.org/" "postfiat_org.html" || FAIL=1
fetch "https://postfiat.org/task-node/" "task_node_page.html" || FAIL=1
fetch "https://docs.postfiat.org/" "docs_postfiat_org.html" || FAIL=1
fetch "https://postfiat.org/whitepaper/" "postfiat_whitepaper.html" || FAIL=1
mv PROBE-MANIFEST.md.tmp PROBE-MANIFEST.md
if [ "$FAIL" -ne 0 ]; then
  echo "probe_all.sh: A FETCH FAILED (non-200)"
  exit 1
fi
echo "probe_all.sh: ALL FETCHES HTTP 200"
exit 0
