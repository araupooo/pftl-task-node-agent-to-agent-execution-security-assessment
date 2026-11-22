# Methodology

## Sources

[FACT] Every technical fact in this pack is verified against a
primary source before being written:

- **postfiatd pinned commit `0085a1ff885d6a446369cf73a4430f75af22be55`**
  (2026-10-10, PR #50 merge, v1.0.9), cloned locally; `git rev-parse
  HEAD` matches. Source excerpts in `fixtures/source-excerpts/` were
  verified with `grep -n` on that checkout and carry file path +
  line numbers.
- **Public PostFiat pages**, fetched read-only 2026-11-23 (all
  HTTP 200): postfiat.org, postfiat.org/task-node/,
  docs.postfiat.org (renders as a Notion offline page via a plain
  fetch — no readable content), postfiat.org/whitepaper/. Verbatim
  copies in `outputs/`; manifest in `outputs/PROBE-MANIFEST.md`.
- **OWASP Top 10 for LLM Applications 2025** (genai.owasp.org,
  2025 edition v2.0).
- **OWASP Top 10 for Agentic Applications 2026** (OWASP GenAI
  Security Project announcement, 2025-12-09).
- **OWASP ASVS 5.0** (github.com/OWASP/ASVS).
- **RFC 8032** (Ed25519, January 2017), fetched from rfc-editor.org;
  §7.1 test vectors reproduced in `fixtures/rfc8032-test-vectors.csv`.
- **NIST SP 800-61 Rev. 3** (April 2025) for the incident-response
  structure.

## Lab

- All drills run against a pure-Python reference implementation
  (stdlib only, `src/a2a_auth.py`, `scripts/ed25519.py`).
- All keys are freshly generated LAB test material. Only public
  keys, fingerprints, and timings are recorded.
- Lab clock: unix 1795382248 (= 2026-11-23).
- No live credentials, no real user data, no live platform access,
  no transactions.

## Reproduction

```bash
bash scripts/clean_reproduce.sh
```

Runs the full pipeline from a fresh clone: probe fetch, excerpt
extraction, Ed25519 self-test, drill, auth model, analysis, digest
verification. Exit 0 with a CHECKS PASSED summary.

```bash
bash scripts/verify_digests.sh
```

Verifies `SHA256SUMS`. Exit 0.

## Status taxonomy

- **VERIFIED** — measured in the lab drill, or measured against a
  pinned source / RFC test vector.
- **SPECIFIED** — stated in pinned code, pinned docs, or a cited
  standard.
- **UNVERIFIED** — could not be checked from any available public
  source.
- **UNTESTABLE** — would need an action this pack's safety boundary
  forbids (live platform access, live credentials).

## Claim labels

Every substantive claim carries one label: [FACT] (verified, with
source and date), [ESTIMATE] (a modelled or reported number), or
[ANALYSIS] (interpretation). They are never mixed.

## Limitations

- The drill proves the reference implementation, not any live
  platform.
- The reference Ed25519 implementation is slow (~0.85 s per sign)
  and makes no side-channel guarantees; it is a reference, not a
  production library.
- Content attacks (goal hijack, prompt injection, memory poisoning)
  are analysed but not drilled: they need a deployed multi-agent
  system.
- The live platform's internals are UNVERIFIED/UNTESTABLE by design
  of this pack's safety boundary.
