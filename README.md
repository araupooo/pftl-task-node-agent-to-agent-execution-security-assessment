# Task Node Agent-to-Agent Execution Security Assessment

Standalone technical assessment of agent-to-agent task execution
security for the PostFiat Task Node lifecycle (request, offer,
acceptance, evidence submission, verification, reward payout).

## Verdict

**NOT VERIFIABLE** — the reference design holds in the lab (16/16
drill cases, 13/13 attacks rejected), but the live platform's
agent-authentication controls cannot be confirmed from any public
source.

## Contents

- **Threat model** (`docs/threat-model.md`): 12 threats — impersonation,
  replay, evidence forgery, privilege escalation, cross-agent data
  leakage, goal hijack, tool misuse, credential compromise, insecure
  inter-agent communication, cascading failure, unbounded consumption.
  Each threat states attacker capability, preconditions, impact, and
  likelihood, mapped to OWASP LLM Top 10 2025 and Agentic Top 10 2026.
- **Auth design** (`docs/auth-design.md`): agent identity bound to an
  Ed25519 public key, per-task scoped capability tokens, signed task
  actions, single-use 128-bit nonces, least-privilege capability model.
  Reference implementation in `src/a2a_auth.py` (Python, stdlib only).
- **Lab drill** (`docs/drill-report.md`, `outputs/drill-run.log`):
  16 cases — 3 valid actions accepted, 13 attacks rejected.
- **Incident-response playbook** (`docs/incident-response.md`) and
  **credential lifecycle policy** (`docs/credential-lifecycle.md`),
  grounded in NIST SP 800-61 Rev. 3.
- **Risk register** (`docs/risk-register.md`): 12 risks, one per threat.
- **Claim index** (`docs/claim-index.md`): 35 claims — 18 VERIFIED,
  12 SPECIFIED, 3 UNVERIFIED, 2 UNTESTABLE.
- **Findings** (`findings.json`): 12 — 3 HIGH, 5 MEDIUM, 3 LOW, 1 INFO;
  6 MEASURED, 6 SPECIFIED.
- **Gap register** (`docs/gap-register.md`): 7 gaps the pack could not close.

## Key measurements

| Measure | Value |
| --- | --- |
| RFC 8032 test vectors (TEST 1–3) | 3/3 PASS (3.76 s) |
| Lab drill | 16/16 PASS; 13/13 attacks rejected |
| Drill wall / mean sign / mean verify | 24.92 s / 850.6 ms / 596.3 ms |
| Capability token size | 580 bytes (measured) |
| Signed action size | 533 bytes (measured) |
| Ed25519 signature vs 512-byte manifest cap | 64 bytes = 12.5% (fits) |
| Nonce collision probability (1e6 actions/day) | 1.469e-27 |
| Design windows | clock skew 300 s, action TTL 900 s, token TTL 3600 s, payload cap 1 MiB |

## Reproduction

```bash
bash scripts/clean_reproduce.sh   # full pipeline from a fresh clone; exit 0, CHECKS PASSED
bash scripts/verify_digests.sh    # verifies SHA256SUMS; exit 0
```

## Pinned sources

- postfiatd `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10,
  PR #50 merge, v1.0.9). Excerpts in `fixtures/source-excerpts/`,
  verified with `grep -n` on a local checkout.
- Public pages fetched 2026-11-23 (all HTTP 200): postfiat.org,
  postfiat.org/task-node/, docs.postfiat.org, postfiat.org/whitepaper/.
  Verbatim copies in `outputs/`; manifest in `outputs/PROBE-MANIFEST.md`.
- OWASP LLM Top 10 2025; OWASP Top 10 for Agentic Applications 2026;
  OWASP ASVS 5.0; RFC 8032; NIST SP 800-61 Rev. 3 (April 2025).

## Boundaries

Lab-only: all keys are freshly generated LAB test material; no live
credentials, no real user data, no live platform access, no
transactions. Live-platform authentication claims are marked
UNVERIFIED or UNTESTABLE rather than invented.

Every substantive claim carries one label: [FACT] / [ESTIMATE] /
[ANALYSIS]. Counts are recomputed from the tables they summarize.
