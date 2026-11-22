# Lab security drill report

[FACT] This drill ran against the reference implementation in
`src/a2a_auth.py` (stdlib only). All keys are freshly generated LAB
test material; no live credentials, no real user data, no live
platform access, no transactions.

## Method

```bash
python3 scripts/drill.py
```

Lab clock: unix 1795382248 (= 2026-11-23). Two agents (victim and
attacker), one issuer (LAB key), one verifier holding the issuer's
public key, the revocation list, and the nonce cache. Every case
builds a real signed action with the real Ed25519 implementation and
submits it to `Verifier.verify_action`.

## Results

[FACT] 16/16 cases PASS — 3 valid actions accepted, 13 attacks
rejected with the expected reason. Full unedited log:
`outputs/drill-run.log`; machine-readable results:
`outputs/derived/drill-results.json`.

| ID | Case | Expected | Actual | Result |
| --- | --- | --- | --- | --- |
| D-01 | Valid acceptance | accept | accept | PASS |
| D-02 | Valid evidence submission | accept | accept | PASS |
| D-03 | Valid verification response | accept | accept | PASS |
| D-04 | Replayed acceptance | reject (replay-nonce) | reject (replay-nonce) | PASS |
| D-05 | Forged evidence (victim identity, attacker key) | reject (bad-agent-signature) | reject (bad-agent-signature) | PASS |
| D-06 | Tampered payload (hash mismatch) | reject (payload-mismatch) | reject (payload-mismatch) | PASS |
| D-07 | Privilege escalation (accept token → evidence) | reject (scope-denied) | reject (scope-denied) | PASS |
| D-08 | Cross-task reuse | reject (task-mismatch) | reject (task-mismatch) | PASS |
| D-09 | Expired token | reject (token-expired) | reject (token-expired) | PASS |
| D-10 | Revoked credential | reject (agent-revoked) | reject (agent-revoked) | PASS |
| D-11 | Stale timestamp | reject (action-expired) | reject (action-expired) | PASS |
| D-12 | Future timestamp | reject (action-not-yet-valid) | reject (action-not-yet-valid) | PASS |
| D-13 | Missing signature | reject (malformed-action) | reject (malformed-action) | PASS |
| D-14 | Non-issuer token | reject (untrusted-issuer) | reject (untrusted-issuer) | PASS |
| D-15 | Nonce reuse across actions | reject (replay-nonce) | reject (replay-nonce) | PASS |
| D-16 | Oversized payload (1,048,577 bytes) | reject (payload-too-large) | reject (payload-too-large) | PASS |

## Timings (measured)

- Wall time: 24.92 s for 16 cases
- Mean sign time: 850.6 ms (pure-Python Ed25519; a production
  library would be orders of magnitude faster)
- Mean verify time: 596.3 ms
- Ed25519 self-test (RFC 8032 TEST 1–3): 3/3 PASS in 3.76 s
  (`outputs/ed25519-test-vectors.log`)

## Failure modes observed

None of the 13 attacks succeeded. Two design defects were found
*during drill design* and fixed before the drill ran:

1. **Ed25519 Edwards-addition sign error.** The y-coordinate of the
   point addition used a minus sign where the correct formula for
   the a=−1 twisted Edwards curve uses a plus sign. Small-value
   checks only proved internal consistency and did not catch it;
   the RFC 8032 §7.1 test vectors did. Fixed in `scripts/ed25519.py`
   before the self-test passed 3/3.
2. **Token issuer trust.** `verify_capability_token` originally
   verified the issuer signature against the issuer key named
   *inside the token* — any key could self-issue. Fixed to require
   the token's `issuer_pk` to equal the verifier's trusted issuer
   key; drill D-14 proves the fixed behaviour.

## What the drill does not prove

- It proves the *reference implementation* rejects these attacks. It
  does not prove anything about the live platform, whose controls
  are UNVERIFIED (C-31..C-35).
- It does not cover content attacks (goal hijack, prompt injection,
  memory poisoning) — those need a deployed multi-agent system, not
  a protocol drill.
- Timings are from a pure-Python reference on shared hardware; they
  are not performance claims about a production implementation.
