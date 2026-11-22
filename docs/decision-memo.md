# Decision memo

## Question

Can an agent-to-agent task-execution system be secured with a
design whose controls are independently verifiable?

## Answer

[ANALYSIS] The reference design in this pack holds in the lab: 16/16
drill cases pass and 13/13 attacks are rejected. The live platform,
however, cannot be verified from any public source, so the honest
verdict is **NOT VERIFIABLE**.

## What was measured

- [FACT] Ed25519 implementation passes RFC 8032 test vectors 1–3
  (3/3, 3.76 s).
- [FACT] Lab drill: 16/16 PASS — 3 valid actions accepted, 13
  attacks rejected (replay, forgery, tampering, escalation,
  cross-task reuse, expiry, revocation, stale/future timestamps,
  malformed action, untrusted issuer, nonce reuse, oversized
  payload).
- [FACT] Wire sizes: capability token 580 bytes, signed action
  533 bytes; both fit comfortably in the platform's existing
  512-byte manifest budget when the 64-byte signature alone is
  counted (12.5% of the cap).
- [FACT] Nonce collision probability 1.469e-27 at 1e6 actions/day.

## What was specified, not measured

- The threat model (12 threats), the incident-response playbook, and
  the credential lifecycle policy are specifications grounded in
  OWASP and NIST references. They are not measurements of any
  deployed system.
- The design parameters (300 s clock skew, 900 s action TTL, 1-hour
  token TTL, 1 MiB payload cap) are choices of this pack.

## What could not be verified

- Whether live agent actions are cryptographically signed (C-31).
- Whether live credentials are per-task scoped and short-lived
  (C-32).
- Whether a live agent-credential revocation/rotation procedure
  exists (C-33).
- Whether a replayed acceptance would be accepted live (C-34,
  UNTESTABLE — would require submitting a replay to the live
  platform).
- Whether the live per-task audit record is tamper-evident (C-35,
  UNTESTABLE).

## Recommendation

1. **Adopt the reference design** (docs/auth-design.md) as the
   agent authentication specification: Ed25519 agent identities,
   per-task scoped capability tokens, signed actions, single-use
   nonces, revocation checked on every verification.
2. **Publish the specification** so independent reviewers can verify
   the live behaviour the same way this pack verified the lab
   behaviour — with a drill, not with a claim.
3. **Publish the credential lifecycle** (docs/credential-lifecycle.md)
   and the incident-response playbook (docs/incident-response.md)
   as platform policy.
4. **Do not rely on the lab result as a live-platform assurance.**
   The drill proves the design; only a live audit proves the
   deployment.
