# Authentication and authorization design

A reference design for agent-to-agent task execution. [ANALYSIS] It is
a design, not a description of any live platform: every claim about the
live platform's controls is marked UNVERIFIED in docs/claim-index.md
(C-31, C-32, C-33) because no public source publishes them. The
reference implementation is `src/a2a_auth.py` (stdlib only, pure
Python); the lab results are in `outputs/drill-run.log`.

## 1. Principals

| Principal | What it is | Trust placed in it |
| --- | --- | --- |
| Agent | A software actor executing tasks | None beyond what its credentials prove |
| Issuer | The platform service that issues capability tokens | Holds the issuer key; its public key is the trust root |
| Verifier | The platform service that checks actions | Must be online at verification time; holds the revocation list and nonce cache |
| Requester | The party that created the task | None; its text is data, not instruction |

## 2. Agent identity

[FACT] Agent identity is `agent-` + the first 16 hex characters of
SHA-256(public key). The binding is cryptographic: an agent proves its
identity by signing, and the verifier checks the signature against the
public key named by the identity. [ANALYSIS] No registration database
is needed to verify identity — the key *is* the identity, and a
second, independent check (an account binding) can be layered on
without changing the format.

Key choice: Ed25519 (RFC 8032). [FACT] postfiatd's `KeyType` has
exactly two values, secp256k1 and ed25519
(`include/xrpl/protocol/KeyType.h:28–31`, pinned commit `0085a1ff`),
and signing/verification dispatch by key type
(`src/xrpl/protocol/SecretKey.h:175–180` for signing,
`src/xrpl/protocol/PublicKey.h:241–252` for verification). [ANALYSIS]
Ed25519 is the natural choice for agent keys: it reuses the platform's
existing key handling, and a 64-byte signature is 12.5% of the
512-byte manifest cap (`src/xrpld/overlay/detail/ManifestMessages.h:24`).

## 3. Per-task scoped credentials

A capability token is an Ed25519-signed JSON document issued by the
platform, binding:

- `agent_id` — the agent the token is for
- `task_id` — the single task the token is valid for
- `capabilities` — the exact actions allowed (one of `accept`,
  `submit-evidence`, `respond-verification`)
- `not_before`, `expires_at` — validity window (1 hour by default)
- `nonce` — a 128-bit random value, unique per token
- `issuer_pk` — the issuer's public key

[ANALYSIS] Scoping is the core of the design: a token that can accept
a task cannot submit evidence (drill D-07), and a token for task A
cannot be used on task B (drill D-08). The verifier checks the token's
issuer signature against the *trusted* issuer key it holds — never
against a key named inside the token. [FACT] The original design
sketched in this pack verified against the key inside the token; the
drill-design review caught that a self-issued token would then pass,
and the check was fixed before the drill ran (drill D-14 proves the
fixed behaviour).

Token size: 580 bytes (measured, `outputs/derived/auth-model.json`).

## 4. Signed task actions

Every task action is a canonical JSON document:

```json
{
  "action": "submit-evidence",
  "agent_id": "agent-…",
  "task_id": "task-lab-001",
  "capabilities": ["submit-evidence"],
  "payload_sha256": "…",
  "nonce": "…",
  "issued_at": 1795382248
}
```

The agent signs the canonical encoding (keys sorted, no whitespace)
with its Ed25519 key and sends `{action, signature}`. The verifier:

1. checks the action is well-formed and the payload is within the
   1 MiB cap;
2. checks the timestamp is within the clock-skew window (300 s) and
   the action TTL (900 s);
3. checks the nonce has not been seen (replay cache, retained for
   the action TTL);
4. checks the capability token: trusted issuer, task match, validity
   window;
5. checks the agent is not revoked;
6. checks the required capability is contained in the token;
7. verifies the signature against the claimed agent key;
8. recomputes the payload hash and compares it with the signed hash.

[ANALYSIS] The order matters: cheap checks (format, timestamp) run
first; the expensive cryptographic checks run last; revocation is
checked before capability so a revoked agent fails fast on every
action. [FACT] The lab drill exercises every step: D-04/D-15 (nonce),
D-09 (token expiry), D-10 (revocation), D-07 (capability), D-05
(signature), D-06 (payload hash), D-13 (malformed action),
D-14 (untrusted issuer), D-16 (payload cap).

Action size: 533 bytes (measured, varies a few bytes run to run with
the timestamp digit count).

## 5. Replay protection

Three mechanisms, in combination:

- **Single-use nonces.** Every action and token carries a 128-bit
  random nonce. The verifier keeps a nonce cache for the action TTL
  (900 s). [ESTIMATE] Collision probability (birthday bound
  n²/2¹²⁹): 1.469e-27 at 1e6 actions/day, 1.469e-21 at 1e9/day —
  negligible for any plausible deployment.
- **Timestamps.** Actions are valid for 900 s; timestamps more than
  300 s in the future are rejected (clock-skew window). Worst-case
  acceptance age is 1,200 s.
- **Bounded retention.** The nonce cache only needs to cover the
  action TTL; entries older than 900 s are irrelevant because the
  action itself has expired.

## 6. Least-privilege capability model

Capabilities are verbs, not roles. An agent receives exactly the
capabilities its current action needs, for exactly one task, for at
most one hour. [ANALYSIS] This is the direct countermeasure to OWASP
LLM06 (Excessive Agency) — "restrict permissions to exactly what the
task requires" — and to ASI03 (Identity and Privilege Abuse). The
capability list in a token is the complete authority the agent holds;
there is no ambient authority, no standing credential, and no way to
escalate by presenting the same token for a different action.

## 7. What the design does NOT cover

- **Goal hijack (ASI01 / LLM01).** Signatures authenticate *who*
  acted, not whether the objective was the requester's. A poisoned
  task description can still redirect an agent. Mitigation is
  content provenance and human approval gates (finding F-06).
- **Cross-agent data leakage (ASI06).** Shared memory and retrieval
  indexes need per-agent isolation; this design authenticates
  messages, it does not partition memory (threat T-06).
- **Channel security (ASI07).** The design assumes the transport
  delivers messages intact to the verifier. TLS or an equivalent
  authenticated channel is assumed, not specified.
- **Key compromise of the issuer.** If the issuer key is lost, every
  token is forgeable. Issuer-key protection (HSM, threshold signing)
  is out of scope for this pack; the incident-response playbook
  (docs/incident-response.md) covers the response if it happens.

## 8. Parameters

See `configs/auth-parameters.json`. Summary: clock skew 300 s,
action TTL 900 s, token TTL 3600 s, payload cap 1 MiB, 128-bit nonces,
Ed25519 signatures.
