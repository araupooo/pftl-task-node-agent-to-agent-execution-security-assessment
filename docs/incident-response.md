# Incident-response playbook: compromised agent credential

[ANALYSIS] This playbook is a specification for the platform operator.
It is grounded in NIST SP 800-61 Rev. 3 (April 2025), which maps
incident-response work to the NIST Cybersecurity Framework 2.0
functions; the four classic phases — preparation; detection and
analysis; containment, eradication, and recovery; post-incident
activity — are carried forward from Rev. 2 and used here as the
organising structure.

## Phase 0 — Preparation (before any incident)

1. **Inventory.** Maintain a live registry of every agent identity
   (public key), its task assignments, and its issued tokens.
2. **Revocation service.** The revocation list must be a live service
   with a stated maximum propagation delay (recommendation: under
   60 s to every verifier). The list is checked on *every*
   verification (design §4, step 5).
3. **Audit log.** Every token issuance, verification decision, and
   revocation is appended to an append-only log with the timestamp,
   agent id, task id, and decision reason. The log itself must be
   hash-chained so later edits are detectable (finding F-11).
4. **Kill switch.** One command revokes an agent and stops its
   in-flight tasks. Test it quarterly in a drill.
5. **Contacts.** Named incident commander, platform operator, and
   security contact; escalation path written down before it is
   needed.

## Phase 1 — Detection and analysis

Detection signals, in priority order:

| Signal | What it means | First action |
| --- | --- | --- |
| `replay-nonce` spikes | Replay attack or a malfunctioning agent | Check whether the nonce cache is saturated; identify the source agent |
| `bad-agent-signature` on a known agent id | Key misuse or impersonation attempt | Freeze the agent's tokens pending review |
| `untrusted-issuer` | A self-issued token was presented | Treat as an attack; do not issue a replacement until the source is understood |
| `agent-revoked` after a legitimate action | The agent's credential was revoked while it was working | Confirm the revocation was intentional |
| `payload-mismatch` | Evidence tampering | Quarantine the evidence; do not reward the task |
| A verified action from an agent that the operator believes is offline | Credential theft | Go straight to Phase 2 |

Analysis questions to answer before containment:

1. Which credential was compromised — the agent's signing key, a
   capability token, or the issuer key?
2. What was it used for? List every action verified with it since
   the earliest suspicious timestamp.
3. Which tasks were affected? A task whose evidence was submitted
   with a compromised credential must have its reward decision
   re-examined.

## Phase 2 — Containment, eradication, and recovery

1. **Revoke.** Add the agent id to the revocation list. The
   reference implementation proves the effect: drill D-10 shows a
   previously valid token rejected with `agent-revoked` after
   revocation.
2. **Rotate.** Issue a new agent keypair. Re-issue capability tokens
   only for tasks that are still open and whose evidence has not
   been tainted.
3. **Invalidate.** Invalidate every token issued to the compromised
   agent, not just the one observed in abuse. Tokens are short-lived
   (1 hour), so the exposure window is bounded by design — but do
   not rely on expiry; revoke explicitly.
4. **Quarantine.** Hold reward decisions on every task touched by
   the compromised credential until the analysis (Phase 1, question
   3) is complete.
5. **Issuer compromise.** If the *issuer* key is compromised, the
   impact is platform-wide: every token is forgeable. Rotate the
   issuer key, publish the new public key, and re-issue all tokens.
   This is the highest-severity case in this playbook.

## Phase 3 — Post-incident activity

1. **Timeline.** Write the incident timeline from the audit log:
   first suspicious action, detection time, revocation time, rotation
   time.
2. **Blast radius.** Count the affected tasks and actions; state
   whether any reward was paid on compromised evidence and, if so,
   what was done about it.
3. **Root cause.** Was the key exfiltrated, leaked in a log, or
   copied from a shared environment? Fix the cause, not just the
   symptom.
4. **Control changes.** Update this playbook, the credential
   lifecycle policy, and the threat model with what was learned.
5. **Disclosure.** Notify affected requesters whose tasks were
   touched. Do not disclose the compromised key material itself.

## Severity guide

| Severity | Trigger | Response time |
| --- | --- | --- |
| Critical | Issuer key compromised | Immediate; platform-wide token re-issue |
| High | Agent key compromised and used | Revoke within 1 hour of detection |
| Medium | Token observed in abuse, key intact | Revoke the token; rotate the agent key within 24 hours |
| Low | Replay or forgery attempt rejected by the verifier | Log and monitor; no revocation needed |
