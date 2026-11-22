# Threat model

Twelve threats across the agent task-execution lifecycle (request, offer, acceptance, evidence submission, verification, reward payout). Each threat states attacker capability, preconditions, and mitigation; the full text of each is in docs/threat-model.md below the table and in docs/risk-register.md.

Counts (recomputed from this table): 12 total — 8 MEASURED, 4 SPECIFIED.

| ID | Stage | Threat | OWASP | Likelihood | Impact | Status | Drill |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T-01 | request / offer | Agent impersonation — attacker presents another agent's identity | ASI03, LLM02 | Medium | High | MEASURED | D-05 |
| T-02 | accept | Replay of a signed acceptance | ASI03 | High | Medium | MEASURED | D-04, D-15 |
| T-03 | evidence | Forged evidence submission | LLM05, ASI07 | High | High | MEASURED | D-05, D-06 |
| T-04 | evidence | Privilege escalation via an over-broad credential | ASI03, LLM06 | High | High | MEASURED | D-07 |
| T-05 | any | Cross-task credential reuse | ASI03 | Medium | High | MEASURED | D-08 |
| T-06 | any | Cross-agent data leakage via shared context | LLM02, ASI06 | Medium | High | SPECIFIED | none (needs multi-agent deployment) |
| T-07 | request | Goal hijack via a poisoned task description | ASI01, LLM01 | High | High | SPECIFIED | none (content attack, not crypto) |
| T-08 | any | Tool misuse — agent invokes out-of-scope actions | ASI02, LLM06 | High | Medium | MEASURED | D-07, D-16 |
| T-09 | any | Compromised agent credential / rogue agent | ASI10, ASI03 | Medium | High | MEASURED | D-10 |
| T-10 | any | Insecure inter-agent communication | ASI07 | Medium | High | SPECIFIED | none (needs a live deployment) |
| T-11 | any | Cascading failure from one compromised agent | ASI08 | Medium | High | SPECIFIED | none (needs a live deployment) |
| T-12 | request | Unbounded consumption / task spam | LLM10 | High | Medium | MEASURED | D-16 |

## T-01 — Agent impersonation — attacker presents another agent's identity

- **Stage:** request / offer
- **OWASP:** ASI03, LLM02
- **Likelihood / impact:** Medium / High
- **Status:** MEASURED (drill: D-05)
- **Attacker capability:** Attacker holds a keypair and a copy of the victim's public key; no access to the victim's secret key.
- **Preconditions:** Agent identity is a bare public key with no binding to an account, or the verifier does not check that the signing key matches the claimed id.
- **Mitigation:** Identity = SHA-256(public key); every action is signed and the signature is verified against the claimed key (docs/auth-design.md §2).

## T-02 — Replay of a signed acceptance

- **Stage:** accept
- **OWASP:** ASI03
- **Likelihood / impact:** High / Medium
- **Status:** MEASURED (drill: D-04, D-15)
- **Attacker capability:** Attacker observes a valid signed action (public record) and resubmits it verbatim or reuses its nonce.
- **Preconditions:** No single-use nonce, or no nonce cache, or an unbounded action validity window.
- **Mitigation:** 128-bit single-use nonce + nonce cache retained for the action TTL + 900 s action validity window.

## T-03 — Forged evidence submission

- **Stage:** evidence
- **OWASP:** LLM05, ASI07
- **Likelihood / impact:** High / High
- **Status:** MEASURED (drill: D-05, D-06)
- **Attacker capability:** Attacker can submit arbitrary bytes as evidence and can sign with any key they hold.
- **Preconditions:** Evidence accepted without a signature bound to the task owner, or payload hash not checked.
- **Mitigation:** Evidence action carries SHA-256(payload); the signature covers the hash; verification recomputes it before acceptance.

## T-04 — Privilege escalation via an over-broad credential

- **Stage:** evidence
- **OWASP:** ASI03, LLM06
- **Likelihood / impact:** High / High
- **Status:** MEASURED (drill: D-07)
- **Attacker capability:** Attacker holds a credential issued for one action and tries to use it for a more powerful one.
- **Preconditions:** Credentials are not scoped per action, or scope is not checked at verification time.
- **Mitigation:** Capability token binds an explicit capability list; the verifier checks containment per action.

## T-05 — Cross-task credential reuse

- **Stage:** any
- **OWASP:** ASI03
- **Likelihood / impact:** Medium / High
- **Status:** MEASURED (drill: D-08)
- **Attacker capability:** Attacker holds a valid token for task A and presents it for task B.
- **Preconditions:** Token does not bind task_id, or the verifier does not compare it with the action's task_id.
- **Mitigation:** Token binds task_id; the verifier rejects any task mismatch.

## T-06 — Cross-agent data leakage via shared context

- **Stage:** any
- **OWASP:** LLM02, ASI06
- **Likelihood / impact:** Medium / High
- **Status:** SPECIFIED (drill: none (needs multi-agent deployment))
- **Attacker capability:** Attacker agent shares a context store, memory, or retrieval index with a victim agent.
- **Preconditions:** Agents share memory/RAG without per-agent namespacing or provenance checks on stored content.
- **Mitigation:** Per-agent context isolation; stored content treated as untrusted input (ASI06); no secrets in shared memory.

## T-07 — Goal hijack via a poisoned task description

- **Stage:** request
- **OWASP:** ASI01, LLM01
- **Likelihood / impact:** High / High
- **Status:** SPECIFIED (drill: none (content attack, not crypto))
- **Attacker capability:** Attacker authors or edits a task description, or plants instructions in linked evidence, that redirects the agent's objective.
- **Preconditions:** Task text is trusted as instruction; the agent does not separate task objectives from untrusted content.
- **Mitigation:** Content provenance for task text; the agent treats linked documents as data, not instructions; consequential actions need human approval.

## T-08 — Tool misuse — agent invokes out-of-scope actions

- **Stage:** any
- **OWASP:** ASI02, LLM06
- **Likelihood / impact:** High / Medium
- **Status:** MEASURED (drill: D-07, D-16)
- **Attacker capability:** Agent (or its hijacked instruction stream) calls an action outside its assignment.
- **Preconditions:** Agent holds a credential that authorizes more actions than the task needs, or no per-action authorization check exists.
- **Mitigation:** Least-agency scoping: one capability per action; payload size cap (1 MiB) bounds abuse.

## T-09 — Compromised agent credential / rogue agent

- **Stage:** any
- **OWASP:** ASI10, ASI03
- **Likelihood / impact:** Medium / High
- **Status:** MEASURED (drill: D-10)
- **Attacker capability:** Attacker exfiltrates an agent's secret key or capability token.
- **Preconditions:** Long-lived credentials, no revocation list, or revocation not checked at verification time.
- **Mitigation:** Short-lived tokens (1 h), per-task scope, revocation list checked on every verification; rotation procedure in docs/credential-lifecycle.md.

## T-10 — Insecure inter-agent communication

- **Stage:** any
- **OWASP:** ASI07
- **Likelihood / impact:** Medium / High
- **Status:** SPECIFIED (drill: none (needs a live deployment))
- **Attacker capability:** Attacker sits between two agents and forges, replays, or alters delegated messages.
- **Preconditions:** Inter-agent messages are unsigned, or the channel provides no authenticity.
- **Mitigation:** Every inter-agent message is a signed task action under this design; the live platform's channel security is UNVERIFIED (C-31).

## T-11 — Cascading failure from one compromised agent

- **Stage:** any
- **OWASP:** ASI08
- **Likelihood / impact:** Medium / High
- **Status:** SPECIFIED (drill: none (needs a live deployment))
- **Attacker capability:** One compromised agent's output feeds other agents' inputs across many tasks.
- **Preconditions:** No blast-radius limits; downstream agents trust upstream output without verification.
- **Mitigation:** Per-task isolation, independent verification of each task's evidence, rate limits, and a kill switch per agent (docs/incident-response.md).

## T-12 — Unbounded consumption / task spam

- **Stage:** request
- **OWASP:** LLM10
- **Likelihood / impact:** High / Medium
- **Status:** MEASURED (drill: D-16)
- **Attacker capability:** Attacker floods the platform with task requests or oversized evidence.
- **Preconditions:** No per-agent rate limits, no payload size cap, no cost accounting per action.
- **Mitigation:** 1 MiB payload cap (measured, D-16); per-agent rate limits and token TTLs are specified but their live values are UNVERIFIED.
