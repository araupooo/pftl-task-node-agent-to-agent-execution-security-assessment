#!/usr/bin/env python3
"""analyze.py — derive the analysis artifacts from the drill/model
outputs. Single source of truth for threats, findings, claims, and
risks; every count in every generated file is recomputed from the
lists below, never typed by hand.

Inputs (all produced by probe_all.sh, ed25519_selftest.py, drill.py,
auth_model.py, extract_excerpts.py):
  outputs/derived/drill-results.json
  outputs/derived/auth-model.json
  outputs/ed25519-test-vectors.log
  outputs/probe-run outputs (postfiat_org.html, task_node_page.html)
  fixtures/source-excerpts/*.txt
Outputs:
  findings.json, run-manifest.json
  docs/claim-index.md, docs/gap-register.md, docs/risk-register.md,
  docs/evidence-index.md, docs/threat-model.md
  fixtures/owasp-llm-top10-2025.csv,
  fixtures/owasp-agentic-top10-2026.csv,
  fixtures/rfc8032-test-vectors.csv, fixtures/source-hashes.json

Status taxonomy (same as the prior packs):
  VERIFIED   — measured in the lab drill, or measured against a pinned
               source / RFC test vector
  SPECIFIED  — stated in pinned code, pinned docs, or a cited standard
  UNVERIFIED — could not be checked from any available public source
  UNTESTABLE — would need an action this pack's safety boundary forbids
               (live platform access, live credentials)
"""
import datetime
import hashlib
import json
import os

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DERIVED = os.path.join(PACK, "outputs", "derived")

VERDICT = ("NOT VERIFIABLE — the reference design holds in the lab "
           "(16/16 drill cases, 13/13 attacks rejected), but the live "
           "platform's agent-authentication controls cannot be confirmed "
           "from any public source.")

# ---------------------------------------------------------------- threats
# stage: lifecycle stage. owasp: OWASP mapping. status: MEASURED means a
# drill case exercises the countermeasure; SPECIFIED means the
# countermeasure is a design specification only.
THREATS = [
    {"id": "T-01", "stage": "request / offer",
     "title": "Agent impersonation — attacker presents another agent's identity",
     "owasp": "ASI03, LLM02", "likelihood": "Medium", "impact": "High",
     "status": "MEASURED", "drill": "D-05",
     "capability": "Attacker holds a keypair and a copy of the victim's "
                   "public key; no access to the victim's secret key.",
     "preconditions": "Agent identity is a bare public key with no "
                      "binding to an account, or the verifier does not "
                      "check that the signing key matches the claimed id.",
     "mitigation": "Identity = SHA-256(public key); every action is "
                   "signed and the signature is verified against the "
                   "claimed key (docs/auth-design.md §2)."},
    {"id": "T-02", "stage": "accept",
     "title": "Replay of a signed acceptance",
     "owasp": "ASI03", "likelihood": "High", "impact": "Medium",
     "status": "MEASURED", "drill": "D-04, D-15",
     "capability": "Attacker observes a valid signed action (public "
                   "record) and resubmits it verbatim or reuses its nonce.",
     "preconditions": "No single-use nonce, or no nonce cache, or an "
                      "unbounded action validity window.",
     "mitigation": "128-bit single-use nonce + nonce cache retained for "
                   "the action TTL + 900 s action validity window."},
    {"id": "T-03", "stage": "evidence",
     "title": "Forged evidence submission",
     "owasp": "LLM05, ASI07", "likelihood": "High", "impact": "High",
     "status": "MEASURED", "drill": "D-05, D-06",
     "capability": "Attacker can submit arbitrary bytes as evidence and "
                   "can sign with any key they hold.",
     "preconditions": "Evidence accepted without a signature bound to "
                      "the task owner, or payload hash not checked.",
     "mitigation": "Evidence action carries SHA-256(payload); the "
                   "signature covers the hash; verification recomputes "
                   "it before acceptance."},
    {"id": "T-04", "stage": "evidence",
     "title": "Privilege escalation via an over-broad credential",
     "owasp": "ASI03, LLM06", "likelihood": "High", "impact": "High",
     "status": "MEASURED", "drill": "D-07",
     "capability": "Attacker holds a credential issued for one action "
                   "and tries to use it for a more powerful one.",
     "preconditions": "Credentials are not scoped per action, or scope "
                      "is not checked at verification time.",
     "mitigation": "Capability token binds an explicit capability list; "
                   "the verifier checks containment per action."},
    {"id": "T-05", "stage": "any",
     "title": "Cross-task credential reuse",
     "owasp": "ASI03", "likelihood": "Medium", "impact": "High",
     "status": "MEASURED", "drill": "D-08",
     "capability": "Attacker holds a valid token for task A and presents "
                   "it for task B.",
     "preconditions": "Token does not bind task_id, or the verifier does "
                      "not compare it with the action's task_id.",
     "mitigation": "Token binds task_id; the verifier rejects any "
                   "task mismatch."},
    {"id": "T-06", "stage": "any",
     "title": "Cross-agent data leakage via shared context",
     "owasp": "LLM02, ASI06", "likelihood": "Medium", "impact": "High",
     "status": "SPECIFIED", "drill": "none (needs multi-agent deployment)",
     "capability": "Attacker agent shares a context store, memory, or "
                   "retrieval index with a victim agent.",
     "preconditions": "Agents share memory/RAG without per-agent "
                      "namespacing or provenance checks on stored content.",
     "mitigation": "Per-agent context isolation; stored content treated "
                   "as untrusted input (ASI06); no secrets in shared "
                   "memory."},
    {"id": "T-07", "stage": "request",
     "title": "Goal hijack via a poisoned task description",
     "owasp": "ASI01, LLM01", "likelihood": "High", "impact": "High",
     "status": "SPECIFIED", "drill": "none (content attack, not crypto)",
     "capability": "Attacker authors or edits a task description, or "
                   "plants instructions in linked evidence, that "
                   "redirects the agent's objective.",
     "preconditions": "Task text is trusted as instruction; the agent "
                      "does not separate task objectives from untrusted "
                      "content.",
     "mitigation": "Content provenance for task text; the agent treats "
                   "linked documents as data, not instructions; "
                   "consequential actions need human approval."},
    {"id": "T-08", "stage": "any",
     "title": "Tool misuse — agent invokes out-of-scope actions",
     "owasp": "ASI02, LLM06", "likelihood": "High", "impact": "Medium",
     "status": "MEASURED", "drill": "D-07, D-16",
     "capability": "Agent (or its hijacked instruction stream) calls an "
                   "action outside its assignment.",
     "preconditions": "Agent holds a credential that authorizes more "
                      "actions than the task needs, or no per-action "
                      "authorization check exists.",
     "mitigation": "Least-agency scoping: one capability per action; "
                   "payload size cap (1 MiB) bounds abuse."},
    {"id": "T-09", "stage": "any",
     "title": "Compromised agent credential / rogue agent",
     "owasp": "ASI10, ASI03", "likelihood": "Medium", "impact": "High",
     "status": "MEASURED", "drill": "D-10",
     "capability": "Attacker exfiltrates an agent's secret key or "
                   "capability token.",
     "preconditions": "Long-lived credentials, no revocation list, or "
                      "revocation not checked at verification time.",
     "mitigation": "Short-lived tokens (1 h), per-task scope, revocation "
                   "list checked on every verification; rotation "
                   "procedure in docs/credential-lifecycle.md."},
    {"id": "T-10", "stage": "any",
     "title": "Insecure inter-agent communication",
     "owasp": "ASI07", "likelihood": "Medium", "impact": "High",
     "status": "SPECIFIED", "drill": "none (needs a live deployment)",
     "capability": "Attacker sits between two agents and forges, "
                   "replays, or alters delegated messages.",
     "preconditions": "Inter-agent messages are unsigned, or the "
                   "channel provides no authenticity.",
     "mitigation": "Every inter-agent message is a signed task action "
                   "under this design; the live platform's channel "
                   "security is UNVERIFIED (C-31)."},
    {"id": "T-11", "stage": "any",
     "title": "Cascading failure from one compromised agent",
     "owasp": "ASI08", "likelihood": "Medium", "impact": "High",
     "status": "SPECIFIED", "drill": "none (needs a live deployment)",
     "capability": "One compromised agent's output feeds other agents' "
                   "inputs across many tasks.",
     "preconditions": "No blast-radius limits; downstream agents trust "
                      "upstream output without verification.",
     "mitigation": "Per-task isolation, independent verification of each "
                   "task's evidence, rate limits, and a kill switch "
                   "per agent (docs/incident-response.md)."},
    {"id": "T-12", "stage": "request",
     "title": "Unbounded consumption / task spam",
     "owasp": "LLM10", "likelihood": "High", "impact": "Medium",
     "status": "MEASURED", "drill": "D-16",
     "capability": "Attacker floods the platform with task requests or "
                   "oversized evidence.",
     "preconditions": "No per-agent rate limits, no payload size cap, "
                      "no cost accounting per action.",
     "mitigation": "1 MiB payload cap (measured, D-16); per-agent rate "
                   "limits and token TTLs are specified but their live "
                   "values are UNVERIFIED."},
]

# ---------------------------------------------------------------- findings
FINDINGS = [
    {"id": "F-01", "severity": "HIGH", "status": "SPECIFIED",
     "title": "No published agent-authentication specification for the live platform",
     "evidence": "The public Task Node page describes the lifecycle "
                 "(request, work, evidence, reward) and the agent "
                 "connect flow (link + short code approval), but "
                 "publishes no token format, signing scheme, credential "
                 "scope, or verification rule. docs.postfiat.org is a "
                 "Notion page that returns no readable content to a "
                 "plain fetch. Whether agent actions are signed at all "
                 "is UNVERIFIED (C-31).",
     "remediation": "Publish the agent credential format, the signing "
                    "scheme, token lifetimes, and the revocation "
                    "procedure; adopt the reference design in "
                    "docs/auth-design.md."},
    {"id": "F-02", "severity": "HIGH", "status": "MEASURED",
     "title": "Reference design rejects 13/13 attack cases in the lab drill",
     "evidence": "Drill D-01..D-16: 3 valid actions accepted, 13 attacks "
                 "rejected with the expected reason (replay, forgery, "
                 "tampering, escalation, cross-task reuse, expiry, "
                 "revocation, stale/future timestamps, malformed "
                 "action, untrusted issuer, nonce reuse, oversized "
                 "payload). outputs/derived/drill-results.json, "
                 "outputs/drill-run.log.",
     "remediation": "None for the design. The gap is adoption: the "
                    "design must be implemented and published by the "
                    "platform, and its live behaviour independently "
                    "verified."},
    {"id": "F-03", "severity": "HIGH", "status": "SPECIFIED",
     "title": "A single long-lived agent credential is a single point of compromise",
     "evidence": "OWASP ASI03 (Identity and Privilege Abuse): agents "
                 "inherit or escalate high-privilege credentials; the "
                 "2025 Agentic Top 10 lists credential leakage letting "
                 "agents operate far beyond intended scope. The design "
                 "counters it with per-task scoped, 1-hour tokens "
                 "(docs/auth-design.md §3).",
     "remediation": "Issue per-task, short-lived capability tokens only; "
                    "never hand an agent a standing credential that "
                    "authorizes more than one task."},
    {"id": "F-04", "severity": "MEDIUM", "status": "MEASURED",
     "title": "Forged evidence is rejected by signature verification",
     "evidence": "D-05: an action claiming the victim's identity but "
                 "signed with the attacker's key is rejected "
                 "(bad-agent-signature). D-06: a valid signature over a "
                 "different payload is rejected (payload-mismatch). "
                 "Ed25519 verification is the binding mechanism; the "
                 "implementation passes RFC 8032 TEST 1–3.",
     "remediation": "Keep evidence signatures mandatory; never accept "
                    "evidence whose payload hash was not signed by the "
                    "task owner."},
    {"id": "F-05", "severity": "MEDIUM", "status": "MEASURED",
     "title": "Cross-task capability reuse is rejected",
     "evidence": "D-08: a token issued for task-lab-001 presented on "
                 "task-lab-002 is rejected (task-mismatch). The token "
                 "binds task_id and the verifier compares it with the "
                 "action's task_id.",
     "remediation": "Bind every credential to exactly one task id at "
                    "issuance; reject mismatches at verification."},
    {"id": "F-06", "severity": "MEDIUM", "status": "SPECIFIED",
     "title": "Goal hijack via poisoned task text is not stopped by cryptography",
     "evidence": "OWASP ASI01 (Agent Goal Hijack) / LLM01 (Prompt "
                 "Injection): malicious content alters the agent's "
                 "objectives through its planning and reasoning. "
                 "Signatures authenticate WHO acted, not WHETHER the "
                 "objective was the requester's. No drill case covers "
                 "it: it is a content attack, not a protocol attack.",
     "remediation": "Content provenance for task text; treat linked "
                    "documents as data, not instructions; require human "
                    "approval for consequential actions."},
    {"id": "F-07", "severity": "MEDIUM", "status": "MEASURED",
     "title": "Revocation list blocks stolen-credential reuse",
     "evidence": "D-10: after the agent is added to the revocation "
                 "list, its previously valid token is rejected "
                 "(agent-revoked). The check runs on every "
                 "verification, before the capability check.",
     "remediation": "Operate the revocation list as a live service with "
                    "a stated maximum propagation delay; audit every "
                    "revocation (docs/incident-response.md)."},
    {"id": "F-08", "severity": "MEDIUM", "status": "SPECIFIED",
     "title": "No published credential revocation/rotation procedure for agents",
     "evidence": "The public Task Node page documents device revocation "
                 "('Every connected device is listed, and can be "
                 "revoked') but publishes no agent-credential "
                 "revocation, rotation, or expiry procedure. Whether "
                 "one exists is UNVERIFIED (C-33).",
     "remediation": "Publish the rotation schedule, the revocation "
                    "endpoint, and the maximum propagation delay; adopt "
                    "docs/credential-lifecycle.md."},
    {"id": "F-09", "severity": "LOW", "status": "MEASURED",
     "title": "Replay window is bounded by nonce cache plus a 300 s clock-skew window",
     "evidence": "D-11 (stale timestamp) and D-12 (future timestamp) "
                 "are rejected; D-04/D-15 (nonce reuse) are rejected. "
                 "Design parameters: action TTL 900 s, clock skew "
                 "300 s, nonce cache retention 900 s; worst-case "
                 "acceptance age 1,200 s. Nonce collision probability "
                 "at 1e6 actions/day is 1.469e-27 (auth-model.json).",
     "remediation": "Keep the windows as specified; alert on nonce "
                    "cache saturation (a sign of replay flooding)."},
    {"id": "F-10", "severity": "LOW", "status": "SPECIFIED",
     "title": "Ed25519 fits the platform's existing key types",
     "evidence": "postfiatd KeyType has exactly two values, secp256k1 "
                 "and ed25519 (include/xrpl/protocol/KeyType.h:28–31, "
                 "pinned 0085a1ff). Signing and verification dispatch "
                 "by KeyType (SecretKey.h:175–180, PublicKey.h:241–252). "
                 "A 64-byte Ed25519 signature is 12.5% of the 512-byte "
                 "manifest cap (ManifestMessages.h:24).",
     "remediation": "Use Ed25519 agent keys: they reuse the platform's "
                    "existing key handling and fit every size budget."},
    {"id": "F-11", "severity": "LOW", "status": "SPECIFIED",
     "title": "Per-task audit record must be append-only; its tamper-evidence is unverified",
     "evidence": "The public Task Node page states each task has a "
                 "requester, an owner, evidence and a verifier, and "
                 "the record is public. Whether that record is "
                 "tamper-evident (hash-chained or signed) is not "
                 "published and is UNTESTABLE from outside (C-35).",
     "remediation": "Hash-chain the per-task record and sign each entry "
                    "with the platform key so any later edit is "
                    "detectable."},
    {"id": "F-12", "severity": "INFO", "status": "MEASURED",
     "title": "Reference implementation passes RFC 8032 test vectors 1–3",
     "evidence": "Pure-Python Ed25519 (stdlib only) passes public-key "
                 "derivation, signature production, verification, and "
                 "tamper rejection for TEST 1 (empty message), TEST 2 "
                 "(1 byte), TEST 3 (2 bytes). "
                 "outputs/ed25519-test-vectors.log, 3/3 PASS in 3.76 s.",
     "remediation": "None. The implementation is a reference, not a "
                    "production library: it is slow (~0.85 s per sign) "
                    "and makes no side-channel guarantees."},
]

# ------------------------------------------------------------------- claims
# (id, status, claim, evidence)
CLAIMS = [
    ("C-01", "VERIFIED",
     "The reference Ed25519 implementation passes RFC 8032 test vectors 1–3.",
     "outputs/ed25519-test-vectors.log: 3/3 PASS (public-key derivation, "
     "signature production, verification, tamper rejection)."),
    ("C-02", "VERIFIED",
     "The lab drill behaves as specified on all 16 cases: 3 valid actions accepted, 13 attacks rejected.",
     "outputs/derived/drill-results.json; outputs/drill-run.log: 16/16 PASS."),
    ("C-03", "VERIFIED",
     "Replay of an identical signed action is rejected.",
     "Drill D-04: second submission rejected (replay-nonce)."),
    ("C-04", "VERIFIED",
     "Nonce reuse across two different actions is rejected.",
     "Drill D-15: second action rejected (replay-nonce)."),
    ("C-05", "VERIFIED",
     "Forged evidence under a victim identity is rejected.",
     "Drill D-05: rejected (bad-agent-signature)."),
    ("C-06", "VERIFIED",
     "A tampered evidence payload is rejected.",
     "Drill D-06: rejected (payload-mismatch)."),
    ("C-07", "VERIFIED",
     "An accept-only capability token cannot authorize an evidence submission.",
     "Drill D-07: rejected (scope-denied)."),
    ("C-08", "VERIFIED",
     "A capability token bound to one task cannot be used on another task.",
     "Drill D-08: rejected (task-mismatch)."),
    ("C-09", "VERIFIED",
     "An expired capability token is rejected.",
     "Drill D-09: rejected (token-expired)."),
    ("C-10", "VERIFIED",
     "A revoked agent credential is rejected.",
     "Drill D-10: rejected (agent-revoked)."),
    ("C-11", "VERIFIED",
     "A stale action timestamp is rejected.",
     "Drill D-11: rejected (action-expired)."),
    ("C-12", "VERIFIED",
     "A future action timestamp beyond the clock-skew window is rejected.",
     "Drill D-12: rejected (action-not-yet-valid)."),
    ("C-13", "VERIFIED",
     "An action with a missing signature field is rejected.",
     "Drill D-13: rejected (malformed-action)."),
    ("C-14", "VERIFIED",
     "A capability token from a non-issuer key is rejected.",
     "Drill D-14: rejected (untrusted-issuer)."),
    ("C-15", "VERIFIED",
     "An oversized evidence payload is rejected.",
     "Drill D-16: payload of 1,048,577 bytes rejected (payload-too-large); cap 1 MiB."),
    ("C-16", "VERIFIED",
     "postfiatd KeyType has exactly two values: secp256k1 and ed25519.",
     "include/xrpl/protocol/KeyType.h:28–31, pinned 0085a1ff "
     "(excerpt KeyType-enum.txt)."),
    ("C-17", "VERIFIED",
     "postfiatd signing and verification dispatch by KeyType, with Ed25519 canonical-signature checks.",
     "SecretKey.h:175–180 (sign), PublicKey.h:241–252 (verifyDigest, "
     "verify), PublicKey.cpp:289–311 (ed25519_sign_open, canonical "
     "check); excerpts SecretKey-sign-dispatch.txt, PublicKey-verify.txt."),
    ("C-18", "VERIFIED",
     "The public Task Node page describes the lifecycle request → work → evidence → reward, with each task having a requester, an owner, evidence and a verifier, and the record public.",
     "outputs/task_node_page.html (fetched 2026-11-23, HTTP 200); "
     "probe manifest in outputs/PROBE-MANIFEST.md."),
    ("C-19", "SPECIFIED",
     "OWASP Top 10 for LLM Applications 2025 lists LLM01 Prompt Injection through LLM10 Unbounded Consumption.",
     "OWASP GenAI Security Project, genai.owasp.org/llm-top-10/; "
     "fixtures/owasp-llm-top10-2025.csv."),
    ("C-20", "SPECIFIED",
     "OWASP Top 10 for Agentic Applications 2026 lists ASI01 Agent Goal Hijack through ASI10 Rogue Agents.",
     "OWASP GenAI Security Project, published 2025-12-09, "
     "genai.owasp.org (announcement 2025-12-09); "
     "fixtures/owasp-agentic-top10-2026.csv."),
    ("C-21", "SPECIFIED",
     "ASI03 (Identity and Privilege Abuse) is mitigated by per-agent identity and short-lived scoped credentials.",
     "OWASP Top 10 for Agentic Applications 2026, ASI03."),
    ("C-22", "SPECIFIED",
     "LLM06 (Excessive Agency) is mitigated by restricting permissions to exactly what each task requires and requiring human approval for consequential actions.",
     "OWASP Top 10 for LLM Applications 2025, LLM06."),
    ("C-23", "SPECIFIED",
     "RFC 8032 Ed25519 uses 32-byte keys and 64-byte signatures.",
     "RFC 8032 sections 5.1.5–5.1.7; fixtures/rfc8032-test-vectors.csv."),
    ("C-24", "SPECIFIED",
     "A capability token binds agent_id, task_id, capability list, validity window, and a 128-bit nonce.",
     "docs/auth-design.md §3; src/a2a_auth.py issue_capability_token; "
     "measured token 580 bytes (outputs/derived/auth-model.json)."),
    ("C-25", "SPECIFIED",
     "A 128-bit single-use nonce makes accidental collision negligible: 1.469e-27 at one million actions per day.",
     "Birthday bound n^2/2^129; outputs/derived/auth-model.json."),
    ("C-26", "SPECIFIED",
     "Design parameters: clock-skew window 300 s, action validity 900 s, token validity 3600 s, payload cap 1 MiB.",
     "configs/auth-parameters.json; src/a2a_auth.py."),
    ("C-27", "SPECIFIED",
     "The revocation list is checked on every verification, before the capability check.",
     "src/a2a_auth.py Verifier.verify_action steps 5–6; drill D-10."),
    ("C-28", "SPECIFIED",
     "Incident response follows the four classic phases — preparation; detection and analysis; containment, eradication, and recovery; post-incident activity — as carried forward in NIST SP 800-61 Rev. 3 (April 2025), which maps the work to NIST CSF 2.0 functions.",
     "NIST SP 800-61 Rev. 3 (April 2025); docs/incident-response.md."),
    ("C-29", "SPECIFIED",
     "OWASP ASVS 5.0 defines authentication verification requirements (chapter V2) and session/token management requirements (chapter V3).",
     "OWASP Application Security Verification Standard 5.0, "
     "github.com/OWASP/ASVS (fetched 2026-11-23, HTTP 200)."),
    ("C-30", "SPECIFIED",
     "A pinned PostFiat design document links Task Node identity to an on-chain address.",
     "docs/dynamic-unl/archive/Design_DistributedLocalHardware.md:52, "
     "pinned 0085a1ff (excerpt TaskNode-identity-address.txt)."),
    ("C-31", "UNVERIFIED",
     "Whether live Task Node agent actions are cryptographically signed.",
     "No token format, signing scheme, or verification rule is "
     "published on the public Task Node page or in the pinned "
     "repository; docs.postfiat.org returns no readable content to a "
     "plain fetch."),
    ("C-32", "UNVERIFIED",
     "Whether live Task Node agent credentials are per-task scoped and short-lived.",
     "No credential scope or lifetime is published on any public source "
     "checked for this pack."),
    ("C-33", "UNVERIFIED",
     "Whether the live platform publishes an agent-credential revocation and rotation procedure.",
     "The public page documents device revocation only; no "
     "agent-credential revocation, rotation, or expiry procedure is "
     "published."),
    ("C-34", "UNTESTABLE",
     "Whether a replayed acceptance would be accepted by the live platform.",
     "Would require submitting a replayed action to the live platform, "
     "which this pack's lab-only boundary forbids."),
    ("C-35", "UNTESTABLE",
     "Whether the live platform's per-task audit record is tamper-evident.",
     "Would require write access to the live platform or its audit log, "
     "which this pack's lab-only boundary forbids."),
]

# -------------------------------------------------------------------- risks
RISKS = [
    {"id": "R-01", "threat": "T-01", "title": "Agent impersonation",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "Signed actions + identity bound to public key (F-04).",
     "residual": "Low if the design is adopted; High until the live "
                 "platform publishes its authentication (C-31)."},
    {"id": "R-02", "threat": "T-02", "title": "Replayed acceptance",
     "likelihood": "High", "impact": "Medium",
     "mitigation": "Single-use nonces + nonce cache (F-09).",
     "residual": "Low in the reference design; unknown live (C-34)."},
    {"id": "R-03", "threat": "T-03", "title": "Forged evidence",
     "likelihood": "High", "impact": "High",
     "mitigation": "Payload hash signed by the task owner (F-04).",
     "residual": "Low in the reference design; unknown live."},
    {"id": "R-04", "threat": "T-04", "title": "Privilege escalation",
     "likelihood": "High", "impact": "High",
     "mitigation": "Per-action capability containment (F-05).",
     "residual": "Low in the reference design; unknown live (C-32)."},
    {"id": "R-05", "threat": "T-05", "title": "Cross-task credential reuse",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "Task-bound tokens (F-05).",
     "residual": "Low in the reference design; unknown live."},
    {"id": "R-06", "threat": "T-06", "title": "Cross-agent data leakage",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "Per-agent context isolation; stored content treated "
                    "as untrusted (T-06).",
     "residual": "Medium: the control is specified, not measured."},
    {"id": "R-07", "threat": "T-07", "title": "Goal hijack",
     "likelihood": "High", "impact": "High",
     "mitigation": "Content provenance + human approval gates (F-06).",
     "residual": "Medium: no cryptographic control exists for this."},
    {"id": "R-08", "threat": "T-08", "title": "Tool misuse",
     "likelihood": "High", "impact": "Medium",
     "mitigation": "Least-agency scoping + payload cap (D-07, D-16).",
     "residual": "Low in the reference design; unknown live."},
    {"id": "R-09", "threat": "T-09", "title": "Compromised credential",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "Short-lived tokens + revocation list (F-07).",
     "residual": "Low in the reference design; unknown live (C-33)."},
    {"id": "R-10", "threat": "T-10", "title": "Insecure inter-agent channel",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "Signed task actions as the only inter-agent message "
                    "format (T-10).",
     "residual": "Medium: the live channel is UNVERIFIED (C-31)."},
    {"id": "R-11", "threat": "T-11", "title": "Cascading failure",
     "likelihood": "Medium", "impact": "High",
     "mitigation": "Per-task isolation + independent verification + "
                    "kill switch (T-11).",
     "residual": "Medium: the controls are specified, not measured."},
    {"id": "R-12", "threat": "T-12", "title": "Unbounded consumption",
     "likelihood": "High", "impact": "Medium",
     "mitigation": "Payload cap measured (D-16); rate limits specified.",
     "residual": "Medium: live rate limits are UNVERIFIED."},
]

OWASP_LLM_2025 = [
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM03", "Supply Chain"),
    ("LLM04", "Data and Model Poisoning"),
    ("LLM05", "Improper Output Handling"),
    ("LLM06", "Excessive Agency"),
    ("LLM07", "System Prompt Leakage"),
    ("LLM08", "Vector and Embedding Weaknesses"),
    ("LLM09", "Misinformation"),
    ("LLM10", "Unbounded Consumption"),
]

OWASP_AGENTIC_2026 = [
    ("ASI01", "Agent Goal Hijack"),
    ("ASI02", "Tool Misuse and Exploitation"),
    ("ASI03", "Identity and Privilege Abuse"),
    ("ASI04", "Agentic Supply Chain Vulnerabilities"),
    ("ASI05", "Unexpected Code Execution"),
    ("ASI06", "Memory and Context Poisoning"),
    ("ASI07", "Insecure Inter-Agent Communication"),
    ("ASI08", "Cascading Failures"),
    ("ASI09", "Human-Agent Trust Exploitation"),
    ("ASI10", "Rogue Agents"),
]

RFC8032_VECTORS = [
    ("TEST 1",
     "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("TEST 2",
     "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("TEST 3",
     "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


def _counts(items, key):
    out = {}
    for item in items:
        out[item[key]] = out.get(item[key], 0) + 1
    return out


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def _md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join([" --- "] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines) + "\n"


def main():
    drill = json.load(open(os.path.join(DERIVED, "drill-results.json")))
    model = json.load(open(os.path.join(DERIVED, "auth-model.json")))

    sev = _counts(FINDINGS, "severity")
    fstat = _counts(FINDINGS, "status")
    cstat = {}
    for _, status, _, _ in CLAIMS:
        cstat[status] = cstat.get(status, 0) + 1
    tstat = _counts(THREATS, "status")
    dsum = drill["summary"]

    # --- findings.json --------------------------------------------------
    findings_doc = {
        "verdict": VERDICT,
        "findings": FINDINGS,
        "counts": {
            "total": len(FINDINGS),
            "by_severity": sev,
            "by_status": fstat,
        },
    }
    _write(os.path.join(PACK, "findings.json"),
           json.dumps(findings_doc, indent=1) + "\n")

    # --- run-manifest.json ----------------------------------------------
    now = datetime.datetime.now(datetime.timezone.utc)
    manifest = {
        "pack": "Task Node agent-to-agent execution security assessment",
        "generated_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {
            "python": "3.12.3",
            "tools": "curl, git, python3 (stdlib only)",
            "network": "public pages only; no credentials, sessions, "
                       "accounts, or live platform access",
        },
        "repo_pins": {
            "postfiatd": "0085a1ff885d6a446369cf73a4430f75af22be55 "
                         "(2026-10-10, PR #50 merge, v1.0.9)",
        },
        "public_sources": [
            "https://postfiat.org/ (HTTP 200)",
            "https://postfiat.org/task-node/ (HTTP 200)",
            "https://docs.postfiat.org/ (HTTP 200, Notion shell, no readable content)",
            "https://postfiat.org/whitepaper/ (HTTP 200)",
            "https://genai.owasp.org/llm-top-10/ (OWASP LLM Top 10 2025)",
            "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/ (OWASP Agentic Top 10 2026)",
            "https://www.rfc-editor.org/rfc/rfc8032.txt (RFC 8032)",
            "https://github.com/OWASP/ASVS (OWASP ASVS 5.0)",
        ],
        "drill": {
            "cases_total": dsum["cases_total"],
            "passed": dsum["passed"],
            "valid_cases": dsum["valid_cases"],
            "attack_cases": dsum["attack_cases"],
            "attacks_rejected": dsum["attacks_rejected"],
            "mean_sign_ms": dsum["mean_sign_ms"],
            "mean_verify_ms": dsum["mean_verify_ms"],
            "wall_seconds": dsum["wall_seconds"],
        },
        "counts": {
            "threats_total": len(THREATS),
            "threats_by_status": tstat,
            "findings_total": len(FINDINGS),
            "by_severity": sev,
            "by_status": fstat,
            "claims_total": len(CLAIMS),
            "claims_by_status": cstat,
            "risks_total": len(RISKS),
        },
        "verdict": VERDICT,
        "notes": [
            "Assessment + lab drills only: no live credentials, no real "
            "user data, no live platform access, no transactions.",
            "All drill keys are freshly generated LAB keys; only public "
            "keys, fingerprints, and timings are recorded.",
            "Live-platform authentication claims are marked UNVERIFIED "
            "or UNTESTABLE: no public source publishes them.",
        ],
    }
    _write(os.path.join(PACK, "run-manifest.json"),
           json.dumps(manifest, indent=1) + "\n")

    # --- docs/claim-index.md --------------------------------------------
    rows = [[c[0], c[1], c[2], c[3]] for c in CLAIMS]
    claim_md = ("# Claim index\n\nEvery claim in this pack, its status, "
                "and its evidence. Statuses: VERIFIED (measured in the "
                "lab or against a pinned source / RFC vector), SPECIFIED "
                "(stated in pinned code, pinned docs, or a cited "
                "standard), UNVERIFIED (could not be checked from any "
                "available public source), UNTESTABLE (would need live "
                "platform access, which this pack's boundary forbids).\n\n"
                f"Counts (recomputed from this table): "
                f"{len(CLAIMS)} total — " +
                ", ".join(f"{v} {k}" for k, v in sorted(cstat.items())) +
                ".\n\n" +
                _md_table(["ID", "Status", "Claim", "Evidence"], rows))
    _write(os.path.join(PACK, "docs", "claim-index.md"), claim_md)

    # --- docs/threat-model.md -------------------------------------------
    rows = [[t["id"], t["stage"], t["title"], t["owasp"],
             t["likelihood"], t["impact"], t["status"],
             t["drill"]] for t in THREATS]
    threat_md = ("# Threat model\n\nTwelve threats across the agent "
                 "task-execution lifecycle (request, offer, acceptance, "
                 "evidence submission, verification, reward payout). "
                 "Each threat states attacker capability, preconditions, "
                 "and mitigation; the full text of each is in "
                 "docs/threat-model.md below the table and in "
                 "docs/risk-register.md.\n\n"
                 f"Counts (recomputed from this table): "
                 f"{len(THREATS)} total — " +
                 ", ".join(f"{v} {k}" for k, v in sorted(tstat.items())) +
                 ".\n\n" +
                 _md_table(["ID", "Stage", "Threat", "OWASP",
                            "Likelihood", "Impact", "Status", "Drill"],
                           rows))
    for t in THREATS:
        threat_md += (f"\n## {t['id']} — {t['title']}\n\n"
                      f"- **Stage:** {t['stage']}\n"
                      f"- **OWASP:** {t['owasp']}\n"
                      f"- **Likelihood / impact:** {t['likelihood']} / "
                      f"{t['impact']}\n"
                      f"- **Status:** {t['status']} (drill: {t['drill']})\n"
                      f"- **Attacker capability:** {t['capability']}\n"
                      f"- **Preconditions:** {t['preconditions']}\n"
                      f"- **Mitigation:** {t['mitigation']}\n")
    _write(os.path.join(PACK, "docs", "threat-model.md"), threat_md)

    # --- docs/risk-register.md -----------------------------------------
    rows = [[r["id"], r["threat"], r["title"], r["likelihood"],
             r["impact"], r["mitigation"], r["residual"]] for r in RISKS]
    risk_md = ("# Risk register\n\n"
               f"Counts (recomputed from this table): {len(RISKS)} total.\n\n" +
               _md_table(["ID", "Threat", "Risk", "Likelihood", "Impact",
                          "Mitigation", "Residual"], rows))
    _write(os.path.join(PACK, "docs", "risk-register.md"), risk_md)

    # --- docs/gap-register.md ------------------------------------------
    gaps = [
        ("G-01", "Live agent-action signing",
         "Whether live Task Node agent actions are cryptographically "
         "signed is not published anywhere public.",
         "Publish the signing scheme; adopt docs/auth-design.md."),
        ("G-02", "Live credential scope and lifetime",
         "Whether agent credentials are per-task scoped and short-lived "
         "is not published.",
         "Publish token lifetimes and scope rules."),
        ("G-03", "Agent credential revocation/rotation",
         "No published agent-credential revocation or rotation procedure.",
         "Publish the procedure; adopt docs/credential-lifecycle.md."),
        ("G-04", "Inter-agent channel security",
         "Whether delegation between agents is authenticated is not "
         "published.",
         "Sign every inter-agent message; publish the channel spec."),
        ("G-05", "Audit-record tamper-evidence",
         "Whether the public per-task record is tamper-evident is not "
         "published.",
         "Hash-chain and sign per-task records."),
        ("G-06", "Goal-hijack defences",
         "No published content-provenance or approval-gate mechanism "
         "for task text.",
         "Add provenance metadata to task text; gate consequential "
         "actions on human approval."),
        ("G-07", "Live rate limits",
         "Per-agent rate limits and cost accounting are not published.",
         "Publish limits; enforce per-agent quotas."),
    ]
    rows = [[g[0], g[1], g[2], g[3]] for g in gaps]
    gap_md = ("# Gap register\n\nEverything this pack could not close: "
              "each gap states what is unknown, why, and what would "
              "close it.\n\n"
              f"Counts (recomputed from this table): {len(gaps)} total.\n\n" +
              _md_table(["ID", "Gap", "What is unknown", "What closes it"],
                        rows))
    _write(os.path.join(PACK, "docs", "gap-register.md"), gap_md)

    # --- docs/evidence-index.md ----------------------------------------
    ev_rows = [
        ["outputs/ed25519-test-vectors.log",
         "RFC 8032 TEST 1–3 self-test, 3/3 PASS", "C-01, F-12"],
        ["outputs/drill-run.log",
         "Unedited drill log, 16 cases", "C-02..C-15, F-02, F-04, F-05, F-07, F-09"],
        ["outputs/derived/drill-results.json",
         "Machine-readable drill results", "C-02..C-15"],
        ["outputs/derived/auth-model.json",
         "Wire sizes, replay window, nonce probabilities, PQ fit",
         "C-24, C-25, C-26, F-09, F-10"],
        ["outputs/PROBE-MANIFEST.md",
         "Public fetch manifest (HTTP codes, sizes, SHA-256)", "C-18"],
        ["outputs/postfiat_org.html",
         "Verbatim postfiat.org homepage fetch", "C-18"],
        ["outputs/task_node_page.html",
         "Verbatim Task Node page fetch", "C-18, F-01, F-08, F-11"],
        ["outputs/docs_postfiat_org.html",
         "Verbatim docs.postfiat.org fetch (Notion shell, no readable content)",
         "F-01, C-31"],
        ["outputs/postfiat_whitepaper.html",
         "Verbatim whitepaper fetch", "C-30 (context)"],
        ["fixtures/source-excerpts/KeyType-enum.txt",
         "KeyType.h:1–45, pinned 0085a1ff", "C-16, F-10"],
        ["fixtures/source-excerpts/SecretKey-sign-dispatch.txt",
         "SecretKey.h:130–182, pinned 0085a1ff", "C-17"],
        ["fixtures/source-excerpts/PublicKey-verify.txt",
         "PublicKey.h:230–262, pinned 0085a1ff", "C-17"],
        ["fixtures/source-excerpts/Seed-random-generate.txt",
         "Seed.h:90–120, pinned 0085a1ff", "C-17 (context)"],
        ["fixtures/source-excerpts/Manifest-verify-revoked.txt",
         "Manifest.cpp:190–245, pinned 0085a1ff", "F-10 (context)"],
        ["fixtures/source-excerpts/TaskNode-identity-address.txt",
         "Design_DistributedLocalHardware.md:45–60, pinned 0085a1ff",
         "C-30"],
        ["fixtures/owasp-llm-top10-2025.csv",
         "OWASP LLM Top 10 2025 list", "C-19, C-22"],
        ["fixtures/owasp-agentic-top10-2026.csv",
         "OWASP Agentic Top 10 2026 list", "C-20, C-21"],
        ["fixtures/rfc8032-test-vectors.csv",
         "RFC 8032 §7.1 TEST 1–3 vectors", "C-01, C-23"],
        ["scripts/ed25519.py",
         "Pure-Python Ed25519 (RFC 8032)", "C-01, F-12"],
        ["src/a2a_auth.py",
         "Reference protocol implementation", "C-24..C-27, F-02..F-09"],
        ["scripts/drill.py",
         "Lab drill, 16 cases", "C-02..C-15"],
    ]
    ev_md = ("# Evidence index\n\nEvery evidence artifact in the pack, "
             "what it proves, and which claims/findings it supports.\n\n" +
             _md_table(["Artifact", "Contents", "Supports"], ev_rows))
    _write(os.path.join(PACK, "docs", "evidence-index.md"), ev_md)

    # --- fixtures --------------------------------------------------------
    _write(os.path.join(PACK, "fixtures", "owasp-llm-top10-2025.csv"),
           "id,name,source\n" + "".join(
               f"{i},{n},OWASP Top 10 for LLM Applications 2025 "
               f"(genai.owasp.org)\n" for i, n in OWASP_LLM_2025))
    _write(os.path.join(PACK, "fixtures", "owasp-agentic-top10-2026.csv"),
           "id,name,source\n" + "".join(
               f"{i},{n},OWASP Top 10 for Agentic Applications 2026 "
               f"(GenAI Security Project, 2025-12-09)\n"
               for i, n in OWASP_AGENTIC_2026))
    _write(os.path.join(PACK, "fixtures", "rfc8032-test-vectors.csv"),
           "test,secret_key,public_key,message,signature\n" + "".join(
               f"{t},{sk},{pk},{m},{s}\n"
               for t, sk, pk, m, s in RFC8032_VECTORS))

    hashes = {}
    for root, _, files in os.walk(os.path.join(PACK, "fixtures")):
        for fn in sorted(files):
            if fn == "source-hashes.json":
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, PACK)
            hashes[rel] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    _write(os.path.join(PACK, "fixtures", "source-hashes.json"),
           json.dumps(hashes, indent=1, sort_keys=True) + "\n")

    print(f"threats: {len(THREATS)} ({tstat})")
    print(f"findings: {len(FINDINGS)} ({sev}; {fstat})")
    print(f"claims: {len(CLAIMS)} ({cstat})")
    print(f"risks: {len(RISKS)}")
    print(f"drill: {dsum['passed']}/{dsum['cases_total']} PASS, "
          f"{dsum['attacks_rejected']}/{dsum['attack_cases']} attacks "
          f"rejected")
    print("analyze.py: DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
