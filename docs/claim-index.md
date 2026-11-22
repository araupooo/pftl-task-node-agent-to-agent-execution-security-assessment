# Claim index

Every claim in this pack, its status, and its evidence. Statuses: VERIFIED (measured in the lab or against a pinned source / RFC vector), SPECIFIED (stated in pinned code, pinned docs, or a cited standard), UNVERIFIED (could not be checked from any available public source), UNTESTABLE (would need live platform access, which this pack's boundary forbids).

Counts (recomputed from this table): 35 total — 12 SPECIFIED, 2 UNTESTABLE, 3 UNVERIFIED, 18 VERIFIED.

| ID | Status | Claim | Evidence |
| --- | --- | --- | --- |
| C-01 | VERIFIED | The reference Ed25519 implementation passes RFC 8032 test vectors 1–3. | outputs/ed25519-test-vectors.log: 3/3 PASS (public-key derivation, signature production, verification, tamper rejection). |
| C-02 | VERIFIED | The lab drill behaves as specified on all 16 cases: 3 valid actions accepted, 13 attacks rejected. | outputs/derived/drill-results.json; outputs/drill-run.log: 16/16 PASS. |
| C-03 | VERIFIED | Replay of an identical signed action is rejected. | Drill D-04: second submission rejected (replay-nonce). |
| C-04 | VERIFIED | Nonce reuse across two different actions is rejected. | Drill D-15: second action rejected (replay-nonce). |
| C-05 | VERIFIED | Forged evidence under a victim identity is rejected. | Drill D-05: rejected (bad-agent-signature). |
| C-06 | VERIFIED | A tampered evidence payload is rejected. | Drill D-06: rejected (payload-mismatch). |
| C-07 | VERIFIED | An accept-only capability token cannot authorize an evidence submission. | Drill D-07: rejected (scope-denied). |
| C-08 | VERIFIED | A capability token bound to one task cannot be used on another task. | Drill D-08: rejected (task-mismatch). |
| C-09 | VERIFIED | An expired capability token is rejected. | Drill D-09: rejected (token-expired). |
| C-10 | VERIFIED | A revoked agent credential is rejected. | Drill D-10: rejected (agent-revoked). |
| C-11 | VERIFIED | A stale action timestamp is rejected. | Drill D-11: rejected (action-expired). |
| C-12 | VERIFIED | A future action timestamp beyond the clock-skew window is rejected. | Drill D-12: rejected (action-not-yet-valid). |
| C-13 | VERIFIED | An action with a missing signature field is rejected. | Drill D-13: rejected (malformed-action). |
| C-14 | VERIFIED | A capability token from a non-issuer key is rejected. | Drill D-14: rejected (untrusted-issuer). |
| C-15 | VERIFIED | An oversized evidence payload is rejected. | Drill D-16: payload of 1,048,577 bytes rejected (payload-too-large); cap 1 MiB. |
| C-16 | VERIFIED | postfiatd KeyType has exactly two values: secp256k1 and ed25519. | include/xrpl/protocol/KeyType.h:28–31, pinned 0085a1ff (excerpt KeyType-enum.txt). |
| C-17 | VERIFIED | postfiatd signing and verification dispatch by KeyType, with Ed25519 canonical-signature checks. | SecretKey.h:175–180 (sign), PublicKey.h:241–252 (verifyDigest, verify), PublicKey.cpp:289–311 (ed25519_sign_open, canonical check); excerpts SecretKey-sign-dispatch.txt, PublicKey-verify.txt. |
| C-18 | VERIFIED | The public Task Node page describes the lifecycle request → work → evidence → reward, with each task having a requester, an owner, evidence and a verifier, and the record public. | outputs/task_node_page.html (fetched 2026-11-23, HTTP 200); probe manifest in outputs/PROBE-MANIFEST.md. |
| C-19 | SPECIFIED | OWASP Top 10 for LLM Applications 2025 lists LLM01 Prompt Injection through LLM10 Unbounded Consumption. | OWASP GenAI Security Project, genai.owasp.org/llm-top-10/; fixtures/owasp-llm-top10-2025.csv. |
| C-20 | SPECIFIED | OWASP Top 10 for Agentic Applications 2026 lists ASI01 Agent Goal Hijack through ASI10 Rogue Agents. | OWASP GenAI Security Project, published 2025-12-09, genai.owasp.org (announcement 2025-12-09); fixtures/owasp-agentic-top10-2026.csv. |
| C-21 | SPECIFIED | ASI03 (Identity and Privilege Abuse) is mitigated by per-agent identity and short-lived scoped credentials. | OWASP Top 10 for Agentic Applications 2026, ASI03. |
| C-22 | SPECIFIED | LLM06 (Excessive Agency) is mitigated by restricting permissions to exactly what each task requires and requiring human approval for consequential actions. | OWASP Top 10 for LLM Applications 2025, LLM06. |
| C-23 | SPECIFIED | RFC 8032 Ed25519 uses 32-byte keys and 64-byte signatures. | RFC 8032 sections 5.1.5–5.1.7; fixtures/rfc8032-test-vectors.csv. |
| C-24 | SPECIFIED | A capability token binds agent_id, task_id, capability list, validity window, and a 128-bit nonce. | docs/auth-design.md §3; src/a2a_auth.py issue_capability_token; measured token 580 bytes (outputs/derived/auth-model.json). |
| C-25 | SPECIFIED | A 128-bit single-use nonce makes accidental collision negligible: 1.469e-27 at one million actions per day. | Birthday bound n^2/2^129; outputs/derived/auth-model.json. |
| C-26 | SPECIFIED | Design parameters: clock-skew window 300 s, action validity 900 s, token validity 3600 s, payload cap 1 MiB. | configs/auth-parameters.json; src/a2a_auth.py. |
| C-27 | SPECIFIED | The revocation list is checked on every verification, before the capability check. | src/a2a_auth.py Verifier.verify_action steps 5–6; drill D-10. |
| C-28 | SPECIFIED | Incident response follows the four classic phases — preparation; detection and analysis; containment, eradication, and recovery; post-incident activity — as carried forward in NIST SP 800-61 Rev. 3 (April 2025), which maps the work to NIST CSF 2.0 functions. | NIST SP 800-61 Rev. 3 (April 2025); docs/incident-response.md. |
| C-29 | SPECIFIED | OWASP ASVS 5.0 defines authentication verification requirements (chapter V2) and session/token management requirements (chapter V3). | OWASP Application Security Verification Standard 5.0, github.com/OWASP/ASVS (fetched 2026-11-23, HTTP 200). |
| C-30 | SPECIFIED | A pinned PostFiat design document links Task Node identity to an on-chain address. | docs/dynamic-unl/archive/Design_DistributedLocalHardware.md:52, pinned 0085a1ff (excerpt TaskNode-identity-address.txt). |
| C-31 | UNVERIFIED | Whether live Task Node agent actions are cryptographically signed. | No token format, signing scheme, or verification rule is published on the public Task Node page or in the pinned repository; docs.postfiat.org returns no readable content to a plain fetch. |
| C-32 | UNVERIFIED | Whether live Task Node agent credentials are per-task scoped and short-lived. | No credential scope or lifetime is published on any public source checked for this pack. |
| C-33 | UNVERIFIED | Whether the live platform publishes an agent-credential revocation and rotation procedure. | The public page documents device revocation only; no agent-credential revocation, rotation, or expiry procedure is published. |
| C-34 | UNTESTABLE | Whether a replayed acceptance would be accepted by the live platform. | Would require submitting a replayed action to the live platform, which this pack's lab-only boundary forbids. |
| C-35 | UNTESTABLE | Whether the live platform's per-task audit record is tamper-evident. | Would require write access to the live platform or its audit log, which this pack's lab-only boundary forbids. |
