# Risk register

Counts (recomputed from this table): 12 total.

| ID | Threat | Risk | Likelihood | Impact | Mitigation | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| R-01 | T-01 | Agent impersonation | Medium | High | Signed actions + identity bound to public key (F-04). | Low if the design is adopted; High until the live platform publishes its authentication (C-31). |
| R-02 | T-02 | Replayed acceptance | High | Medium | Single-use nonces + nonce cache (F-09). | Low in the reference design; unknown live (C-34). |
| R-03 | T-03 | Forged evidence | High | High | Payload hash signed by the task owner (F-04). | Low in the reference design; unknown live. |
| R-04 | T-04 | Privilege escalation | High | High | Per-action capability containment (F-05). | Low in the reference design; unknown live (C-32). |
| R-05 | T-05 | Cross-task credential reuse | Medium | High | Task-bound tokens (F-05). | Low in the reference design; unknown live. |
| R-06 | T-06 | Cross-agent data leakage | Medium | High | Per-agent context isolation; stored content treated as untrusted (T-06). | Medium: the control is specified, not measured. |
| R-07 | T-07 | Goal hijack | High | High | Content provenance + human approval gates (F-06). | Medium: no cryptographic control exists for this. |
| R-08 | T-08 | Tool misuse | High | Medium | Least-agency scoping + payload cap (D-07, D-16). | Low in the reference design; unknown live. |
| R-09 | T-09 | Compromised credential | Medium | High | Short-lived tokens + revocation list (F-07). | Low in the reference design; unknown live (C-33). |
| R-10 | T-10 | Insecure inter-agent channel | Medium | High | Signed task actions as the only inter-agent message format (T-10). | Medium: the live channel is UNVERIFIED (C-31). |
| R-11 | T-11 | Cascading failure | Medium | High | Per-task isolation + independent verification + kill switch (T-11). | Medium: the controls are specified, not measured. |
| R-12 | T-12 | Unbounded consumption | High | Medium | Payload cap measured (D-16); rate limits specified. | Medium: live rate limits are UNVERIFIED. |
