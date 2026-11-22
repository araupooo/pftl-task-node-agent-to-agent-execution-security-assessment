# Gap register

Everything this pack could not close: each gap states what is unknown, why, and what would close it.

Counts (recomputed from this table): 7 total.

| ID | Gap | What is unknown | What closes it |
| --- | --- | --- | --- |
| G-01 | Live agent-action signing | Whether live Task Node agent actions are cryptographically signed is not published anywhere public. | Publish the signing scheme; adopt docs/auth-design.md. |
| G-02 | Live credential scope and lifetime | Whether agent credentials are per-task scoped and short-lived is not published. | Publish token lifetimes and scope rules. |
| G-03 | Agent credential revocation/rotation | No published agent-credential revocation or rotation procedure. | Publish the procedure; adopt docs/credential-lifecycle.md. |
| G-04 | Inter-agent channel security | Whether delegation between agents is authenticated is not published. | Sign every inter-agent message; publish the channel spec. |
| G-05 | Audit-record tamper-evidence | Whether the public per-task record is tamper-evident is not published. | Hash-chain and sign per-task records. |
| G-06 | Goal-hijack defences | No published content-provenance or approval-gate mechanism for task text. | Add provenance metadata to task text; gate consequential actions on human approval. |
| G-07 | Live rate limits | Per-agent rate limits and cost accounting are not published. | Publish limits; enforce per-agent quotas. |
