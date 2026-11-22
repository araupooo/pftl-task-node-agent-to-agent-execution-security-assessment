# Evidence index

Every evidence artifact in the pack, what it proves, and which claims/findings it supports.

| Artifact | Contents | Supports |
| --- | --- | --- |
| outputs/ed25519-test-vectors.log | RFC 8032 TEST 1–3 self-test, 3/3 PASS | C-01, F-12 |
| outputs/drill-run.log | Unedited drill log, 16 cases | C-02..C-15, F-02, F-04, F-05, F-07, F-09 |
| outputs/derived/drill-results.json | Machine-readable drill results | C-02..C-15 |
| outputs/derived/auth-model.json | Wire sizes, replay window, nonce probabilities, PQ fit | C-24, C-25, C-26, F-09, F-10 |
| outputs/PROBE-MANIFEST.md | Public fetch manifest (HTTP codes, sizes, SHA-256) | C-18 |
| outputs/postfiat_org.html | Verbatim postfiat.org homepage fetch | C-18 |
| outputs/task_node_page.html | Verbatim Task Node page fetch | C-18, F-01, F-08, F-11 |
| outputs/docs_postfiat_org.html | Verbatim docs.postfiat.org fetch (Notion shell, no readable content) | F-01, C-31 |
| outputs/postfiat_whitepaper.html | Verbatim whitepaper fetch | C-30 (context) |
| fixtures/source-excerpts/KeyType-enum.txt | KeyType.h:1–45, pinned 0085a1ff | C-16, F-10 |
| fixtures/source-excerpts/SecretKey-sign-dispatch.txt | SecretKey.h:130–182, pinned 0085a1ff | C-17 |
| fixtures/source-excerpts/PublicKey-verify.txt | PublicKey.h:230–262, pinned 0085a1ff | C-17 |
| fixtures/source-excerpts/Seed-random-generate.txt | Seed.h:90–120, pinned 0085a1ff | C-17 (context) |
| fixtures/source-excerpts/Manifest-verify-revoked.txt | Manifest.cpp:190–245, pinned 0085a1ff | F-10 (context) |
| fixtures/source-excerpts/TaskNode-identity-address.txt | Design_DistributedLocalHardware.md:45–60, pinned 0085a1ff | C-30 |
| fixtures/owasp-llm-top10-2025.csv | OWASP LLM Top 10 2025 list | C-19, C-22 |
| fixtures/owasp-agentic-top10-2026.csv | OWASP Agentic Top 10 2026 list | C-20, C-21 |
| fixtures/rfc8032-test-vectors.csv | RFC 8032 §7.1 TEST 1–3 vectors | C-01, C-23 |
| scripts/ed25519.py | Pure-Python Ed25519 (RFC 8032) | C-01, F-12 |
| src/a2a_auth.py | Reference protocol implementation | C-24..C-27, F-02..F-09 |
| scripts/drill.py | Lab drill, 16 cases | C-02..C-15 |
