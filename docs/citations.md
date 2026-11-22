# Citations

## PostFiat sources

- PostFiat homepage — https://postfiat.org/ (fetched 2026-11-23,
  HTTP 200, 34,713 bytes; verbatim copy `outputs/postfiat_org.html`)
- Task Node page — https://postfiat.org/task-node/ (fetched
  2026-11-23, HTTP 200, 10,623 bytes; verbatim copy
  `outputs/task_node_page.html`)
- PostFiat docs — https://docs.postfiat.org/ (fetched 2026-11-23,
  HTTP 200; renders as a Notion offline page via a plain fetch —
  no readable content; verbatim copy
  `outputs/docs_postfiat_org.html`)
- PostFiat whitepaper — https://postfiat.org/whitepaper/ (fetched
  2026-11-23, HTTP 200, 163,089 bytes; verbatim copy
  `outputs/postfiat_whitepaper.html`)
- postfiatd repository, pinned commit
  `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, PR #50
  merge, v1.0.9) — https://github.com/postfiatorg/postfiatd
  - `include/xrpl/protocol/KeyType.h:28–31` — KeyType enum
    (secp256k1, ed25519)
  - `src/xrpl/protocol/SecretKey.h:175–180` — sign dispatch by
    KeyType
  - `src/xrpl/protocol/PublicKey.h:241–252` — verifyDigest / verify
  - `include/xrpl/protocol/Seed.h:99,113` — randomSeed /
    generateSeed
  - `src/xrpld/overlay/Manifest.cpp:196–245` — Manifest verify /
    revoked
  - `src/xrpld/overlay/detail/ManifestMessages.h:24` — 512-byte
    manifest cap
  - `docs/dynamic-unl/archive/Design_DistributedLocalHardware.md:52`
    — Task Node address linked to operator identity

## OWASP sources

- OWASP Top 10 for LLM Applications 2025 —
  https://genai.owasp.org/llm-top-10/ (2025 edition v2.0, published
  2024-11-18; LLM06 Excessive Agency expanded; new LLM07 System
  Prompt Leakage, LLM08 Vector and Embedding Weaknesses)
- OWASP Top 10 for Agentic Applications 2026 — OWASP GenAI Security
  Project announcement, 2025-12-09 —
  https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
- OWASP Application Security Verification Standard 5.0 —
  https://github.com/OWASP/ASVS (chapters V2 authentication,
  V3 session/token management)

## Standards

- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA),
  January 2017 — https://www.rfc-editor.org/rfc/rfc8032.txt
  (§5.1.5–5.1.7 algorithm; §7.1 test vectors TEST 1–3)
- NIST SP 800-61 Rev. 3, Incident Response Recommendations and
  Considerations for Cybersecurity Risk Management, April 2025 —
  reorganized around NIST CSF 2.0 functions; the four classic
  phases (preparation; detection and analysis; containment,
  eradication, and recovery; post-incident activity) are carried
  forward from Rev. 2.
