#!/usr/bin/env python3
"""auth_model.py — quantitative model of the reference design.

Computes, from the design parameters in configs/auth-parameters.json
and the reference implementation in src/a2a_auth.py:
  * wire sizes of a capability token and a signed task action
    (measured from real envelopes built with fresh LAB keys);
  * Ed25519 key/signature sizes and their fit against the pinned
    512-byte manifest cap (ManifestMessages.h:24, postfiatd 0085a1ff);
  * nonce-collision probability (birthday bound) for 128-bit nonces;
  * replay-window arithmetic (action TTL, clock-skew window, nonce
    cache retention);
  * post-quantum signature fit (FIPS 204/205 sizes vs the 512-byte cap).

Writes outputs/derived/auth-model.json. Deterministic except for the
measured envelope sizes, which vary by a few bytes with the hex
encoding of random keys — the reproduce comparison therefore checks
ranges, not exact bytes (see scripts/compare_reproduce.py).
"""
import json
import math
import os
import sys

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PACK, "src"))

from a2a_auth import (  # noqa: E402
    ACTION_TTL_SECONDS, CLOCK_SKEW_SECONDS, MAX_PAYLOAD_BYTES,
    TOKEN_TTL_SECONDS, issue_capability_token, new_agent_keypair,
    sign_task_action,
)


def _nonce_collision_probability(n_actions: int) -> float:
    """Birthday bound for 128-bit nonces: P ~= n^2 / 2^129."""
    return (n_actions ** 2) / (2 ** 129)


def main():
    now = 1_700_000_000  # fixed lab epoch for reproducibility
    issuer_sk, issuer_pk = new_agent_keypair()
    agent_sk, agent_pk = new_agent_keypair()

    token = issue_capability_token(
        issuer_sk, issuer_pk, agent_pk, "task-lab-001",
        ["accept", "submit_evidence", "respond_verification"], now)
    action = sign_task_action(
        agent_sk, agent_pk, "task-lab-001", "submit_evidence",
        b"evidence artifact", now)
    token_bytes = len(json.dumps(token, sort_keys=True).encode())
    action_bytes = len(json.dumps(action, sort_keys=True).encode())

    # FIPS sizes (NIST FIPS 204 Table 2, FIPS 205 Table 2).
    pq = {
        "ml_dsa_65_signature_bytes": 3309,
        "ml_dsa_65_public_key_bytes": 1952,
        "slh_dsa_128s_signature_bytes": 7856,
        "slh_dsa_128s_public_key_bytes": 32,
    }
    manifest_cap = 512
    model = {
        "design_parameters": {
            "clock_skew_seconds": CLOCK_SKEW_SECONDS,
            "action_ttl_seconds": ACTION_TTL_SECONDS,
            "token_ttl_seconds": TOKEN_TTL_SECONDS,
            "max_payload_bytes": MAX_PAYLOAD_BYTES,
            "nonce_bits": 128,
        },
        "measured_wire_sizes_bytes": {
            "capability_token_json": token_bytes,
            "signed_action_json": action_bytes,
            "ed25519_public_key": 32,
            "ed25519_secret_key": 32,
            "ed25519_signature": 64,
        },
        "replay_window": {
            "action_valid_seconds": ACTION_TTL_SECONDS,
            "nonce_cache_retention_seconds": ACTION_TTL_SECONDS,
            "clock_skew_seconds": CLOCK_SKEW_SECONDS,
            "max_acceptable_age_seconds":
                ACTION_TTL_SECONDS + CLOCK_SKEW_SECONDS,
        },
        "nonce_collision_probability": {
            "actions_per_day": {
                "1e3": _nonce_collision_probability(1_000),
                "1e6": _nonce_collision_probability(1_000_000),
                "1e9": _nonce_collision_probability(1_000_000_000),
            },
            "note": "birthday bound n^2 / 2^129 for 128-bit nonces",
        },
        "signature_fit_vs_manifest_cap_bytes": {
            "manifest_cap_bytes": manifest_cap,
            "ed25519_signature_bytes": 64,
            "ed25519_fits_cap": 64 <= manifest_cap,
            "ed25519_cap_ratio": round(64 / manifest_cap, 3),
            "ml_dsa_65_signature_bytes": pq["ml_dsa_65_signature_bytes"],
            "ml_dsa_65_fits_cap":
                pq["ml_dsa_65_signature_bytes"] <= manifest_cap,
            "ml_dsa_65_cap_ratio":
                round(pq["ml_dsa_65_signature_bytes"] / manifest_cap, 2),
            "slh_dsa_128s_signature_bytes":
                pq["slh_dsa_128s_signature_bytes"],
            "slh_dsa_128s_fits_cap":
                pq["slh_dsa_128s_signature_bytes"] <= manifest_cap,
            "slh_dsa_128s_cap_ratio":
                round(pq["slh_dsa_128s_signature_bytes"] / manifest_cap, 2),
        },
        "pq_sizes": pq,
    }
    out = os.path.join(PACK, "outputs", "derived", "auth-model.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(model, f, indent=1)
    print(f"auth-model.json written: token {token_bytes} B, "
          f"action {action_bytes} B")
    print(f"  Ed25519 sig 64 B vs 512 B cap: fits "
          f"({64 / manifest_cap:.1%} of cap)")
    print(f"  ML-DSA-65 sig 3309 B vs 512 B cap: does not fit "
          f"({3309 / manifest_cap:.1f}x cap)")
    print(f"  nonce collision P at 1e6 actions/day: "
          f"{_nonce_collision_probability(1_000_000):.3e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
