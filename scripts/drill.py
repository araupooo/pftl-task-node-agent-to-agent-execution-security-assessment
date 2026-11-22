#!/usr/bin/env python3
"""drill.py — lab security drill against the reference implementation.

Runs 16 cases against src/a2a_auth.py: 3 valid actions (must verify)
and 13 attacks (must be rejected with the expected reason). Every key
is freshly generated LAB test material; nothing here touches a live
account, credential, or network.

Usage:
  python3 scripts/drill.py --out outputs/derived/drill-results.json \
      --log outputs/drill-run.log
Prints a per-case PASS/FAIL table and exits 0 only if every case
behaves as specified.
"""
import argparse
import json
import os
import sys
import time

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PACK, "src"))
sys.path.insert(0, os.path.join(PACK, "scripts"))

from a2a_auth import (  # noqa: E402
    ACTION_TTL_SECONDS, CLOCK_SKEW_SECONDS, MAX_PAYLOAD_BYTES,
    TOKEN_TTL_SECONDS, Verifier, agent_id_for, issue_capability_token,
    new_agent_keypair, sign_task_action,
)

TASK_A = "task-lab-001"
TASK_B = "task-lab-002"


def _ms(t0):
    return round((time.time() - t0) * 1000, 1)


def run_drill(now):
    """Execute all 16 drill cases. Returns (cases, summary)."""
    cases = []

    def record(case_id, name, category, expected_ok, expected_reason,
               outcome):
        ok, reason, sign_ms, verify_ms = outcome
        passed = (ok == expected_ok and reason == expected_reason)
        cases.append({
            "id": case_id, "name": name, "category": category,
            "expected": {"ok": expected_ok, "reason": expected_reason},
            "actual": {"ok": ok, "reason": reason},
            "pass": passed,
            "sign_ms": sign_ms, "verify_ms": verify_ms,
        })
        return passed

    def fresh_setup(capabilities, task_id=TASK_A, ttl=TOKEN_TTL_SECONDS,
                    issued_at=None):
        """Fresh issuer + agent + token + verifier for one case."""
        issued_at = now if issued_at is None else issued_at
        issuer_sk, issuer_pk = new_agent_keypair()
        agent_sk, agent_pk = new_agent_keypair()
        token = issue_capability_token(
            issuer_sk, issuer_pk, agent_pk, task_id, capabilities,
            issued_at, ttl_seconds=ttl)
        verifier = Verifier(issuer_pk)
        return issuer_sk, issuer_pk, agent_sk, agent_pk, token, verifier

    # ---- valid actions ------------------------------------------------
    t0 = time.time()
    _, _, ask, apk, tok, ver = fresh_setup(["accept"])
    act = sign_task_action(ask, apk, TASK_A, "accept", b"accepting", now)
    s_ms = _ms(t0)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"accepting", now)
    record("D-01", "valid accept action", "valid", True, "ok",
           (res[0], res[1], s_ms, _ms(t1)))

    t0 = time.time()
    _, _, ask, apk, tok, ver = fresh_setup(["submit_evidence"])
    payload = b"evidence artifact: sha256 of pack files"
    act = sign_task_action(ask, apk, TASK_A, "submit_evidence", payload,
                           now)
    s_ms = _ms(t0)
    t1 = time.time()
    res = ver.verify_action(act, tok, payload, now)
    record("D-02", "valid evidence submission", "valid", True, "ok",
           (res[0], res[1], s_ms, _ms(t1)))

    t0 = time.time()
    _, _, ask, apk, tok, ver = fresh_setup(["respond_verification"])
    act = sign_task_action(ask, apk, TASK_A, "respond_verification",
                           b"verification answer", now)
    s_ms = _ms(t0)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"verification answer", now)
    record("D-03", "valid verification response", "valid", True, "ok",
           (res[0], res[1], s_ms, _ms(t1)))

    # ---- attacks ------------------------------------------------------
    # D-04: exact replay of an accepted action.
    _, _, ask, apk, tok, ver = fresh_setup(["accept"])
    act = sign_task_action(ask, apk, TASK_A, "accept", b"accepting", now)
    first = ver.verify_action(act, tok, b"accepting", now)
    assert first == (True, "ok")
    t1 = time.time()
    res = ver.verify_action(act, tok, b"accepting", now)
    record("D-04", "replayed accept (identical bytes)", "attack",
           False, "replay-nonce", (res[0], res[1], 0.0, _ms(t1)))

    # D-05: forged evidence — victim's public key, attacker's signature.
    _, _, vsk, vpk, tok, ver = fresh_setup(["submit_evidence"])
    ask2, apk2 = new_agent_keypair()  # attacker keypair
    payload = b"forged evidence"
    # Attacker builds an envelope claiming the victim's identity, signed
    # with the attacker's own secret key.
    act = sign_task_action(ask2, apk2, TASK_A, "submit_evidence", payload,
                           now)
    act["agent_pk"] = vpk.hex()
    act["agent_id"] = agent_id_for(vpk)
    t1 = time.time()
    res = ver.verify_action(act, tok, payload, now)
    record("D-05", "forged evidence (victim identity, attacker key)",
           "attack", False, "bad-agent-signature",
           (res[0], res[1], 0.0, _ms(t1)))

    # D-06: tampered payload — signature covers a different payload.
    _, _, ask, apk, tok, ver = fresh_setup(["submit_evidence"])
    act = sign_task_action(ask, apk, TASK_A, "submit_evidence",
                           b"original evidence", now)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"tampered evidence", now)
    record("D-06", "tampered payload (hash mismatch)", "attack",
           False, "payload-mismatch", (res[0], res[1], 0.0, _ms(t1)))

    # D-07: privilege escalation — accept-only token used for evidence.
    _, _, ask, apk, tok, ver = fresh_setup(["accept"])
    act = sign_task_action(ask, apk, TASK_A, "submit_evidence",
                           b"evidence", now)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"evidence", now)
    record("D-07", "privilege escalation (accept token, evidence action)",
           "attack", False, "scope-denied", (res[0], res[1], 0.0, _ms(t1)))

    # D-08: cross-task reuse — token for task A used on task B.
    _, _, ask, apk, tok, ver = fresh_setup(["submit_evidence"],
                                           task_id=TASK_A)
    act = sign_task_action(ask, apk, TASK_B, "submit_evidence",
                           b"evidence", now)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"evidence", now)
    record("D-08", "cross-task capability reuse", "attack", False,
           "task-mismatch", (res[0], res[1], 0.0, _ms(t1)))

    # D-09: expired capability token.
    _, _, ask, apk, tok, ver = fresh_setup(
        ["submit_evidence"], issued_at=now - 2 * TOKEN_TTL_SECONDS)
    act = sign_task_action(ask, apk, TASK_A, "submit_evidence",
                           b"evidence", now)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"evidence", now)
    record("D-09", "expired capability token", "attack", False,
           "token-expired", (res[0], res[1], 0.0, _ms(t1)))

    # D-10: revoked credential — agent revoked after token issuance.
    _, _, ask, apk, tok, ver = fresh_setup(["submit_evidence"])
    ver.revoke_agent(agent_id_for(apk))
    act = sign_task_action(ask, apk, TASK_A, "submit_evidence",
                           b"evidence", now)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"evidence", now)
    record("D-10", "revoked agent credential reused", "attack", False,
           "agent-revoked", (res[0], res[1], 0.0, _ms(t1)))

    # D-11: stale action timestamp (outside the validity window).
    _, _, ask, apk, tok, ver = fresh_setup(["accept"])
    act = sign_task_action(ask, apk, TASK_A, "accept", b"accepting",
                           now - ACTION_TTL_SECONDS - 60)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"accepting", now)
    record("D-11", "stale action timestamp", "attack", False,
           "action-expired", (res[0], res[1], 0.0, _ms(t1)))

    # D-12: future action timestamp (beyond the clock-skew window).
    _, _, ask, apk, tok, ver = fresh_setup(["accept"])
    act = sign_task_action(ask, apk, TASK_A, "accept", b"accepting",
                           now + CLOCK_SKEW_SECONDS + 3600)
    t1 = time.time()
    res = ver.verify_action(act, tok, b"accepting", now)
    record("D-12", "future action timestamp", "attack", False,
           "action-not-yet-valid", (res[0], res[1], 0.0, _ms(t1)))

    # D-13: missing signature field.
    _, _, ask, apk, tok, ver = fresh_setup(["accept"])
    act = sign_task_action(ask, apk, TASK_A, "accept", b"accepting", now)
    del act["signature"]
    t1 = time.time()
    res = ver.verify_action(act, tok, b"accepting", now)
    record("D-13", "missing signature field", "attack", False,
           "malformed-action", (res[0], res[1], 0.0, _ms(t1)))

    # D-14: token signed by a non-issuer key.
    isk, ipk, ask, apk, _, ver = fresh_setup(["submit_evidence"])
    rogue_sk, rogue_pk = new_agent_keypair()  # not the issuer
    token = issue_capability_token(rogue_sk, rogue_pk, apk, TASK_A,
                                   ["submit_evidence"], now)
    act = sign_task_action(ask, apk, TASK_A, "submit_evidence",
                           b"evidence", now)
    t1 = time.time()
    res = ver.verify_action(act, token, b"evidence", now)
    record("D-14", "capability token from a non-issuer key", "attack",
           False, "untrusted-issuer", (res[0], res[1], 0.0, _ms(t1)))

    # D-15: nonce reuse across two different actions.
    _, _, ask, apk, tok, ver = fresh_setup(["accept", "submit_evidence"])
    shared_nonce = os.urandom(16)
    act1 = sign_task_action(ask, apk, TASK_A, "accept", b"accepting",
                            now, nonce=shared_nonce)
    first = ver.verify_action(act1, tok, b"accepting", now)
    assert first == (True, "ok")
    act2 = sign_task_action(ask, apk, TASK_A, "submit_evidence",
                            b"evidence", now, nonce=shared_nonce)
    t1 = time.time()
    res = ver.verify_action(act2, tok, b"evidence", now)
    record("D-15", "nonce reused across different actions", "attack",
           False, "replay-nonce", (res[0], res[1], 0.0, _ms(t1)))

    # D-16: oversized payload (over the 1 MiB cap).
    _, _, ask, apk, tok, ver = fresh_setup(["submit_evidence"])
    big = b"x" * (MAX_PAYLOAD_BYTES + 1)
    act = sign_task_action(ask, apk, TASK_A, "submit_evidence", big, now)
    t1 = time.time()
    res = ver.verify_action(act, tok, big, now)
    record("D-16", "oversized evidence payload", "attack", False,
           "payload-too-large", (res[0], res[1], 0.0, _ms(t1)))

    passed = sum(1 for c in cases if c["pass"])
    summary = {
        "cases_total": len(cases),
        "passed": passed,
        "failed": len(cases) - passed,
        "valid_cases": sum(1 for c in cases if c["category"] == "valid"),
        "attack_cases": sum(1 for c in cases if c["category"] == "attack"),
        "attacks_rejected": sum(
            1 for c in cases
            if c["category"] == "attack" and c["pass"]),
        "lab_clock_unix": now,
        "design": {
            "clock_skew_seconds": CLOCK_SKEW_SECONDS,
            "action_ttl_seconds": ACTION_TTL_SECONDS,
            "token_ttl_seconds": TOKEN_TTL_SECONDS,
            "max_payload_bytes": MAX_PAYLOAD_BYTES,
        },
    }
    return cases, summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--log", required=True)
    args = ap.parse_args()

    now = int(time.time())
    t_start = time.time()
    cases, summary = run_drill(now)
    wall_s = round(time.time() - t_start, 2)
    summary["wall_seconds"] = wall_s
    # Mean timings over cases that performed a fresh sign/verify.
    signed = [c["sign_ms"] for c in cases if c["sign_ms"] > 0]
    verified = [c["verify_ms"] for c in cases if c["verify_ms"] > 0]
    summary["mean_sign_ms"] = round(sum(signed) / len(signed), 1)
    summary["mean_verify_ms"] = round(sum(verified) / len(verified), 1)

    lines = []
    lines.append("lab security drill run start "
                 "(LAB keys only, no live key material)")
    lines.append(f"lab clock (unix): {now}")
    lines.append(f"cases: {summary['cases_total']} "
                 f"({summary['valid_cases']} valid, "
                 f"{summary['attack_cases']} attacks)")
    for c in cases:
        status = "PASS" if c["pass"] else "FAIL"
        lines.append(
            f"  [{c['id']}] {status} {c['name']}: "
            f"expected {c['expected']['ok']}/{c['expected']['reason']}, "
            f"got {c['actual']['ok']}/{c['actual']['reason']} "
            f"(sign {c['sign_ms']} ms, verify {c['verify_ms']} ms)")
    lines.append(f"drill result: {summary['passed']}/"
                 f"{summary['cases_total']} cases PASS "
                 f"({summary['attacks_rejected']}/"
                 f"{summary['attack_cases']} attacks rejected)")
    lines.append(f"mean sign {summary['mean_sign_ms']} ms, "
                 f"mean verify {summary['mean_verify_ms']} ms, "
                 f"wall {wall_s} s")
    lines.append("drill run end")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump({"cases": cases, "summary": summary}, f, indent=1)
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    with open(args.log, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    if summary["failed"]:
        print("drill.py: FAILURES PRESENT")
        return 1
    print("drill.py: ALL CASES PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
