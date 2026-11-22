#!/usr/bin/env python3
"""compare_reproduce.py — compare a fresh-clone reproduce run against
the committed pack outputs.

Usage: python3 scripts/compare_reproduce.py <fresh_dir> <pack_dir>

Checks (15):
  1.  pinned excerpts byte-identical (6 files)
  2.  drill-results.json summary counts match
  3.  drill per-case expected/actual/reason match
  4.  auth-model.json structural values match (envelope sizes in range)
  5.  findings.json counts + finding ids/severities/statuses match
  6.  run-manifest.json counts + verdict + drill summary match
      (generated_at_utc excluded)
  7.  docs/claim-index.md byte-identical
  8.  docs/threat-model.md byte-identical
  9.  docs/risk-register.md byte-identical
 10.  docs/gap-register.md byte-identical
 11.  docs/evidence-index.md byte-identical
 12.  fixtures CSVs byte-identical (3 files)
 13.  ed25519 self-test log contains 3/3 PASS
 14.  drill log contains 16/16 PASS
 15.  fresh probe manifest: all 4 pages HTTP 200

Exits 0 only if every check passes. Prints one CHECK line per check
and a final N/15 CHECKS PASSED line.
"""
import json
import os
import sys

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, ok))
    print(f"CHECK {'PASS' if ok else 'FAIL'}: {name}"
          + (f" — {detail}" if detail else ""))
    return ok


def _load(p):
    with open(p) as f:
        return json.load(f)


def _read(p):
    with open(p) as f:
        return f.read()


def main():
    fresh, pack = sys.argv[1], sys.argv[2]

    # 1. excerpts
    excerpts = ["KeyType-enum.txt", "SecretKey-sign-dispatch.txt",
                "PublicKey-verify.txt", "Seed-random-generate.txt",
                "Manifest-verify-revoked.txt",
                "TaskNode-identity-address.txt"]
    ok = all(_read(os.path.join(fresh, "fixtures", "source-excerpts", e))
             == _read(os.path.join(pack, "fixtures", "source-excerpts", e))
             for e in excerpts)
    check("pinned excerpts byte-identical (6 files)", ok)

    # 2. drill summary
    fd = _load(os.path.join(fresh, "outputs", "derived",
                            "drill-results.json"))
    pd = _load(os.path.join(pack, "outputs", "derived",
                            "drill-results.json"))
    fs, ps = fd["summary"], pd["summary"]
    ok = all(fs[k] == ps[k] for k in
             ("cases_total", "passed", "valid_cases", "attack_cases",
              "attacks_rejected"))
    check("drill summary counts match", ok,
          f"{fs['passed']}/{fs['cases_total']} PASS, "
          f"{fs['attacks_rejected']}/{fs['attack_cases']} attacks rejected")

    # 3. drill per-case
    fc = {c["id"]: c for c in fd["cases"]}
    pc = {c["id"]: c for c in pd["cases"]}
    ok = (set(fc) == set(pc) and all(
        fc[i]["expected"] == pc[i]["expected"]
        and fc[i]["actual"] == pc[i]["actual"]
        and fc[i]["pass"] == pc[i]["pass"]
        for i in fc))
    check("drill per-case results match (16 cases)", ok)

    # 4. auth model
    fm = _load(os.path.join(fresh, "outputs", "derived", "auth-model.json"))
    pm = _load(os.path.join(pack, "outputs", "derived", "auth-model.json"))
    fw = fm["measured_wire_sizes_bytes"]
    pw = pm["measured_wire_sizes_bytes"]
    ok = (500 <= fw["capability_token_json"] <= 650
          and 450 <= fw["signed_action_json"] <= 600
          and fw["ed25519_public_key"]
          == pw["ed25519_public_key"]
          and fw["ed25519_signature"]
          == pw["ed25519_signature"]
          and fm["signature_fit_vs_manifest_cap_bytes"]
          ["manifest_cap_bytes"]
          == pm["signature_fit_vs_manifest_cap_bytes"]
          ["manifest_cap_bytes"]
          and fm["nonce_collision_probability"]["actions_per_day"]["1e6"]
          == pm["nonce_collision_probability"]["actions_per_day"]["1e6"]
          and fm["replay_window"]["max_acceptable_age_seconds"]
          == pm["replay_window"]["max_acceptable_age_seconds"])
    check("auth-model values match (sizes in range)", ok,
          f"token {fw['capability_token_json']} B, "
          f"action {fw['signed_action_json']} B")

    # 5. findings
    ff = _load(os.path.join(fresh, "findings.json"))
    pf = _load(os.path.join(pack, "findings.json"))
    ok = (ff["counts"] == pf["counts"]
          and ff["verdict"] == pf["verdict"]
          and [(f["id"], f["severity"], f["status"]) for f in ff["findings"]]
          == [(f["id"], f["severity"], f["status"])
              for f in pf["findings"]])
    check("findings.json counts and list match", ok,
          f"{ff['counts']['total']} findings")

    # 6. run manifest
    fman = _load(os.path.join(fresh, "run-manifest.json"))
    pman = _load(os.path.join(pack, "run-manifest.json"))
    ok = (fman["counts"] == pman["counts"]
          and fman["verdict"] == pman["verdict"]
          and fman["drill"]["cases_total"]
          == pman["drill"]["cases_total"]
          and fman["drill"]["passed"] == pman["drill"]["passed"]
          and fman["drill"]["attacks_rejected"]
          == pman["drill"]["attacks_rejected"])
    check("run-manifest.json counts and verdict match", ok)

    # 7-11. generated docs byte-identical
    for i, doc in enumerate(("claim-index.md", "threat-model.md",
                             "risk-register.md", "gap-register.md",
                             "evidence-index.md"), start=7):
        ok = (_read(os.path.join(fresh, "docs", doc))
              == _read(os.path.join(pack, "docs", doc)))
        check(f"docs/{doc} byte-identical", ok)

    # 12. fixtures CSVs
    csvs = ["owasp-llm-top10-2025.csv", "owasp-agentic-top10-2026.csv",
            "rfc8032-test-vectors.csv"]
    ok = all(_read(os.path.join(fresh, "fixtures", c))
             == _read(os.path.join(pack, "fixtures", c)) for c in csvs)
    check("fixtures CSVs byte-identical (3 files)", ok)

    # 13. ed25519 log
    ok = "3/3 vectors PASS" in _read(os.path.join(
        fresh, "outputs", "ed25519-test-vectors.log"))
    check("ed25519 self-test log shows 3/3 vectors PASS", ok)

    # 14. drill log
    ok = "16/16 cases PASS" in _read(os.path.join(
        fresh, "outputs", "drill-run.log"))
    check("drill log shows 16/16 cases PASS", ok)

    # 15. probe manifest
    lines = _read(os.path.join(fresh, "outputs",
                               "PROBE-MANIFEST.md")).splitlines()
    codes = [ln.split()[1] for ln in lines if ln.startswith("https://")]
    ok = len(codes) == 4 and all(c == "200" for c in codes)
    check("fresh probe manifest: 4 pages HTTP 200", ok,
          f"codes={','.join(codes)}")

    passed = sum(1 for _, ok in CHECKS if ok)
    print(f"{passed}/{len(CHECKS)} CHECKS PASSED")
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
