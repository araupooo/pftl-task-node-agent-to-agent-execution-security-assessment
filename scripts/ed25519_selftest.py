#!/usr/bin/env python3
"""ed25519_selftest.py — verify scripts/ed25519.py against the
RFC 8032 section 7.1 test vectors (TEST 1, TEST 2, TEST 3).

Usage: python3 scripts/ed25519_selftest.py [--log outputs/ed25519-test-vectors.log]
Exits 0 only if all three vectors pass (public key derivation,
signature production, verification, and tamper rejection).
"""
import argparse
import os
import sys
import time

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PACK, "scripts"))

from ed25519 import public_key, sign, verify  # noqa: E402

VECTORS = [
    {
        "id": "TEST 1",
        "secret": "9d61b19deffd5a60ba844af492ec2cc4"
                  "4449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a"
                  "0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": "e5564300c360ac729086e2cc806e828a"
                     "84877f1eb8e5d974d873e06522490155"
                     "5fb8821590a33bacc61e39701cf9b46b"
                     "d25bf5f0595bbe24655141438e7a100b",
    },
    {
        "id": "TEST 2",
        "secret": "4ccd089b28ff96da9db6c346ec114e0f"
                  "5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc"
                  "9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": "92a009a9f0d4cab8720e820b5f642540"
                     "a2b27b5416503f8fb3762223ebdb69da"
                     "085ac1e43e15996e458f3613d0f11d8c"
                     "387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "id": "TEST 3",
        "secret": "c5aa8df43f9f837bedb7442f31dcb7b1"
                  "66d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f058"
                  "0816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": "6291d657deec24024827e69c3abe01a3"
                     "0ce548a284743a445e3680d7db5ac3ac"
                     "18ff9b538d16f290ae67f760984dc659"
                     "4a7c15e9716ed28dc027beceea1ec40a",
    },
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=None)
    args = ap.parse_args()

    lines = ["RFC 8032 section 7.1 Ed25519 self-test"]
    passed = 0
    t0 = time.time()
    for v in VECTORS:
        sk = bytes.fromhex(v["secret"])
        pk = bytes.fromhex(v["public"])
        msg = bytes.fromhex(v["message"])
        sig = bytes.fromhex(v["signature"])
        checks = []
        checks.append(("public-key derivation", public_key(sk) == pk))
        checks.append(("signature production", sign(msg, sk, pk) == sig))
        checks.append(("verification", verify(sig, msg, pk)))
        checks.append(("tamper rejection",
                       not verify(sig, msg + b"\x00", pk)))
        ok = all(c[1] for c in checks)
        passed += 1 if ok else 0
        detail = ", ".join(f"{name}={'OK' if r else 'FAIL'}"
                           for name, r in checks)
        lines.append(f"  {v['id']}: {'PASS' if ok else 'FAIL'} ({detail})")
    wall = round(time.time() - t0, 2)
    lines.append(f"self-test: {passed}/{len(VECTORS)} vectors PASS "
                 f"({wall} s)")
    text = "\n".join(lines) + "\n"
    print(text, end="")
    if args.log:
        os.makedirs(os.path.dirname(args.log), exist_ok=True)
        with open(args.log, "w") as f:
            f.write(text)
    return 0 if passed == len(VECTORS) else 1


if __name__ == "__main__":
    sys.exit(main())
