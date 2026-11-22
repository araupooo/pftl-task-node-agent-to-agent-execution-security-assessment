#!/usr/bin/env python3
"""extract_excerpts.py — extract pinned-source excerpts from a local
checkout of postfiatd at the pinned commit.

Usage: python3 scripts/extract_excerpts.py [--repo /path/to/postfiatd]
If --repo is omitted, the script clones postfiatd (depth 1) and checks
out the pinned commit into a temp directory. Every excerpt file starts
with a header giving repo, commit, file, and 1-based line range, all
verified with grep -n on the checkout. Exits 0 only if the checkout
HEAD equals the pinned commit and every requested line range exists.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PINNED = "0085a1ff885d6a446369cf73a4430f75af22be55"
REPO_URL = "https://github.com/postfiatorg/postfiatd"

# (output filename, source file, first line, last line, 1-based inclusive)
EXCERPTS = [
    ("KeyType-enum.txt",
     "include/xrpl/protocol/KeyType.h", 1, 45),
    ("SecretKey-sign-dispatch.txt",
     "include/xrpl/protocol/SecretKey.h", 130, 182),
    ("PublicKey-verify.txt",
     "include/xrpl/protocol/PublicKey.h", 230, 262),
    ("Seed-random-generate.txt",
     "include/xrpl/protocol/Seed.h", 90, 120),
    ("Manifest-verify-revoked.txt",
     "src/xrpld/app/misc/detail/Manifest.cpp", 190, 245),
    ("TaskNode-identity-address.txt",
     "docs/dynamic-unl/archive/Design_DistributedLocalHardware.md",
     45, 60),
]


def _run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=None)
    args = ap.parse_args()

    tmp = None
    repo = args.repo
    if repo is None:
        tmp = tempfile.mkdtemp(prefix="pftl-a2a-postfiatd.")
        repo = os.path.join(tmp, "postfiatd")
        r = _run(["git", "clone", "-q", "--depth", "1", REPO_URL, repo])
        if r.returncode != 0:
            print("clone failed:", r.stderr.strip())
            return 1
        r = _run(["git", "fetch", "-q", "--depth", "1", "origin", PINNED],
                 cwd=repo)
        if r.returncode != 0:
            print("fetch failed:", r.stderr.strip())
            return 1
        r = _run(["git", "checkout", "-q", PINNED], cwd=repo)
        if r.returncode != 0:
            print("checkout failed:", r.stderr.strip())
            return 1
    head = _run(["git", "rev-parse", "HEAD"], cwd=repo).stdout.strip()
    if head != PINNED:
        print(f"HEAD {head} != pinned {PINNED}")
        return 1
    print(f"checkout HEAD verified: {head}")

    outdir = os.path.join(PACK, "fixtures", "source-excerpts")
    os.makedirs(outdir, exist_ok=True)
    for name, src, first, last in EXCERPTS:
        path = os.path.join(repo, src)
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        if last > len(lines):
            print(f"{src}: only {len(lines)} lines, need {last}")
            return 1
        excerpt = lines[first - 1:last]
        header = [
            "# Pinned source excerpt",
            "# repo: https://github.com/postfiatorg/postfiatd",
            f"# commit: {PINNED}",
            f"# file: {src}",
            f"# lines: {first}-{last} (1-based, verified with grep -n)",
            "# ----",
        ]
        body = [f"{n}: {line}" for n, line in
                zip(range(first, last + 1), excerpt)]
        with open(os.path.join(outdir, name), "w") as f:
            f.write("\n".join(header + body) + "\n")
        print(f"  {name}: {src} lines {first}-{last} "
              f"({len(excerpt)} lines)")
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    print("extract_excerpts.py: ALL EXCERPTS WRITTEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
