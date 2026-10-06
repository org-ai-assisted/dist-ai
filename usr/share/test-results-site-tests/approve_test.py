#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## AI-Assisted

"""Unit + canary tests for the golden-approval tool.

Canaries:
  - approving a run's shot writes goldens/<id>.webp and records its sha256, and a
    subsequent classify() of that shot flips NEW -> MATCH (green); without the
    approval it is NEW. An approval whose recorded sha does not match the golden
    bytes never reads MATCH (compare's AND-combined rule).
  - rejecting clears the approval (back to NEW);
  - --approver is required to approve; an unsafe screenshot id is refused.

Pillow absent -> exit 78. Exit: 0 all pass, 1 any fail, 78 env-unmet.
"""

import os
import subprocess  # nosec B404 -- drives the in-tree tool, fixed argv
import sys
import tempfile

_SELF = os.path.dirname(os.path.realpath(__file__))
_LIB = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

try:
    from PIL import Image
    from dm_test_results import compare
except ImportError as exc:
    print("approve_test: env-unmet (Pillow/numpy): %s" % exc, file=sys.stderr)
    sys.exit(78)

APPROVE = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "bin", "test-results-site-approve")

_failures = 0


def check(label, cond):
    global _failures
    if cond:
        print("ok: %s" % label)
    else:
        print("FAIL: %s" % label, file=sys.stderr)
        _failures += 1


def run_approve(site_out, *args, expect_ok=True):
    res = subprocess.run(  # nosec B603 -- fixed argv, in-tree tool
        [APPROVE, "--site-out", site_out] + list(args),
        capture_output=True, text=True,
    )
    if expect_ok and res.returncode != 0:
        print("approve failed: %s" % res.stderr, file=sys.stderr)
    return res


work = tempfile.mkdtemp(prefix="approve_test.")
out_root = os.path.join(work, "automated-test-results")
run_id = "kicksecure-lxqt-18-2-3-5-1"
sid = "kicksecure-lxqt/calamares-install"
run_dir = os.path.join(out_root, run_id)
os.makedirs(run_dir)
goldens = os.path.join(work, "goldens")
approvals_path = os.path.join(work, "approvals.json")

## The run's normalized shot (what the generator wrote + compared + displayed).
shot = os.path.join(run_dir, "kicksecure-lxqt__calamares-install.webp")
Image.new("RGB", (40, 30), (20, 90, 40)).save(shot, "WEBP", lossless=True, method=6)

## Before approval: NEW (no golden recorded).
appr0 = compare.load_approvals(approvals_path) if os.path.exists(approvals_path) else {}
b0, _ = compare.classify(sid, shot, os.path.join(goldens, sid + ".webp"), appr0)
check("before approval the shot is NEW", b0 == compare.BUCKET_NEW)

## Approve it.
res = run_approve(work, "--run-id", run_id, "--approve", sid,
                  "--approver", "patrick", "--approved-commit", "abc123",
                  "--goldens-dir", goldens, "--approvals", approvals_path,
                  "--source-date-epoch", "1760000000")
check("approve exits 0", res.returncode == 0)
golden = os.path.join(goldens, sid + ".webp")
check("golden webp created", os.path.isfile(golden))

appr = compare.load_approvals(approvals_path)
check("approval record present", sid in appr)
check("approval status is approved", appr.get(sid, {}).get("status") == "approved")
check("approval records the approver", appr.get(sid, {}).get("approver") == "patrick")
check("approval records the golden sha256",
      appr.get(sid, {}).get("golden_sha256") == compare.sha256_file(golden))

## After approval: the same shot now classifies MATCH (green).
b1, _ = compare.classify(sid, shot, golden, appr)
check("after approval the shot is MATCH (green)", b1 == compare.BUCKET_MATCH)

## A tampered sha (golden bytes != recorded) must never read MATCH.
tampered = dict(appr)
tampered[sid] = dict(appr[sid], golden_sha256="f" * 64)
b2, _ = compare.classify(sid, shot, golden, tampered)
check("a sha-mismatched approval is not MATCH", b2 != compare.BUCKET_MATCH)

## Reject clears the approval -> back to NEW.
run_approve(work, "--run-id", run_id, "--reject", sid,
            "--goldens-dir", goldens, "--approvals", approvals_path)
appr2 = compare.load_approvals(approvals_path)
check("reject clears the approval", sid not in appr2)
b3, _ = compare.classify(sid, shot, golden, appr2)
check("after reject the shot is NEW again", b3 == compare.BUCKET_NEW)

## --approver is required to approve.
res_noapp = run_approve(work, "--run-id", run_id, "--approve", sid,
                        "--goldens-dir", goldens, "--approvals", approvals_path,
                        expect_ok=False)
check("approve without --approver is refused", res_noapp.returncode != 0)

## An unsafe screenshot id (traversal) is refused.
res_bad = run_approve(work, "--run-id", run_id, "--approve", "../../etc/x",
                      "--approver", "x", "--goldens-dir", goldens,
                      "--approvals", approvals_path, expect_ok=False)
check("unsafe screenshot id is refused", res_bad.returncode != 0)

## An unsafe --run-id (would read from an arbitrary dir) is refused.
res_rid = run_approve(work, "--run-id", "../../etc", "--approve", sid,
                      "--approver", "x", "--goldens-dir", goldens,
                      "--approvals", approvals_path, expect_ok=False)
check("unsafe --run-id is refused", res_rid.returncode != 0)

## --approve-all resolves ids from the per-run shots.json manifest (no lossy
## filename-unflatten) and approves only the ones flagged needs_approval.
import json as _json  # noqa: E402

if os.path.exists(approvals_path):
    os.remove(approvals_path)
with open(os.path.join(run_dir, "shots.json"), "w", encoding="ascii") as handle:
    handle.write(_json.dumps({"shots": [
        {"sid": sid, "webp": "kicksecure-lxqt__calamares-install.webp",
         "bucket": "NEW", "needs_approval": True},
        {"sid": "kicksecure-lxqt/other", "webp": "x.webp",
         "bucket": "MATCH", "needs_approval": False},
    ]}))
run_approve(work, "--run-id", run_id, "--approve-all", "--approver", "patrick",
            "--goldens-dir", goldens, "--approvals", approvals_path,
            "--source-date-epoch", "1760000000")
appr_all = compare.load_approvals(approvals_path)
check("--approve-all approved the NEW shot (via manifest)", sid in appr_all)
check("--approve-all skipped the already-MATCH shot",
      "kicksecure-lxqt/other" not in appr_all)

import shutil  # noqa: E402

shutil.rmtree(work, ignore_errors=True)

if _failures:
    print("\n%d approve assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall approve assertions passed")
