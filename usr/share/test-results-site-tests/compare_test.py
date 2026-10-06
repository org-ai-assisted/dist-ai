#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## AI-Assisted

"""Unit + canary tests for the golden normalize/compare state machine.

Canaries (each asserts the no-false-green contract):
  - a change ONLY inside the masked clock rect is a MATCH (normalization blanks it);
  - a real pixel change OUTSIDE the mask is CHANGED, never a silent MATCH;
  - an absent golden, an absent approval record, and a recorded-but-unapproved
    golden are each NEW (never green);
  - a golden file whose bytes no longer match the approved sha256 is CHANGED;
  - an unreadable current image is UNKNOWN (fail closed), never a pass;
  - MATCH is the ONLY green bucket.

Pillow/numpy absent -> exit 78 (env-unmet), surfaced distinctly, never folded into
a pass. Pure logic otherwise: tiny in-memory images, no root/network.

Exit: 0 all pass, 1 any fail, 78 env-unmet.
"""

import os
import sys
import tempfile

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

try:
    from PIL import Image
    from dm_test_results import compare
except ImportError as exc:
    print("test-results-site compare_test: env-unmet (Pillow/numpy): %s" % exc, file=sys.stderr)
    sys.exit(78)

_failures = 0


def check(label, cond):
    global _failures
    if cond:
        print("ok: %s" % label)
    else:
        print("FAIL: %s" % label, file=sys.stderr)
        _failures += 1


## 20x20 canvas; the clock mask is the top-right 6x6 (inside it, pixel changes are
## ignored; outside it, they count).
SIZE = (20, 20)
MASK = [(14, 0, 6, 6)]


def write_png(path, painted=None):
    image = Image.new("RGB", SIZE, (255, 255, 255))
    if painted:
        (x, y, w, h), color = painted
        image.paste(Image.new("RGB", (w, h), color), (x, y))
    image.save(path, format="PNG")
    return path


def approvals_for(golden_path, screenshot_id="kicksecure-lxqt/r4", status="approved"):
    return {
        screenshot_id: {
            "golden_sha256": compare.sha256_file(golden_path),
            "status": status,
            "approver": "tester",
            "approved_utc": "2026-01-01T00:00:00Z",
            "approved_commit": "0" * 40,
        }
    }


work = tempfile.mkdtemp(prefix="test-results-compare.")
sid = "kicksecure-lxqt/r4"

## Golden = plain white canvas.
golden = write_png(os.path.join(work, "golden.png"))
approvals = approvals_for(golden)

## 1. Identical current -> MATCH (green).
cur_same = write_png(os.path.join(work, "same.png"))
bucket, detail = compare.classify(sid, cur_same, golden, approvals, rects=MASK)
check("identical current is MATCH", bucket == compare.BUCKET_MATCH)
check("MATCH ratio is 0", detail["ratio"] == 0.0)

## 2. Change ONLY inside the masked clock rect -> MATCH (normalization blanks it).
cur_clock = write_png(os.path.join(work, "clock.png"), painted=((15, 1, 4, 4), (255, 0, 0)))
bucket, _ = compare.classify(sid, cur_clock, golden, approvals, rects=MASK)
check("masked-clock-only change is MATCH", bucket == compare.BUCKET_MATCH)
## ...and WITHOUT the mask the very same change is CHANGED (proves the mask did it).
bucket_nomask, _ = compare.classify(sid, cur_clock, golden, approvals, rects=None)
check("same change unmasked is CHANGED", bucket_nomask == compare.BUCKET_CHANGED)

## 3. A real pixel change OUTSIDE the mask -> CHANGED (never a silent MATCH).
cur_real = write_png(os.path.join(work, "real.png"), painted=((0, 0, 5, 5), (0, 0, 255)))
bucket, _ = compare.classify(sid, cur_real, golden, approvals, rects=MASK)
check("real change outside mask is CHANGED", bucket == compare.BUCKET_CHANGED)

## 4. No golden file -> NEW.
bucket, _ = compare.classify(sid, cur_same, os.path.join(work, "absent.png"), approvals, rects=MASK)
check("absent golden is NEW", bucket == compare.BUCKET_NEW)

## 5. No approval record for this id -> NEW.
bucket, _ = compare.classify(sid, cur_same, golden, {}, rects=MASK)
check("no approval record is NEW", bucket == compare.BUCKET_NEW)

## 6. Recorded but status != approved -> NEW (never green on an unapproved golden).
pending = approvals_for(golden, status="pending")
bucket, _ = compare.classify(sid, cur_same, golden, pending, rects=MASK)
check("unapproved golden is NEW", bucket == compare.BUCKET_NEW)

## 7. Golden file bytes no longer match the approved sha256 -> CHANGED.
tampered = approvals_for(golden)
tampered[sid]["golden_sha256"] = "f" * 64
bucket, _ = compare.classify(sid, cur_same, golden, tampered, rects=MASK)
check("golden sha mismatch is CHANGED", bucket == compare.BUCKET_CHANGED)

## 8. Unreadable current -> UNKNOWN (fail closed).
bogus = os.path.join(work, "notimage.png")
with open(bogus, "w", encoding="ascii") as handle:
    handle.write("not a png")
bucket, _ = compare.classify(sid, bogus, golden, approvals, rects=MASK)
check("unreadable current is UNKNOWN", bucket == compare.BUCKET_UNKNOWN)

## 9. MATCH is the only green bucket.
check("only MATCH is green", compare.BUCKET_GREEN == compare.BUCKET_MATCH)

## 10. A malformed approvals file fails closed (raises), never silently empty.
bad_appr = os.path.join(work, "bad-approvals.json")
with open(bad_appr, "w", encoding="ascii") as handle:
    handle.write('{"schema": "wrong", "approvals": {}}')
raised = False
try:
    compare.load_approvals(bad_appr)
except compare.CompareError:
    raised = True
check("malformed approvals file raises", raised)
## ...a MISSING approvals file is the legitimate initial state -> {} (all NEW).
check(
    "missing approvals file is empty (not an error)",
    compare.load_approvals(os.path.join(work, "no-such.json")) == {},
)

import shutil  # noqa: E402

shutil.rmtree(work, ignore_errors=True)

if _failures:
    print("\n%d compare assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall compare assertions passed")
