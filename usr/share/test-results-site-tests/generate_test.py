#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## AI-Assisted

"""Integration + canary tests for the static site generator.

Drives the REAL test-results-site-generate over a synthetic results plane and
asserts the no-false-green contract on the rendered HTML:
  - only a finished-fresh-PASS-with-approved-MATCH run carries the green class;
  - new / fail / no-data runs carry their non-green classes, never green;
  - a NEW screenshot appears in the NEEDS-APPROVAL section;
  - a text-only step renders with no <img>; a screenshot step renders one;
  - regenerating identical input yields a byte-identical output tree (determinism).

Pillow/numpy absent -> exit 78 (env-unmet). Pure logic otherwise: tiny images,
no root, no network.

Exit: 0 all pass, 1 any fail, 78 env-unmet.
"""

import filecmp
import os
import subprocess  # nosec B404 -- drives the in-tree generator, fixed argv
import sys
import tempfile

_SELF = os.path.dirname(os.path.realpath(__file__))
_LIB = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

try:
    from PIL import Image
    from dm_test_results import compare, model
except ImportError as exc:
    print("generate_test: env-unmet (Pillow/numpy): %s" % exc, file=sys.stderr)
    sys.exit(78)

GEN = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "bin", "test-results-site-generate")
EPOCH = 1_700_000_000

_failures = 0


def check(label, cond):
    global _failures
    if cond:
        print("ok: %s" % label)
    else:
        print("FAIL: %s" % label, file=sys.stderr)
        _failures += 1


def write_png(path, color):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Image.new("RGB", (40, 30), color).save(path, format="PNG")


def write_result(run_dir, run_id, lane, version, rc, stop_unix, step_name, shot_name):
    atts = []
    if shot_name:
        atts = [model.make_attachment("screenshot", "image/png", shot_name)]
    step = model.make_step(
        name=step_name, status=model.step_status_from_rc(rc), exit_code=rc,
        attachments=atts,
    )
    result = model.build_result(
        run_id=run_id, lane=lane, version=version, builder="dm-release-test",
        mode="calamares-install", origin=model.ORIGIN_DOWNLOADED, rc=rc,
        generated_unix=stop_unix, stop_unix=stop_unix, steps=[step],
    )
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(result))


def build_plane(root, goldens, approvals_path):
    import json

    now = EPOCH
    approvals = {"schema": compare.APPROVALS_SCHEMA, "approvals": {}}

    ## A: green -- PASS, fresh, one screenshot matching an approved golden.
    a_dir = os.path.join(root, "kicksecure-lxqt-18-2-3-5", "20261006T000000Z")
    write_png(os.path.join(a_dir, "calamares-install.png"), (10, 120, 10))
    write_result(a_dir, "kicksecure-lxqt-18-2-3-5-1", "kicksecure-lxqt", "18.2.3.5",
                 0, now, "calamares-install", "calamares-install.png")
    ## Golden = the normalized current (same masking the generator applies), as webp.
    sid_a = "kicksecure-lxqt/calamares-install"
    rects = [compare.top_right_rect((40, 30))]
    norm = compare.normalize_image(os.path.join(a_dir, "calamares-install.png"), rects)
    golden_a = os.path.join(goldens, sid_a + ".webp")
    os.makedirs(os.path.dirname(golden_a), exist_ok=True)
    norm.save(golden_a, format="WEBP", lossless=True, quality=100, method=6)
    approvals["approvals"][sid_a] = {
        "golden_sha256": compare.sha256_file(golden_a),
        "status": "approved", "approver": "tester",
        "approved_utc": "2026-01-01T00:00:00Z", "approved_commit": "0" * 40,
    }

    ## B: new -- PASS with a screenshot but no golden -> NEW.
    b_dir = os.path.join(root, "kicksecure-cli-18-2-3-5", "20261006T000000Z")
    write_png(os.path.join(b_dir, "calamares-install.png"), (10, 10, 120))
    write_result(b_dir, "kicksecure-cli-18-2-3-5-1", "kicksecure-cli", "18.2.3.5",
                 0, now, "calamares-install", "calamares-install.png")

    ## C: fail -- rc 5.
    c_dir = os.path.join(root, "kicksecure-lxqt-18-2-3-6", "20261006T000000Z")
    write_result(c_dir, "kicksecure-lxqt-18-2-3-6-1", "kicksecure-lxqt", "18.2.3.6",
                 5, now, "calamares-install", None)

    ## D: no-data -- an unreadable result.json.
    d_dir = os.path.join(root, "whonix-gw-ws-18-2-3-5", "20261006T000000Z")
    os.makedirs(d_dir, exist_ok=True)
    with open(os.path.join(d_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write("{ this is not valid json")

    ## E: text-only pass -- PASS, a step with NO screenshot.
    e_dir = os.path.join(root, "whonix-gw-ws-text-18-2-3-5", "20261006T000000Z")
    write_result(e_dir, "whonix-text-18-2-3-5-1", "whonix-gw-ws-text", "18.2.3.5",
                 0, now, "verify-signature", None)

    with open(approvals_path, "w", encoding="ascii") as handle:
        handle.write(json.dumps(approvals, indent=2) + "\n")


def run_generator(root, goldens, approvals_path, site_out):
    os.makedirs(site_out, exist_ok=True)
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(EPOCH)
    subprocess.run(  # nosec B603 -- fixed argv, in-tree generator
        [GEN, "--results-root", root, "--site-out", site_out,
         "--goldens-dir", goldens, "--approvals", approvals_path],
        check=True, env=env,
    )


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def tree_identical(a, b):
    """True if two directory trees have identical file paths AND identical bytes."""
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    for sub in cmp.common_dirs:
        if not tree_identical(os.path.join(a, sub), os.path.join(b, sub)):
            return False
    return True


work = tempfile.mkdtemp(prefix="generate_test.")
plane = os.path.join(work, "plane")
goldens = os.path.join(work, "goldens")
approvals_path = os.path.join(work, "approvals.json")
os.makedirs(plane)
os.makedirs(goldens)
build_plane(plane, goldens, approvals_path)

site1 = os.path.join(work, "site1")
run_generator(plane, goldens, approvals_path, site1)
out1 = os.path.join(site1, "automated-test-results")
overview = read(os.path.join(out1, "index.html"))

## Overview carries the non-green statuses, and green for exactly the green runs.
check("overview has green pass cell", "st-pass" in overview)
check("overview has NEW cell", "st-new" in overview)
check("overview has FAIL cell", "st-fail" in overview)
check("overview has NO-DATA cell", "st-nodata" in overview)
check("overview CSP is strict", "default-src 'none'" in overview and "script-src 'self'" in overview)
check("overview has no inline script body", "<script>" not in overview)

## The NEW run B (kicksecure-cli) must be listed in NEEDS-APPROVAL.
needs = overview.split('id="needs-approval"', 1)[-1].split("</section>", 1)[0]
check("needs-approval lists the NEW shot", "kicksecure-cli/calamares-install" in needs)
check("needs-approval does not list the approved MATCH run",
      "kicksecure-lxqt/calamares-install" not in needs)

## The green run (A) page shows a screenshot; the text-only run (E) page has none.
a_page = read(os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1", "index.html"))
e_page = read(os.path.join(out1, "whonix-text-18-2-3-5-1", "index.html"))
check("green run page has an <img", "<img" in a_page)
check("green run page webp exists",
      os.path.isfile(os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1",
                                  "kicksecure-lxqt__calamares-install.webp")))
check("green run page is green", "st-pass" in a_page)
check("text-only run page has NO <img", "<img" not in e_page)
check("text-only run page is still green", "st-pass" in e_page)

## The green run's screenshot must classify MATCH (not NEW/CHANGED) -- i.e. the
## approved golden path works end to end.
check("green run page is not flagged new/changed",
      "st-new" not in a_page and "st-changed" not in a_page)

## Determinism: a second generation over identical input is byte-identical.
site2 = os.path.join(work, "site2")
run_generator(plane, goldens, approvals_path, site2)
out2 = os.path.join(site2, "automated-test-results")
check("regeneration is byte-identical (deterministic)", tree_identical(out1, out2))

import shutil  # noqa: E402

shutil.rmtree(work, ignore_errors=True)

if _failures:
    print("\n%d generate assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall generate assertions passed")
