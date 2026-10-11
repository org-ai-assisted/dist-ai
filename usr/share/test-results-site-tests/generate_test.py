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


def write_result_multi(run_dir, run_id, lane, version, rc, stop_unix, step_name, shots):
    """A result with several named milestone shots on one step (the install 'full
    story'). `shots` is a list of (attachment_name, file_basename)."""
    atts = [model.make_attachment(n, "image/png", p) for n, p in shots]
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

    ## I: FAIL (rc 5) with a screenshot that MATCHES an approved golden. The visual
    ## bucket is MATCH but the step FAILED, so the shot chip must NOT read green -- a
    ## failed step's screenshot showing a pass chip is a fabricated-green signal (the
    ## "pass -- within tolerance" shown on a real calamares failure screen). Regression.
    i_dir = os.path.join(root, "kicksecure-lxqt-fail-18-2-3-6", "20261006T000000Z")
    write_png(os.path.join(i_dir, "calamares-install.png"), (10, 120, 10))
    write_result(i_dir, "kicksecure-lxqt-fail-18-2-3-6-1", "kicksecure-lxqt-fail",
                 "18.2.3.6", 5, now, "calamares-install", "calamares-install.png")
    sid_i = "kicksecure-lxqt-fail/calamares-install"
    norm_i = compare.normalize_image(os.path.join(i_dir, "calamares-install.png"), rects)
    golden_i = os.path.join(goldens, sid_i + ".webp")
    os.makedirs(os.path.dirname(golden_i), exist_ok=True)
    norm_i.save(golden_i, format="WEBP", lossless=True, quality=100, method=6)
    approvals["approvals"][sid_i] = {
        "golden_sha256": compare.sha256_file(golden_i),
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

    ## F: a result.json with an ESCAPING (absolute) attachment path -- validate must
    ## reject it (NO-DATA), so root never reads /etc/hostname into a published webp.
    f_dir = os.path.join(root, "escape-18-2-3-5", "20261006T000000Z")
    write_result(f_dir, "escape-1", "escape", "18.2.3.5", 0, now,
                 "calamares-install", "calamares-install.png")
    write_png(os.path.join(f_dir, "calamares-install.png"), (1, 1, 1))
    _rewrite(os.path.join(f_dir, "result.json"),
             '"path": "calamares-install.png"', '"path": "/etc/hostname"')

    ## G: a result.json whose run.id is the RESERVED name 'goldens' -- must be
    ## treated as NO-DATA, never allowed to write into / overwrite the goldens dir.
    g_dir = os.path.join(root, "reserved-18-2-3-5", "20261006T000000Z")
    write_result(g_dir, "goldens", "reserved-lane", "18.2.3.5", 0, now,
                 "verify-signature", None)

    ## H: a PASS run that produces NO shot, but an APPROVED golden exists for its
    ## lane -- the expected screenshot vanished, so the run must NOT read green.
    h_dir = os.path.join(root, "kicksecure-xfce-18-2-3-5", "20261006T000000Z")
    write_result(h_dir, "kicksecure-xfce-18-2-3-5-1", "kicksecure-xfce", "18.2.3.5",
                 0, now, "verify-signature", None)
    sid_h = "kicksecure-xfce/calamares-install"
    golden_h = os.path.join(goldens, sid_h + ".webp")
    os.makedirs(os.path.dirname(golden_h), exist_ok=True)
    Image.new("RGB", (40, 30), (9, 9, 9)).save(golden_h, "WEBP", lossless=True, method=6)
    approvals["approvals"][sid_h] = {
        "golden_sha256": compare.sha256_file(golden_h),
        "status": "approved", "approver": "dev",
        "approved_utc": "2026-01-01T00:00:00Z", "approved_commit": "0" * 40,
    }

    ## I: structurally malformed result (attachments is a list of strings) -> must
    ## be NO-DATA, never an uncaught crash that denies the whole site.
    i_dir = os.path.join(root, "malformed-18-2-3-5", "20261006T000000Z")
    write_result(i_dir, "malformed-1", "malformed", "18.2.3.5", 0, now, "verify-signature", None)
    _rewrite(os.path.join(i_dir, "result.json"), '"attachments": []', '"attachments": ["x"]')

    ## J/K: two runs claiming the SAME run.id -> both must appear (unique page dirs),
    ## neither silently overwritten or dropped.
    j_dir = os.path.join(root, "dup-a-18-2-3-5", "20261006T000000Z")
    write_result(j_dir, "dup-run-1", "dup-a", "18.2.3.5", 0, now, "verify-signature", None)
    k_dir = os.path.join(root, "dup-b-18-2-3-5", "20261006T000000Z")
    write_result(k_dir, "dup-run-1", "dup-b", "18.2.3.5", 0, now, "verify-signature", None)

    ## L: a PASS run with a MULTI-shot "full story" -- several milestone screenshots
    ## on ONE step. Each must render (own webp), labelled by its milestone name, in
    ## filename order. Regression for the multi-screenshot extension.
    l_dir = os.path.join(root, "kicksecure-fullstory-18-2-3-5", "20261006T000000Z")
    write_png(os.path.join(l_dir, "01-welcome.png"), (20, 20, 20))
    write_png(os.path.join(l_dir, "02-partitions.png"), (30, 30, 30))
    write_png(os.path.join(l_dir, "03-first-boot.png"), (40, 40, 40))
    write_result_multi(
        l_dir, "kicksecure-fullstory-18-2-3-5-1", "kicksecure-fullstory", "18.2.3.5",
        0, now, "calamares-install",
        [("welcome", "01-welcome.png"), ("partitions", "02-partitions.png"),
         ("first-boot", "03-first-boot.png")],
    )

    with open(approvals_path, "w", encoding="ascii") as handle:
        handle.write(json.dumps(approvals, indent=2) + "\n")


def _rewrite(path, old, new):
    with open(path, "r", encoding="ascii") as handle:
        text = handle.read()
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text.replace(old, new))


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

## The footer rows are DIRECT <footer> children: no intermediate .wrap that would
## double-apply style.css's per-row gutter and misalign the tagline -- the
## broken-footer regression. The website-tests footer-structure gate enforces this
## across all pages; this canary keeps the generator's own _FOOTER honest.
footer_region = overview.split("<footer>", 1)[-1].rsplit("</footer>", 1)[0]
check("footer .ftop is a direct <footer> child",
      overview.count('<footer><div class="ftop">') == 1)
check("footer has no intermediate .wrap row-wrapper", 'class="wrap"' not in footer_region)
check("footer .fbot tagline row present", '<div class="fbot">' in footer_region)

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

## Overview sorts worst-first: a FAIL run appears ABOVE a PASS run in the matrix
## (the legend still lists pass first, so scope this to the matrix section).
matrix_sec = overview.split('id="matrix"', 1)[-1].split("</section>", 1)[0]
fail_pos = matrix_sec.find("kicksecure-lxqt-18-2-3-6-1")  # run C (fail)
pass_pos = matrix_sec.find("kicksecure-lxqt-18-2-3-5-1")  # run A (pass)
check("overview lists the FAIL run before the PASS run",
      fail_pos != -1 and pass_pos != -1 and fail_pos < pass_pos)

## The green run (A) page shows a screenshot; the text-only run (E) page has none.
a_page = read(os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1", "index.html"))
e_page = read(os.path.join(out1, "whonix-text-18-2-3-5-1", "index.html"))
check("green run page has an <img", "<img" in a_page)
## Per-run detail pages are ephemeral -> noindex (kept out of the sitemap); the
## overview is the stable landing page and stays indexable.
check("run detail page is noindex", 'name="robots" content="noindex"' in a_page)
check("overview page is indexable (no robots noindex)", 'name="robots"' not in overview)
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

## I: a FAILED run whose screenshot visually MATCHES its golden must NOT render a green
## pass chip on the shot -- a failed step's screenshot reading "pass" is a fabricated
## green (status classes appear only as chip classes; style.css is external). Canary:
## before the fix, the MATCH bucket mapped straight to a st-pass chip regardless of the
## step's functional FAIL.
i_page = read(os.path.join(out1, "kicksecure-lxqt-fail-18-2-3-6-1", "index.html"))
check("failed run with a matching shot still renders an <img", "<img" in i_page)
check("failed run page is st-fail", "st-fail" in i_page)
check("failed run page has NO green pass chip (shot not green on a failed step)",
      "st-pass" not in i_page)

## F: an escaping attachment path is rejected -> NO-DATA, and nothing is read or
## copied from the escaping target (no webp written for that run).
f_id = "escape-18-2-3-5__20261006T000000Z"
f_dir_out = os.path.join(out1, f_id)
check("escaping-path run is NO-DATA",
      os.path.isfile(os.path.join(f_dir_out, "index.html"))
      and "st-nodata" in read(os.path.join(f_dir_out, "index.html")))
check("escaping-path run wrote no webp",
      not any(n.endswith(".webp") for n in (os.listdir(f_dir_out) if os.path.isdir(f_dir_out) else [])))

## G: a run whose id is the reserved name 'goldens' never writes into a goldens dir.
check("reserved run.id did not create out_root/goldens",
      not os.path.exists(os.path.join(out1, "goldens")))

## H: a PASS run missing its expected approved golden is NOT green.
h_page = read(os.path.join(out1, "kicksecure-xfce-18-2-3-5-1", "index.html"))
check("missing-expected-shot run flags unknown", "st-unknown" in h_page)
check("missing-expected-shot reason is shown",
      "expected approved golden not produced" in h_page)

## I: a structurally malformed result.json is NO-DATA, and generation did not crash
## (reaching here proves it). One bad file must not deny the whole site.
mal_page = os.path.join(out1, "malformed-18-2-3-5__20261006T000000Z", "index.html")
check("malformed result is NO-DATA (no crash)",
      os.path.isfile(mal_page) and "st-nodata" in read(mal_page))

## J/K: a duplicated run.id does not drop or overwrite a run -- both page dirs exist.
check("colliding run.id keeps the first run", os.path.isdir(os.path.join(out1, "dup-run-1")))
check("colliding run.id keeps the second run (dir-derived id)",
      os.path.isdir(os.path.join(out1, "dup-b-18-2-3-5__20261006T000000Z")))

## The green run (with a shot) gets a per-run shots.json manifest for the approver.
check("per-run shots.json manifest written",
      os.path.isfile(os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1", "shots.json")))

## L: the multi-shot "full story" -- all three milestone webps exist, each is labelled
## by its milestone name, and they render in filename (capture) order.
l_out = os.path.join(out1, "kicksecure-fullstory-18-2-3-5-1")
l_page = read(os.path.join(l_out, "index.html"))
for mshot in ("welcome", "partitions", "first-boot"):
    check("full-story webp for '%s' exists" % mshot,
          os.path.isfile(os.path.join(
              l_out, "kicksecure-fullstory__calamares-install__%s.webp" % mshot)))
    check("full-story page labels milestone '%s'" % mshot,
          "<strong>%s</strong>" % mshot in l_page)
check("full-story milestones render in capture order",
      l_page.find("<strong>welcome</strong>")
      < l_page.find("<strong>partitions</strong>")
      < l_page.find("<strong>first-boot</strong>"))
## The disambiguating sid (lane/step/<milestone>) is used only for multiple shots; a
## single-shot run keeps the plain placeholder caption (no <strong> milestone label).
check("single-shot green run has no milestone label", "<strong>" not in a_page)

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
