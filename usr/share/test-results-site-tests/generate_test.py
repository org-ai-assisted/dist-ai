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
import re
import subprocess  # nosec B404 -- drives the in-tree generator, fixed argv
import sys
import tempfile

_SELF = os.path.dirname(os.path.realpath(__file__))
_LIB = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

try:
    from PIL import Image
    from dm_test_results import compare, model, site_classes
except ImportError as exc:
    print("generate_test: env-unmet (Pillow/numpy): %s" % exc, file=sys.stderr)
    sys.exit(78)

GEN = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "bin", "test-results-site-generate")
EPOCH = 1_700_000_000
## A recognizable 64-hex ISO digest the detail page must surface (run M).
SHA256_M = "0123456789abcdef" * 4

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


def write_result(run_dir, run_id, lane, version, rc, stop_unix, step_name, shot_name,
                 artifact_sha256=None):
    atts = []
    if shot_name:
        atts = [model.make_attachment("screenshot", "image/png", shot_name)]
    step = model.make_step(
        name=step_name, status=model.step_status_from_rc(rc), exit_code=rc,
        attachments=atts,
    )
    provenance = {"artifact_sha256": artifact_sha256} if artifact_sha256 else None
    result = model.build_result(
        run_id=run_id, lane=lane, version=version, builder="dm-release-test",
        mode="calamares-install", origin=model.ORIGIN_DOWNLOADED, rc=rc,
        generated_unix=stop_unix, stop_unix=stop_unix, steps=[step],
        provenance=provenance,
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

    ## S: FAIL (rc 5) with a screenshot but NO approved golden -> bucket NEW. The step FAILED,
    ## but the shot's only visual state is "no approved golden yet" (pending first approval), so
    ## its chip must render st-new (soft), NOT be repainted red with the step's st-fail. Canary
    ## for the "fail welcome -- no approved golden yet" over-flagging: pre-fix, any non-pass step
    ## repainted every shot (NEW included) with the step's FAIL class.
    s_dir = os.path.join(root, "kicksecure-lxqt-nogolden-18-2-3-6", "20261006T000000Z")
    write_png(os.path.join(s_dir, "calamares-install.png"), (10, 120, 10))
    write_result(s_dir, "kicksecure-lxqt-nogolden-18-2-3-6-1", "kicksecure-lxqt-nogolden",
                 "18.2.3.6", 5, now, "calamares-install", "calamares-install.png")

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

    ## M: a PASS run that recorded the ISO sha256 -> the detail page must SHOW it, so the
    ## exact artifact under test is identifiable. Regression for the provenance-digest surfacing.
    m_dir = os.path.join(root, "kicksecure-sha-18-2-3-5", "20261006T000000Z")
    write_result(m_dir, "kicksecure-sha-18-2-3-5-1", "kicksecure-sha", "18.2.3.5",
                 0, now, "verify-signature", None,
                 artifact_sha256=SHA256_M)

    ## N: a step whose stderr log is MULTI-KB. The FULL log must survive to the rendered page:
    ## regression for the 1200-char render cut that showed a systemcheck run starting
    ## "...emcheck#" mid-word (its head silently dropped). START + END needles bracket a body
    ## far larger than both the old 1200-char render cut and the old 4 KB emitter cap.
    n_dir = os.path.join(root, "kicksecure-log-18-2-3-5", "20261006T000000Z")
    big_log = "LOGSTART_NEEDLE\n" + ("systemcheck line filler\n" * 400) + "LOGEND_NEEDLE\n"
    n_step = model.make_step(
        name="checks", status=model.step_status_from_rc(1), exit_code=1,
        stderr_tail=big_log,
    )
    n_result = model.build_result(
        run_id="kicksecure-log-18-2-3-5-1", lane="kicksecure-log", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=1, generated_unix=now, stop_unix=now, steps=[n_step],
    )
    os.makedirs(n_dir, exist_ok=True)
    with open(os.path.join(n_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(n_result))

    ## O: a run carrying firmware-lane EVIDENCE (environment.firmware) that MATCHES its declared
    ## lane -> the detail page shows a "Firmware lane" panel with the command/output + a verified
    ## (green) chip. Regression for the firmware-evidence rendering.
    o_dir = os.path.join(root, "kicksecure-fw-18-2-3-5", "20261006T000000Z")
    o_env = {"firmware": {
        "declared": "efi-secureboot", "detected": "UEFI+SecureBoot",
        "evidence": "FWEVIDENCE_NEEDLE: [ -d /sys/firmware/efi ] -> UEFI; mokutil --sb-state -> SecureBoot enabled",
        "match": True,
    }}
    o_step = model.make_step(name="checks", status=model.step_status_from_rc(0), exit_code=0)
    o_result = model.build_result(
        run_id="kicksecure-fw-18-2-3-5-1", lane="kicksecure-fw-efi-secureboot", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=0, generated_unix=now, stop_unix=now, steps=[o_step], environment=o_env)
    os.makedirs(o_dir, exist_ok=True)
    with open(os.path.join(o_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(o_result))

    ## P: firmware evidence that CONTRADICTS the declared lane (booted BIOS, declared
    ## efi-secureboot) -> a MISMATCH (red) chip, so a wrong-lane boot is loud, not silent.
    p_dir = os.path.join(root, "kicksecure-fwbad-18-2-3-5", "20261006T000000Z")
    p_env = {"firmware": {
        "declared": "efi-secureboot", "detected": "BIOS",
        "evidence": "FWMISMATCH_NEEDLE: [ -d /sys/firmware/efi ] -> BIOS (efi dir absent)",
        "match": False,
    }}
    p_step = model.make_step(name="checks", status=model.step_status_from_rc(1), exit_code=1)
    p_result = model.build_result(
        run_id="kicksecure-fwbad-18-2-3-5-1", lane="kicksecure-fwbad-efi-secureboot", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=1, generated_unix=now, stop_unix=now, steps=[p_step], environment=p_env)
    os.makedirs(p_dir, exist_ok=True)
    with open(os.path.join(p_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(p_result))

    ## Q: a PASS verdict (rc=0) whose captured firmware EVIDENCE proves a WRONG-lane boot
    ## (match False). The guest booted the wrong firmware, so the run must NOT be green -- in
    ## the overview cell AND the detail header -- even though the verdict is PASS and there is
    ## no failing shot. The P fixture uses rc=1 (FAIL) and so cannot expose this false green.
    q_dir = os.path.join(root, "kicksecure-fwgreen-18-2-3-5", "20261006T000000Z")
    q_env = {"firmware": {
        "declared": "efi-secureboot", "detected": "BIOS",
        "evidence": "FWGREEN_NEEDLE: [ -d /sys/firmware/efi ] -> BIOS; declared efi-secureboot",
        "match": False,
    }}
    q_step = model.make_step(name="checks", status=model.step_status_from_rc(0), exit_code=0)
    q_result = model.build_result(
        run_id="kicksecure-fwgreen-18-2-3-5-1", lane="kicksecure-fwgreen-efi-secureboot",
        version="18.2.3.5", builder="dm-release-test", mode="calamares-install",
        origin=model.ORIGIN_DOWNLOADED, rc=0, generated_unix=now, stop_unix=now,
        steps=[q_step], environment=q_env)
    os.makedirs(q_dir, exist_ok=True)
    with open(os.path.join(q_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(q_result))

    ## R: a MALFORMED environment.firmware (a non-object). validate must classify it NO-DATA so
    ## site generation CONTINUES; before firmware-object validation, run_fields called .get() on
    ## the string -> AttributeError aborted the WHOLE site. Written raw (model.dumps does not
    ## re-validate), since build_result would reject it at construction.
    r_dir = os.path.join(root, "kicksecure-fwbad2-18-2-3-5", "20261006T000000Z")
    r_step = model.make_step(name="checks", status=model.step_status_from_rc(0), exit_code=0)
    r_result = model.build_result(
        run_id="kicksecure-fwbad2-18-2-3-5-1", lane="kicksecure-fwbad2", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=0, generated_unix=now, stop_unix=now, steps=[r_step])
    r_result["environment"] = {"firmware": "not-an-object"}
    os.makedirs(r_dir, exist_ok=True)
    with open(os.path.join(r_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(r_result))

    with open(approvals_path, "w", encoding="ascii") as handle:
        handle.write(json.dumps(approvals, indent=2) + "\n")


def _rewrite(path, old, new):
    with open(path, "r", encoding="ascii") as handle:
        text = handle.read()
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text.replace(old, new))


def run_generator(root, goldens, approvals_path, site_out, cache_dir=None,
                  full_rebuild=False):
    os.makedirs(site_out, exist_ok=True)
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(EPOCH)
    argv = [GEN, "--results-root", root, "--site-out", site_out,
            "--goldens-dir", goldens, "--approvals", approvals_path]
    ## Pin the incremental cache into the test work dir so the run is hermetic (never touches the
    ## real XDG_CACHE_HOME) and the cache behaviour is exercised deterministically.
    if cache_dir is not None:
        argv += ["--cache-dir", cache_dir]
    if full_rebuild:
        argv += ["--full-rebuild"]
    subprocess.run(  # nosec B603 -- fixed argv, in-tree generator
        argv, check=True, env=env,
    )


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def read_bytes(path):
    with open(path, "rb") as handle:
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

cache_dir = os.path.join(work, "gen-cache")
site1 = os.path.join(work, "site1")
run_generator(plane, goldens, approvals_path, site1, cache_dir=cache_dir)
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

## Generator-owned CSS class contract (dm_test_results.site_classes.GENERATED_CLASSES): every class
## generator emits MUST be in the manifest, so a NEW class (the .stage boot caption that shipped
## with no rule and silently blocked every publish) is caught HERE, in dist-ai's own suite, not
## later as an opaque undefined-classes failure across every generated page at deploy. The
## companion website-tests check (check_generated_class_contract) asserts the served style.css
## defines the manifest; together they close the generator<->style.css drift.
_CLASS_ATTR = re.compile(r'class="([^"]*)"')
_CLASS_TOKEN = re.compile(r'-?[_a-zA-Z][_a-zA-Z0-9-]*\Z')


def emitted_classes(tree):
    tokens = set()
    for base, _dirs, files in os.walk(tree):
        for name in files:
            if name.endswith(".html"):
                for attr in _CLASS_ATTR.findall(read(os.path.join(base, name))):
                    tokens.update(attr.split())
    return tokens


## The fixture uses the generator's built-in header (no --chrome-from lift), so every emitted
## class is a generator literal -- any token outside the manifest is an unregistered new class.
emitted = emitted_classes(out1)
unregistered = sorted(emitted - site_classes.GENERATED_CLASSES)
check("every generator-emitted class is in GENERATED_CLASSES (unregistered: %s)"
      % (unregistered or "none"), not unregistered)
## Canary: the subset check must FAIL on an unregistered class, else it proves nothing.
check("manifest subset check catches an unregistered class (canary)",
      bool((emitted | {"xdrift-canary"}) - site_classes.GENERATED_CLASSES))

## Manifest honesty (no stale entry): the structural half of the manifest must match EXACTLY the
## class literals the generator source emits. The st-<status> half is derived from ALL_STATUSES via
## css_class (not a literal), so it cannot drift and is excluded here. Python source quotes the
## class attribute with backslash-escaped quotes in a few spots -- unescape before scanning.
structural_manifest = {c for c in site_classes.GENERATED_CLASSES if not c.startswith("st-")}
src = read(GEN).replace('\\"', '"')
src_structural = set()
for attr in _CLASS_ATTR.findall(src):
    for tok in attr.split():
        if _CLASS_TOKEN.match(tok):  # skip the "%s" status placeholder in `class="chip %s"`
            src_structural.add(tok)
check("GENERATED_CLASSES structural set matches the generator's class literals exactly "
      "(only-in-manifest=%s only-in-source=%s)"
      % (sorted(structural_manifest - src_structural), sorted(src_structural - structural_manifest)),
      structural_manifest == src_structural)

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
## Provenance digest: run M recorded a sha256, so its detail page shows the exact ISO
## digest; run A recorded none, so its page must NOT invent a sha256 line.
m_page = read(os.path.join(out1, "kicksecure-sha-18-2-3-5-1", "index.html"))
check("run with a recorded sha256 shows it on the detail page", SHA256_M in m_page)
check("a run with no sha256 shows no sha256 line", "sha256 <code" not in a_page)
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

## S: a FAILED run whose shot has NO approved golden (bucket NEW) must render the shot as the
## SOFT st-new "needs approval" state, NOT repainted as the step's red st-fail. This is the
## "fail welcome -- no approved golden yet" over-flagging. The run itself is still st-fail
## overall (verdict), so scope the chip assertion to the shot paragraph. Canary: pre-fix the
## shot chip here was st-fail and no st-new appeared on the page.
s_page = read(os.path.join(out1, "kicksecure-lxqt-nogolden-18-2-3-6-1", "index.html"))
check("failed+no-golden shot shows the pending-approval reason",
      "no approved golden yet" in s_page)
check("failed+no-golden shot chip is the soft st-new state (not red fail)",
      'class="chip st-new"' in s_page)
s_shot_para = (s_page.split("no approved golden yet", 1)[0].rsplit("<p>", 1)[-1]
               if "no approved golden yet" in s_page else "")
check("failed+no-golden shot is not repainted as a red st-fail chip",
      "st-new" in s_shot_para and "st-fail" not in s_shot_para)

## N: a multi-KB step log survives IN FULL to the rendered page -- both the START (head) and
## END (tail) needles must appear. Before the fix the generator re-cut the stored tail to the
## last 1200 chars, dropping the head (systemcheck output began "...emcheck#" mid-word); this
## pins that the full stored log is rendered. The <pre> carries the scroll class so a long log
## stays bounded on the page.
n_page = read(os.path.join(out1, "kicksecure-log-18-2-3-5-1", "index.html"))
check("multi-KB log: END (tail) survives to the page", "LOGEND_NEEDLE" in n_page)
check("multi-KB log: START (head) survives to the page (no 1200-char re-cut)",
      "LOGSTART_NEEDLE" in n_page)
check("step log <pre> is the scrollable class", 'pre class="steplog"' in n_page)

## O/P: firmware-lane evidence renders on the detail page (the booted lane PROOF, not just the
## --firmware label). A matching lane shows a verified panel + the command/output; a contradicting
## lane shows a loud MISMATCH. Regression for #17 firmware evidence.
o_page = read(os.path.join(out1, "kicksecure-fw-18-2-3-5-1", "index.html"))
check("firmware panel: heading present", "Firmware lane" in o_page)
check("firmware panel: detected lane shown", "UEFI+SecureBoot" in o_page)
check("firmware panel: evidence command+output shown", "FWEVIDENCE_NEEDLE" in o_page)
check("firmware panel: matching lane reads verified", "verified against the declared lane" in o_page)
p_page = read(os.path.join(out1, "kicksecure-fwbad-18-2-3-5-1", "index.html"))
check("firmware panel: contradicting lane reads MISMATCH", "MISMATCH" in p_page)
check("firmware panel: mismatch evidence shown", "FWMISMATCH_NEEDLE" in p_page)

## Q: a PASS verdict whose firmware EVIDENCE proves a wrong-lane boot (match False) is NOT
## green -- the detail header AND the overview cell read non-green, not just the panel. Canary:
## before the classifier fix, run_cell_status returned st-pass for this PASS run.
q_page = read(os.path.join(out1, "kicksecure-fwgreen-18-2-3-5-1", "index.html"))
## Scope to the run HEADER (hero section): the per-step chip legitimately reads st-pass (the
## step functionally passed) -- it is the RUN-level status, shown in the header + overview,
## that must not be green when the firmware boot was wrong.
q_hero = q_page.split('<section class="hero">', 1)[-1].split("</section>", 1)[0]
check("PASS+firmware-mismatch detail header is st-fail", "st-fail" in q_hero)
check("PASS+firmware-mismatch detail header is NOT green", "st-pass" not in q_hero)
check("PASS+firmware-mismatch still shows the MISMATCH panel", "MISMATCH" in q_page)
## The overview CELL (not just the header) is non-green: scope to Q's own matrix row.
q_rows = [r for r in matrix_sec.split("<tr>") if "kicksecure-fwgreen-18-2-3-5-1/" in r]
check("PASS+firmware-mismatch has exactly one overview row", len(q_rows) == 1)
check("PASS+firmware-mismatch overview cell is non-green",
      bool(q_rows) and "st-fail" in q_rows[0] and "st-pass" not in q_rows[0])

## R: a malformed environment.firmware does NOT abort the site. run_generator above did not
## raise (it would have, on the pre-fix AttributeError), and the run renders NO-DATA while
## every other run still generated.
r_page = read(os.path.join(out1, "kicksecure-fwbad2-18-2-3-5__20261006T000000Z", "index.html"))
check("malformed-firmware run is NO-DATA", "st-nodata" in r_page)

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

## Determinism: a second generation over identical input is byte-identical. A separate site_out
## (its own empty tree) is a cache MISS even sharing the cache dir -- the cached webps are not
## present there -- so this still exercises a full build and proves determinism.
site2 = os.path.join(work, "site2")
run_generator(plane, goldens, approvals_path, site2, cache_dir=cache_dir)
out2 = os.path.join(site2, "automated-test-results")
check("regeneration is byte-identical (deterministic)", tree_identical(out1, out2))

## Incremental regenerate (F5): a re-run over the SAME site_out with unchanged inputs must REUSE
## each run's already-encoded webp -- the dominant method=6 cost -- not re-encode it. Prove the
## skip by pinning run A's webp mtime to an old value and asserting it survives an incremental
## run (not rewritten) but IS rewritten under --full-rebuild. Byte content stays identical either
## way. Canary: the pre-F5 generator has no cache and always re-encodes, so "mtime preserved"
## FAILS on it.
a_webp = os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1", "kicksecure-lxqt__calamares-install.webp")
check("run A webp has a cache entry",
      os.path.isfile(os.path.join(cache_dir, "kicksecure-lxqt-18-2-3-5-1.json")))
a_bytes = read_bytes(a_webp)
os.utime(a_webp, (EPOCH, EPOCH))
run_generator(plane, goldens, approvals_path, site1, cache_dir=cache_dir)
check("incremental re-run REUSED run A webp (not re-encoded)",
      int(os.stat(a_webp).st_mtime) == EPOCH)
check("incremental re-run kept run A webp byte-identical", read_bytes(a_webp) == a_bytes)
os.utime(a_webp, (EPOCH, EPOCH))
run_generator(plane, goldens, approvals_path, site1, cache_dir=cache_dir, full_rebuild=True)
check("--full-rebuild re-encoded run A webp", int(os.stat(a_webp).st_mtime) != EPOCH)
check("--full-rebuild kept run A webp byte-identical", read_bytes(a_webp) == a_bytes)

## Review-fix regressions (ai-review 2026-10-22): the incremental cache must never serve a stale
## green when a dependency drifts. Each starts from a warm, consistent cache for run A.

## C: a cached webp whose BYTES changed on disk (corruption, partial write) must be re-encoded,
## not reused -- the cache records + verifies each webp's sha. Canary: the pre-fix hit checked
## only that the filename existed, so it kept the corrupt bytes.
run_generator(plane, goldens, approvals_path, site1, cache_dir=cache_dir)
with open(a_webp, "ab") as handle:
    handle.write(b"corruption")
os.utime(a_webp, (EPOCH, EPOCH))
run_generator(plane, goldens, approvals_path, site1, cache_dir=cache_dir)
check("a corrupted cached webp is re-encoded, not reused",
      int(os.stat(a_webp).st_mtime) != EPOCH)
check("a corrupted cached webp is restored to correct bytes", read_bytes(a_webp) == a_bytes)

## A: changing an approved GOLDEN -- stored in a per-lane SUBDIR -- must invalidate the cache, or
## a run stays green against a golden it no longer matches. Canary: the pre-fix flat listdir
## hashed NO golden (they are all in subdirs), so a golden change left the fingerprint unchanged.
golden_a = os.path.join(goldens, "kicksecure-lxqt", "calamares-install.webp")
golden_bytes = read_bytes(golden_a)
os.utime(a_webp, (EPOCH, EPOCH))
with open(golden_a, "ab") as handle:
    handle.write(b"golden-drift")
run_generator(plane, goldens, approvals_path, site1, cache_dir=cache_dir)
check("a changed golden invalidates the cache (run re-processed)",
      int(os.stat(a_webp).st_mtime) != EPOCH)
with open(golden_a, "wb") as handle:
    handle.write(golden_bytes)

## D: one unreadable source screenshot must NOT abort the whole generate -- the fingerprint hash
## degrades per-file like process_run isolates a per-shot read error. (Root bypasses file perms,
## so the unreadable state is unprovable there -- skip the assertion, do not fake a pass.)
if os.geteuid() != 0:
    bad_src = os.path.join(plane, "kicksecure-lxqt-18-2-3-5", "20261006T000000Z",
                           "calamares-install.png")
    src_mode = os.stat(bad_src).st_mode
    os.chmod(bad_src, 0)
    rc = subprocess.run(  # nosec B603 -- fixed argv, in-tree generator
        [GEN, "--results-root", plane, "--site-out", site1, "--goldens-dir", goldens,
         "--approvals", approvals_path, "--cache-dir", cache_dir, "--full-rebuild"],
        env={**os.environ, "SOURCE_DATE_EPOCH": str(EPOCH)}).returncode
    os.chmod(bad_src, src_mode)
    if rc == 0:
        print("ok: an unreadable source screenshot does not crash the generate")
    else:
        print("FAIL: unreadable source crashed the generate (rc=%d)" % rc, file=sys.stderr)
        _failures += 1
else:
    print("ok: unreadable-source check skipped (running as root; perms unprovable)")

## Restore a clean, consistent cache + output for run A before the downstream checks.
run_generator(plane, goldens, approvals_path, site1, cache_dir=cache_dir, full_rebuild=True)

## Stale-artifact cleanup: a '<shot>-golden.webp' is written only while a shot is CHANGED;
## once the shot becomes MATCH the generator stops emitting it. A file left in the run dir
## from a prior generate must be REMOVED on regenerate -- else the asset check flags it
## orphaned and blocks the publish. Plant one in a MATCH run's committed dir, regenerate over
## the SAME out_root, and assert it is gone while the run's real output is rebuilt.
stale_run = os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1")
stale_golden = os.path.join(stale_run, "kicksecure-lxqt__calamares-install-golden.webp")
with open(stale_golden, "wb") as handle:
    handle.write(b"stale-golden-from-a-prior-generate")
## Even with the incremental cache warm for this run, an unexpected file in the page dir forces a
## full rebuild (orphan-purge is still owed), so the stale artifact is removed.
run_generator(plane, goldens, approvals_path, site1, cache_dir=cache_dir)
check("stale per-run -golden.webp removed on regenerate", not os.path.exists(stale_golden))
check("regenerated MATCH run still rebuilt its page",
      os.path.isfile(os.path.join(stale_run, "index.html")))

import shutil  # noqa: E402

shutil.rmtree(work, ignore_errors=True)

if _failures:
    print("\n%d generate assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall generate assertions passed")
