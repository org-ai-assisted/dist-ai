#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## AI-Assisted

"""Integration + canary tests for the static site generator.

Drives the REAL test-results-site-generate over a synthetic results plane and
asserts the no-false-green contract on the rendered HTML. Status is OBJECTIVE:
  - a finished-fresh-PASS run carries the green class, with NO golden-approval step;
  - fail / no-data / firmware-mismatch runs carry their non-green classes, never green;
  - every screenshot is published; a failed step's shot never reads green;
  - a text-only step renders with no <img>; a screenshot step renders one;
  - regenerating identical input yields a byte-identical output tree (determinism).

Pillow (python3-pil) is a REQUIRED dependency, so a failed import is an environment
bug -> exit 1 (FATAL), never a skip. Pure logic otherwise: tiny images, no root,
no network.

Exit: 0 all pass, 1 any fail (incl. a missing required dependency).
"""

import filecmp
import os
import re
import shutil
import subprocess  # nosec B404 -- drives the in-tree generator, fixed argv
import sys
import tempfile

_SELF = os.path.dirname(os.path.realpath(__file__))
_LIB = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

try:
    from PIL import Image
    from dm_test_results import model, site_classes
except ImportError as exc:
    print("generate_test: FATAL: required dependency Pillow (python3-pil) not "
          "importable: %s" % exc, file=sys.stderr)
    sys.exit(1)

GEN = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "bin", "test-results-site-generate")


def _import_generator():
    """Import the generator as a module to unit-test its pure helpers (its bash-guard line is an
    inert string under Python import; main() runs only under __main__)."""
    import importlib.machinery
    import importlib.util

    loader = importlib.machinery.SourceFileLoader("trs_generate", GEN)
    spec = importlib.util.spec_from_loader("trs_generate", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


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


def build_plane(root):
    ## A: green -- PASS, fresh, one published screenshot. No golden, no approval: a finished
    ## fresh PASS is green on its objective merits (the keystone of the no-human-approval model).
    now = EPOCH
    a_dir = os.path.join(root, "kicksecure-lxqt-18-2-3-5", "20261006T000000Z")
    write_png(os.path.join(a_dir, "calamares-install.png"), (10, 120, 10))
    write_result(a_dir, "kicksecure-lxqt-18-2-3-5-1", "kicksecure-lxqt", "18.2.3.5",
                 0, now, "calamares-install", "calamares-install.png")

    ## B: a second PASS lane with a shot -> also green (publishes its shot, no approval).
    b_dir = os.path.join(root, "kicksecure-cli-18-2-3-5", "20261006T000000Z")
    write_png(os.path.join(b_dir, "calamares-install.png"), (10, 10, 120))
    write_result(b_dir, "kicksecure-cli-18-2-3-5-1", "kicksecure-cli", "18.2.3.5",
                 0, now, "calamares-install", "calamares-install.png")

    ## C: fail -- rc 5, no shot.
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

    ## G: a result.json whose run.id is the RESERVED name 'index.html' -- must get a
    ## dir-derived id instead, never allowed to overwrite the overview index.html.
    g_dir = os.path.join(root, "reserved-18-2-3-5", "20261006T000000Z")
    write_result(g_dir, "index.html", "reserved-lane", "18.2.3.5", 0, now,
                 "verify-signature", None)

    ## I: FAIL (rc 5) WITH a screenshot. The shot is published, but its chip carries the
    ## STEP's functional status -- a failed step's screenshot must NOT read green (a green
    ## chip on a failure screen is a fabricated-green signal). Regression.
    fail_dir = os.path.join(root, "kicksecure-lxqt-fail-18-2-3-6", "20261006T000000Z")
    write_png(os.path.join(fail_dir, "calamares-install.png"), (10, 120, 10))
    write_result(fail_dir, "kicksecure-lxqt-fail-18-2-3-6-1", "kicksecure-lxqt-fail",
                 "18.2.3.6", 5, now, "calamares-install", "calamares-install.png")

    ## MAL: structurally malformed result (attachments is a list of strings) -> must be
    ## NO-DATA, never an uncaught crash that denies the whole site.
    mal_dir = os.path.join(root, "malformed-18-2-3-5", "20261006T000000Z")
    write_result(mal_dir, "malformed-1", "malformed", "18.2.3.5", 0, now, "verify-signature", None)
    _rewrite(os.path.join(mal_dir, "result.json"), '"attachments": []', '"attachments": ["x"]')

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
    ## "...emcheck#" mid-word. START + END needles bracket a body far larger than that cut.
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
    ## the overview cell AND the detail header -- even though the verdict is PASS.
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

    ## V: a PASS run carrying per-shot CONTENT validation + an OCR sidecar + a state-card TEXT panel
    ## (the DISPLAY/publish half). On a PASSING run: a 'validated' shot shows a green content chip; an
    ## 'unvalidated' shot (no golden) shows an INCONCLUSIVE content chip -- NOT green (the keystone:
    ## "every screenshot read green" is what this closes); a 'mismatch' shot shows a FAIL content
    ## chip. The welcome shot has a published OCR sidecar (linked). The vm-defined CARD is TEXT (a
    ## panel, never an <img>). Content validation is ORTHOGONAL to the step's functional status.
    v_dir = os.path.join(root, "kicksecure-vshow-18-2-3-5", "20261006T000000Z")
    write_png(os.path.join(v_dir, "01-welcome.png"), (20, 120, 20))
    write_png(os.path.join(v_dir, "02-keyboard.png"), (60, 60, 60))
    write_png(os.path.join(v_dir, "03-badframe.png"), (90, 20, 20))
    with open(os.path.join(v_dir, "01-welcome.png.ocr.txt"), "w", encoding="utf-8") as handle:
        handle.write("OCRNEEDLE recognized welcome text")
    ## Card at NN=00 so it must render BEFORE the NN>=01 screenshots -- proving shots and cards
    ## interleave by capture order, not grouped (images-then-cards would wrongly float it to the end).
    with open(os.path.join(v_dir, "00-vm-defined.card.txt"), "w", encoding="utf-8") as handle:
        handle.write("CARDNEEDLE [state card -- not a screenshot] VM defined (pre-boot)")
    v_atts = [
        model.make_attachment("welcome", "image/png", "01-welcome.png",
                              validation=model.VALIDATION_VALIDATED),
        model.make_attachment("welcome", "text/plain", "01-welcome.png.ocr.txt"),
        model.make_attachment("keyboard", "image/png", "02-keyboard.png",
                              validation=model.VALIDATION_UNVALIDATED),
        model.make_attachment("badframe", "image/png", "03-badframe.png",
                              validation=model.VALIDATION_MISMATCH),
        model.make_attachment("vm-defined", "text/plain", "00-vm-defined.card.txt"),
    ]
    v_step = model.make_step(name="calamares-install", status=model.step_status_from_rc(0),
                             exit_code=0, attachments=v_atts)
    v_result = model.build_result(
        run_id="kicksecure-vshow-18-2-3-5-1", lane="kicksecure-vshow", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=0, generated_unix=now, stop_unix=now, steps=[v_step])
    os.makedirs(v_dir, exist_ok=True)
    with open(os.path.join(v_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(v_result))

    ## X: an untrusted result.json whose attachment path is a 4301-digit run (a safe component the
    ## model accepts). The capture-order parser must NOT int() the whole string (CPython caps int()
    ## at 4300 digits -> ValueError) and crash the WHOLE site -- the run is isolated, site generates.
    x_dir = os.path.join(root, "kicksecure-bigNN-18-2-3-5", "20261006T000000Z")
    x_atts = [model.make_attachment("blob", "image/png", ("9" * 4301) + ".png")]
    x_step = model.make_step(name="calamares-install", status=model.step_status_from_rc(0),
                             exit_code=0, attachments=x_atts)
    x_result = model.build_result(
        run_id="kicksecure-bigNN-18-2-3-5-1", lane="kicksecure-bigNN", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=0, generated_unix=now, stop_unix=now, steps=[x_step])
    os.makedirs(x_dir, exist_ok=True)
    with open(os.path.join(x_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(x_result))

    ## Y: an equal-NN shot/card tie where result.json lists the CARD first. The render tiebreak is
    ## attachments[] order (seq), so the card must render before the same-NN shot -- not "all shots
    ## then all cards".
    y_dir = os.path.join(root, "kicksecure-tie-18-2-3-5", "20261006T000000Z")
    write_png(os.path.join(y_dir, "calamares-install-10-shot.png"), (15, 15, 15))
    with open(os.path.join(y_dir, "10-card.card.txt"), "w", encoding="utf-8") as handle:
        handle.write("TIECARDNEEDLE powered-off state")
    y_atts = [
        model.make_attachment("tiecard", "text/plain", "10-card.card.txt"),
        model.make_attachment("tieshot", "image/png", "calamares-install-10-shot.png"),
    ]
    y_step = model.make_step(name="calamares-install", status=model.step_status_from_rc(0),
                             exit_code=0, attachments=y_atts)
    y_result = model.build_result(
        run_id="kicksecure-tie-18-2-3-5-1", lane="kicksecure-tie", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=0, generated_unix=now, stop_unix=now, steps=[y_step])
    os.makedirs(y_dir, exist_ok=True)
    with open(os.path.join(y_dir, "result.json"), "w", encoding="ascii") as handle:
        handle.write(model.dumps(y_result))


def _rewrite(path, old, new):
    with open(path, "r", encoding="ascii") as handle:
        text = handle.read()
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text.replace(old, new))


def run_generator(root, site_out, cache_dir=None, full_rebuild=False, mask_config=None):
    os.makedirs(site_out, exist_ok=True)
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(EPOCH)
    argv = [GEN, "--results-root", root, "--site-out", site_out]
    ## Pin the incremental cache into the test work dir so the run is hermetic (never touches the
    ## real XDG_CACHE_HOME) and the cache behaviour is exercised deterministically.
    if cache_dir is not None:
        argv += ["--cache-dir", cache_dir]
    if full_rebuild:
        argv += ["--full-rebuild"]
    if mask_config is not None:
        argv += ["--mask-config", mask_config]
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
os.makedirs(plane)
build_plane(plane)

cache_dir = os.path.join(work, "gen-cache")
site1 = os.path.join(work, "site1")
run_generator(plane, site1, cache_dir=cache_dir)
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
## the generator emits MUST be in the manifest, so a NEW class (the .stage boot caption that shipped
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
check("overview has FAIL cell", "st-fail" in overview)
check("overview has NO-DATA cell", "st-nodata" in overview)
check("overview CSP is strict", "default-src 'none'" in overview and "script-src 'self'" in overview)
check("overview has no inline script body", "<script>" not in overview)
## The human golden-approval workflow is GONE: no needs-approval section, no new/changed classes.
check("overview has NO needs-approval section", 'id="needs-approval"' not in overview)
check("overview has no st-new class", "st-new" not in overview)
check("overview has no st-changed class", "st-changed" not in overview)

## Overview sorts worst-first: a FAIL run appears ABOVE a PASS run in the matrix
## (the legend still lists pass first, so scope this to the matrix section).
matrix_sec = overview.split('id="matrix"', 1)[-1].split("</section>", 1)[0]
fail_pos = matrix_sec.find("kicksecure-lxqt-18-2-3-6-1")  # run C (fail)
pass_pos = matrix_sec.find("kicksecure-lxqt-18-2-3-5-1")  # run A (pass)
check("overview lists the FAIL run before the PASS run",
      fail_pos != -1 and pass_pos != -1 and fail_pos < pass_pos)

## The green run (A) page shows a screenshot and is green with NO golden-approval step;
## the text-only run (E) page has none.
a_page = read(os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1", "index.html"))
e_page = read(os.path.join(out1, "whonix-text-18-2-3-5-1", "index.html"))
check("green run page has an <img", "<img" in a_page)
check("green run page is green (no golden needed)", "st-pass" in a_page)
check("green run page webp exists",
      os.path.isfile(os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1",
                                  "kicksecure-lxqt__calamares-install.webp")))
check("green run page has no needs-approval state", "st-new" not in a_page and "st-changed" not in a_page)
check("text-only run page has NO <img", "<img" not in e_page)
check("text-only run page is still green", "st-pass" in e_page)

## Provenance digest: run M recorded a sha256, so its detail page shows the exact ISO
## digest; run A recorded none, so its page must NOT invent a sha256 line.
m_page = read(os.path.join(out1, "kicksecure-sha-18-2-3-5-1", "index.html"))
check("run with a recorded sha256 shows it on the detail page", SHA256_M in m_page)
check("a run with no sha256 shows no sha256 line", "sha256 <code" not in a_page)
## Per-run detail pages are ephemeral -> noindex (kept out of the sitemap); the
## overview is the stable landing page and stays indexable.
check("run detail page is noindex", 'name="robots" content="noindex"' in a_page)
check("overview page is indexable (no robots noindex)", 'name="robots"' not in overview)
## The disambiguating sid (lane/step/<milestone>) is used only for multiple shots; a
## single-shot run keeps the plain placeholder caption (no <strong> milestone label).
check("single-shot green run has no milestone label", "<strong>" not in a_page)

## Heading-level conformance: no rendered page may SKIP a level (vnu flags "<h3> follows
## <h1>" / "<h4> follows <h2>"). The run page nests firmware+step <h3> under an
## <h2 class="catname"> section (hero <h1> -> section <h2> -> <h3>), and the footer
## heading is <h3> so it never skips after an <h2>. Guards the h1->h3 run-page skip and
## the h2->h4 footer skip at the generator source.
_HEADING = re.compile(r"<h([1-6])\b")


def heading_skip(html):
    prev = None
    for lv in (int(m) for m in _HEADING.findall(html)):
        if prev is not None and lv > prev + 1:
            return (prev, lv)
        prev = lv
    return None


check("run detail page has no heading-level skip", heading_skip(a_page) is None)
check("overview page has no heading-level skip", heading_skip(overview) is None)
check('run page nests sections under an <h2 class="catname">', '<h2 class="catname">' in a_page)
check("footer heading is <h3> (no <h4> skip under <h2>)",
      "<h3>Family</h3>" in overview and "<h4>Family" not in overview)
## Canary: the detector must FIRE on a real skip, else it proves nothing.
check("heading-skip detector catches an h1->h3 skip (canary)",
      heading_skip("<h1>a</h1><h3>b</h3>") == (1, 3))

## Landmark + scrollable a11y: each page carries exactly one <main> (so page content is
## inside a landmark region), both nav landmarks are NAMED so they are unique, and the
## scrollable step-log <pre> is keyboard-focusable. Guards the axe landmark-one-main /
## landmark-unique / region / scrollable-region-focusable findings at the generator.
check("run page has exactly one <main> landmark",
      a_page.count("<main>") == 1 and a_page.count("</main>") == 1)
check("overview has exactly one <main> landmark", overview.count("<main>") == 1)
check("overview matrix details header has text (axe empty-table-header)",
      "<th>details</th>" in overview and "<th></th>" not in overview)
check("header nav is a named landmark", '<nav aria-label="Primary">' in a_page)
check("footer nav is a named landmark", 'nav class="fcols" aria-label="Footer"' in a_page)
check("scrollable step-log <pre> is keyboard-focusable",
      'pre class="steplog" tabindex="0"' in a_page)

## I: a FAILED run WITH a published screenshot. The shot is shown (<img), the run is st-fail,
## and the shot chip carries the step's FAIL status -- NEVER a green pass chip on a failure
## screen. Canary: a green chip anywhere on a failed run's page is a fabricated-green signal.
i_page = read(os.path.join(out1, "kicksecure-lxqt-fail-18-2-3-6-1", "index.html"))
check("failed run with a shot still renders an <img", "<img" in i_page)
check("failed run page is st-fail", "st-fail" in i_page)
check("failed run page has NO green pass chip (shot not green on a failed step)",
      "st-pass" not in i_page)

## N: a multi-KB step log survives IN FULL to the rendered page -- both the START (head) and
## END (tail) needles must appear. Before the fix the generator re-cut the stored tail to the
## last 1200 chars, dropping the head. The <pre> carries the scroll class so a long log stays
## bounded on the page.
n_page = read(os.path.join(out1, "kicksecure-log-18-2-3-5-1", "index.html"))
check("multi-KB log: END (tail) survives to the page", "LOGEND_NEEDLE" in n_page)
check("multi-KB log: START (head) survives to the page (no 1200-char re-cut)",
      "LOGSTART_NEEDLE" in n_page)
check("step log <pre> is the scrollable class", 'pre class="steplog"' in n_page)

## O/P: firmware-lane evidence renders on the detail page (the booted lane PROOF, not just the
## --firmware label). A matching lane shows a verified panel + the command/output; a contradicting
## lane shows a loud MISMATCH.
o_page = read(os.path.join(out1, "kicksecure-fw-18-2-3-5-1", "index.html"))
check("firmware panel: heading present", "Firmware lane" in o_page)
check("firmware panel: detected lane shown", "UEFI+SecureBoot" in o_page)
check("firmware panel: evidence command+output shown", "FWEVIDENCE_NEEDLE" in o_page)
check("firmware panel: matching lane reads verified", "verified against the declared lane" in o_page)
p_page = read(os.path.join(out1, "kicksecure-fwbad-18-2-3-5-1", "index.html"))
check("firmware panel: contradicting lane reads MISMATCH", "MISMATCH" in p_page)
check("firmware panel: mismatch evidence shown", "FWMISMATCH_NEEDLE" in p_page)

## Q: a PASS verdict whose firmware EVIDENCE proves a wrong-lane boot (match False) is NOT
## green -- the detail header AND the overview cell read non-green, not just the panel.
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

## V: per-shot CONTENT validation chips + OCR link + state-card TEXT panel (the DISPLAY/publish
## half). Each shot carries a SECOND chip (the content verdict) beside the functional one, coloured
## via the reused st-* classes; a state card renders as a text panel, never an <img>.
v_dir_out = os.path.join(out1, "kicksecure-vshow-18-2-3-5-1")
v_page = read(os.path.join(v_dir_out, "index.html"))
check("validated shot shows a green content chip", 'st-pass">content: validated' in v_page)
check("mismatch shot shows a FAIL content chip", 'st-fail">content: MISMATCH' in v_page)
check("unvalidated shot shows an INCONCLUSIVE content chip",
      'st-inconclusive">content: UNVALIDATED (no golden)' in v_page)
## KEYSTONE CANARY: an UNVALIDATED shot on a PASSING run is NOT green at the content level -- its
## content chip is never st-pass. This is the exact "every screenshot read green" false-green #60
## closes; a regression that mapped unvalidated -> green would trip here.
check("unvalidated shot is NEVER green (no st-pass content chip)",
      'st-pass">content: UNVALIDATED' not in v_page
      and 'st-pass">content: unvalidated' not in v_page)
## Per-run validation tally (over SHOTS only; the card is authoritative text, not a validated shot).
check("per-run validation tally line rendered",
      "screenshots: 1 validated, 1 unvalidated, 1 mismatch, 0 OCR error" in v_page)
## OCR sidecar: linked under the welcome image + the text file copied into the page dir.
v_ocr = "kicksecure-vshow__calamares-install__welcome.ocr.txt"
check("OCR sidecar link emitted", ('href="%s"' % v_ocr) in v_page and ">OCR text<" in v_page)
check("OCR sidecar file copied into the page dir",
      os.path.isfile(os.path.join(v_dir_out, v_ocr)))
## State card: rendered as a TEXT panel (the card text embedded, labelled), NOT an image.
check("state card text rendered on the page", "CARDNEEDLE" in v_page)
check("state card labelled by its milestone name", "<strong>vm-defined</strong>" in v_page)
check("state card produced NO webp (text, not an image)",
      not any("vm-defined" in n and n.endswith(".webp")
              for n in os.listdir(v_dir_out)))
## Interleave canary: the NN=00 vm-defined card renders BEFORE the NN=01 welcome shot (shots and
## cards ordered by capture NN, not grouped images-then-cards).
check("card at NN=00 renders before the NN=01 welcome shot",
      "CARDNEEDLE" in v_page and v_page.index("CARDNEEDLE") < v_page.index("<strong>welcome</strong>"))

## X: a 4301-digit attachment path did NOT crash the generate (if _milestone_order int()'d the
## whole string the subprocess would have exited 1 and every assertion here would be unreached).
## The run is isolated and rendered.
check("huge-digit NN path run generated (no site crash)",
      os.path.isfile(os.path.join(out1, "kicksecure-bigNN-18-2-3-5-1", "index.html")))

## Y: equal-NN tie -- the card listed first in attachments[] renders before the same-NN shot
## (seq tiebreak = attachments order, not shots-then-cards).
y_page = read(os.path.join(out1, "kicksecure-tie-18-2-3-5-1", "index.html"))
check("equal-NN tie renders the card (listed first) before the shot",
      "TIECARDNEEDLE" in y_page
      and y_page.index("TIECARDNEEDLE") < y_page.index("<strong>tieshot</strong>"))

## F: an escaping attachment path is rejected -> NO-DATA, and nothing is read or
## copied from the escaping target (no webp written for that run).
f_id = "escape-18-2-3-5__20261006T000000Z"
f_dir_out = os.path.join(out1, f_id)
check("escaping-path run is NO-DATA",
      os.path.isfile(os.path.join(f_dir_out, "index.html"))
      and "st-nodata" in read(os.path.join(f_dir_out, "index.html")))
check("escaping-path run wrote no webp",
      not any(n.endswith(".webp") for n in (os.listdir(f_dir_out) if os.path.isdir(f_dir_out) else [])))

## G: a run whose id is the reserved name 'index.html' gets a dir-derived id instead, and the
## overview index.html is the real overview (the matrix), never overwritten by a run page.
check("reserved run.id did not overwrite the overview index.html",
      'id="matrix"' in overview)
check("reserved run.id rendered under a dir-derived id",
      os.path.isdir(os.path.join(out1, "reserved-18-2-3-5__20261006T000000Z")))

## MAL: a structurally malformed result.json is NO-DATA, and generation did not crash
## (reaching here proves it). One bad file must not deny the whole site.
mal_page = os.path.join(out1, "malformed-18-2-3-5__20261006T000000Z", "index.html")
check("malformed result is NO-DATA (no crash)",
      os.path.isfile(mal_page) and "st-nodata" in read(mal_page))

## J/K: a duplicated run.id does not drop or overwrite a run -- both page dirs exist.
check("colliding run.id keeps the first run", os.path.isdir(os.path.join(out1, "dup-run-1")))
check("colliding run.id keeps the second run (dir-derived id)",
      os.path.isdir(os.path.join(out1, "dup-b-18-2-3-5__20261006T000000Z")))

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

## Determinism: a second generation over identical input is byte-identical. A separate site_out
## (its own empty tree) is a cache MISS even sharing the cache dir -- the cached webps are not
## present there -- so this still exercises a full build and proves determinism.
site2 = os.path.join(work, "site2")
run_generator(plane, site2, cache_dir=cache_dir)
out2 = os.path.join(site2, "automated-test-results")
check("regeneration is byte-identical (deterministic)", tree_identical(out1, out2))

## Incremental regenerate (F5): a re-run over the SAME site_out with unchanged inputs must REUSE
## each run's already-encoded webp -- the dominant method=6 cost -- not re-encode it. Prove the
## skip by pinning run A's webp mtime to an old value and asserting it survives an incremental
## run (not rewritten) but IS rewritten under --full-rebuild. Byte content stays identical either
## way. Canary: the pre-F5 generator has no cache and always re-encodes, so "mtime preserved" FAILS.
a_webp = os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1", "kicksecure-lxqt__calamares-install.webp")
check("run A webp has a cache entry",
      os.path.isfile(os.path.join(cache_dir, "kicksecure-lxqt-18-2-3-5-1.json")))
a_bytes = read_bytes(a_webp)
os.utime(a_webp, (EPOCH, EPOCH))
run_generator(plane, site1, cache_dir=cache_dir)
check("incremental re-run REUSED run A webp (not re-encoded)",
      int(os.stat(a_webp).st_mtime) == EPOCH)
check("incremental re-run kept run A webp byte-identical", read_bytes(a_webp) == a_bytes)
os.utime(a_webp, (EPOCH, EPOCH))
run_generator(plane, site1, cache_dir=cache_dir, full_rebuild=True)
check("--full-rebuild re-encoded run A webp", int(os.stat(a_webp).st_mtime) != EPOCH)
check("--full-rebuild kept run A webp byte-identical", read_bytes(a_webp) == a_bytes)

## A cached webp whose BYTES changed on disk (corruption, partial write) must be re-encoded,
## not reused -- the cache records + verifies each webp's sha. Canary: the pre-fix hit checked
## only that the filename existed, so it kept the corrupt bytes.
run_generator(plane, site1, cache_dir=cache_dir)
with open(a_webp, "ab") as handle:
    handle.write(b"corruption")
os.utime(a_webp, (EPOCH, EPOCH))
run_generator(plane, site1, cache_dir=cache_dir)
check("a corrupted cached webp is re-encoded, not reused",
      int(os.stat(a_webp).st_mtime) != EPOCH)
check("a corrupted cached webp is restored to correct bytes", read_bytes(a_webp) == a_bytes)

## One unreadable source screenshot must NOT abort the whole generate -- the fingerprint hash
## degrades per-file like process_run isolates a per-shot read error. (Root bypasses file perms,
## so the unreadable state is unprovable there -- skip the assertion, do not fake a pass.)
if os.geteuid() != 0:
    bad_src = os.path.join(plane, "kicksecure-lxqt-18-2-3-5", "20261006T000000Z",
                           "calamares-install.png")
    src_mode = os.stat(bad_src).st_mode
    os.chmod(bad_src, 0)
    rc = subprocess.run(  # nosec B603 -- fixed argv, in-tree generator
        [GEN, "--results-root", plane, "--site-out", site1,
         "--cache-dir", cache_dir, "--full-rebuild"],
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
run_generator(plane, site1, cache_dir=cache_dir, full_rebuild=True)

## Stale-artifact cleanup: a stray file left in a run dir by a prior generate (an artifact this
## generate no longer emits, or a planted file) must be REMOVED on regenerate -- else the asset
## check flags it orphaned and blocks the publish. Plant one in a run's committed dir, regenerate
## over the SAME out_root, and assert it is gone while the run's real output is rebuilt.
stale_run = os.path.join(out1, "kicksecure-lxqt-18-2-3-5-1")
stray = os.path.join(stale_run, "kicksecure-lxqt__calamares-install-stray.webp")
with open(stray, "wb") as handle:
    handle.write(b"stray-artifact-from-a-prior-generate")
## Even with the incremental cache warm for this run, an unexpected file in the page dir forces a
## full rebuild (orphan-purge is still owed), so the stale artifact is removed.
run_generator(plane, site1, cache_dir=cache_dir)
check("stray per-run artifact removed on regenerate", not os.path.exists(stray))
check("regenerated run still rebuilt its page",
      os.path.isfile(os.path.join(stale_run, "index.html")))

## Per-rect OCR redaction (deterministic unit test, no tesseract): _redact_ocr_text keeps tokens
## whose box is OUTSIDE every privacy rect and drops any that overlap -- fail-closed per token. This
## is the operator's rule ("a masked-rect token absent, an unmasked token present on the same
## frame") at the function level, free of OCR flake.
_gen = _import_generator()
## Rect at (0,0,50,20). Tokens: SECRET fully inside; PUBLIC fully outside; EDGE straddling the edge.
_words = [
    (5, 5, 20, 10, "SECRETTOKEN"),     # inside the rect -> dropped
    (100, 100, 30, 10, "PUBLICTOKEN"),  # outside -> kept
    (40, 5, 30, 10, "EDGETOKEN"),       # overlaps the right edge of the rect -> dropped (fail-closed)
]
_redacted = _gen._redact_ocr_text(_words, [[0, 0, 50, 20]])
check("per-rect redaction drops an in-rect token", "SECRETTOKEN" not in _redacted)
check("per-rect redaction keeps an out-of-rect token", "PUBLICTOKEN" in _redacted)
check("per-rect redaction drops an edge-overlapping token (fail-closed)", "EDGETOKEN" not in _redacted)
check("per-rect redaction keeps tokens that only TOUCH an edge",
      "TOUCHTOKEN" in _gen._redact_ocr_text([(50, 0, 10, 10, "TOUCHTOKEN")], [[0, 0, 50, 20]]))

## Orphan-OCR + masked-lane e2e: a dedicated generate with a mask config.
mask_plane = os.path.join(work, "maskplane")
mask_site = os.path.join(work, "masksite")
## Masked lane: a real UI frame (so re-OCR reads text) + its run-time OCR sidecar.
baseline = os.path.join(os.path.dirname(os.path.dirname(_SELF)), "share",
                        "dm-smbios-reader-boot-tests", "render-baselines",
                        "kicksecure-calamares-1280x800", "welcome.png")
m1 = os.path.join(mask_plane, "kicksecure-masked-18-2-3-5", "20261006T000000Z")
os.makedirs(m1, exist_ok=True)
if os.path.isfile(baseline):
    shutil.copyfile(baseline, os.path.join(m1, "01-welcome.png"))
else:
    write_png(os.path.join(m1, "01-welcome.png"), (20, 120, 20))
with open(os.path.join(m1, "01-welcome.png.ocr.txt"), "w", encoding="utf-8") as handle:
    handle.write("MASKEDOCRSECRET welcome text")   # run-time (unmasked) sidecar -- must NOT publish verbatim
m1_atts = [model.make_attachment("welcome", "image/png", "01-welcome.png"),
           model.make_attachment("welcome", "text/plain", "01-welcome.png.ocr.txt")]
m1_step = model.make_step(name="calamares-install", status=model.step_status_from_rc(0),
                          exit_code=0, attachments=m1_atts)
with open(os.path.join(m1, "result.json"), "w", encoding="ascii") as handle:
    handle.write(model.dumps(model.build_result(
        run_id="kicksecure-masked-18-2-3-5-1", lane="kicksecure-masked", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=0, generated_unix=EPOCH, stop_unix=EPOCH, steps=[m1_step])))
## Orphan OCR on a NON-masked lane: a .ocr.txt text attachment with NO matching image shot.
m2 = os.path.join(mask_plane, "kicksecure-orphan-18-2-3-5", "20261006T000000Z")
os.makedirs(m2, exist_ok=True)
with open(os.path.join(m2, "zz.png.ocr.txt"), "w", encoding="utf-8") as handle:
    handle.write("ORPHANOCRSECRET")
m2_atts = [model.make_attachment("stray", "text/plain", "zz.png.ocr.txt")]
m2_step = model.make_step(name="calamares-install", status=model.step_status_from_rc(0),
                          exit_code=0, attachments=m2_atts)
with open(os.path.join(m2, "result.json"), "w", encoding="ascii") as handle:
    handle.write(model.dumps(model.build_result(
        run_id="kicksecure-orphan-18-2-3-5-1", lane="kicksecure-orphan", version="18.2.3.5",
        builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=0, generated_unix=EPOCH, stop_unix=EPOCH, steps=[m2_step])))
## Mask the whole top band (the Calamares title) but leave the lower panel; re-OCR must drop the
## title tokens while keeping the lower-panel ones.
mask_cfg = os.path.join(work, "mask.json")
with open(mask_cfg, "w", encoding="ascii") as handle:
    handle.write('{"kicksecure-masked": [[0, 0, 1280, 120]]}')
run_generator(mask_plane, mask_site, mask_config=mask_cfg)
mask_out = os.path.join(mask_site, "automated-test-results")
masked_dir = os.path.join(mask_out, "kicksecure-masked-18-2-3-5-1")
masked_page = read(os.path.join(masked_dir, "index.html"))
orphan_page = read(os.path.join(mask_out, "kicksecure-orphan-18-2-3-5-1", "index.html"))
check("masked lane still renders its screenshot", "<img" in masked_page)
## The run-time (UNmasked) sidecar text is NEVER published verbatim on a masked lane -- regardless
## of tesseract: with tesseract the re-OCR replaces it; without, it fails closed to no sidecar.
published_ocr = [n for n in os.listdir(masked_dir) if n.endswith(".ocr.txt")]
masked_ocr_text = read(os.path.join(masked_dir, published_ocr[0])) if published_ocr else ""
check("masked lane never publishes the run-time unmasked OCR text",
      "MASKEDOCRSECRET" not in masked_ocr_text and "MASKEDOCRSECRET" not in masked_page)
check("orphan OCR is NOT rendered as a card (secret absent)", "ORPHANOCRSECRET" not in orphan_page)
## Tesseract-dependent e2e: when it is present (sandbox), the masked top band's text is dropped
## while the lower panel's text survives. On a host without tesseract the re-OCR fails closed (no
## sidecar), already covered above; the deterministic unit test covers the redaction rule either way.
if shutil.which("tesseract") and os.path.isfile(baseline):
    from dm_test_results import ocr as _ocr  # noqa: E402
    _full_words = _ocr.tesseract_words(baseline)
    _full_text = " ".join(w[4] for w in _full_words)
    _expected = _gen._redact_ocr_text(_full_words, [[0, 0, 1280, 120]])
    check("masked lane publishes a (redacted) OCR link", ">OCR text<" in masked_page)
    ## The generator re-OCRs the identical image with the identical tesseract, so its published
    ## sidecar must EQUAL the redaction function applied to the real OCR for that mask rect.
    check("masked OCR == per-rect redaction of the real OCR", masked_ocr_text == _expected)
    ## The top band carried text, so redaction must have DROPPED tokens (shorter) yet kept some.
    check("masking actually dropped tokens but kept the rest",
          0 < len(_expected) < len(_full_text))
else:
    print("ok: masked-lane redaction e2e deferred to the sandbox (no tesseract here); "
          "unit test covers the rule")

shutil.rmtree(work, ignore_errors=True)

if _failures:
    print("\n%d generate assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall generate assertions passed")
