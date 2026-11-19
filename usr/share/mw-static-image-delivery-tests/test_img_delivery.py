#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Black-box regression for mw-static-generator's image-delivery byte-budget gate
(tools/check-img-compression.py): the gate that REPRODUCES Google PageSpeed /
Lighthouse's "Improve image delivery" per-image byte saving so an under-compressed
served raster is caught at the deploy gate, not weeks later on a field PageSpeed run.

WHY a dist-ai suite: the gate + its byte model are SINGLE-SOURCED in the generator
(like every other tools/check-img-*.py) and run only in the deploy-time lint-gate.sh
lane -- the generator has no GitHub CI. This suite adds the missing CI coverage by
DRIVING the real gate (resolved from MW_STATIC_GENERATOR_REPO) against fixtures this
suite generates, and asserting its verdict + its reported bytes. It copies NO
production constant: the oracle below states the EXTERNAL Lighthouse model the gate
must reproduce -- a test oracle, not a second source of truth.

Subject resolution + the absent-subject policy live in the bash entrypoint
(usr/bin/mw-static-image-delivery-tests): it exports MW_STATIC_GENERATOR_REPO only
when the gate is present, so by the time this module runs the subject is guaranteed.
Required fixture tools (Pillow, avifenc) are declared CI dependencies -- their
absence is FATAL (exit 1), never a skip.

Exit: 0 all pass, 1 a failure or a missing required dependency.
"""
from __future__ import annotations

import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# The EXTERNAL Lighthouse ImageDelivery model (devtools-frontend
# models/trace/insights/ImageDelivery.ts) that the gate must reproduce. Stated
# HERE as the test's independent oracle -- NOT a copy of the generator's
# production constant: this suite asserts the gate's reported bytes equal what
# Lighthouse/PageSpeed would compute, so it must know Lighthouse's own numbers.
# The float expression mirrors Chromium's Math.round (floor(x + 0.5), half-UP)
# and multiplies the pixel count FIRST, exactly as the gate's ideal_bytes does,
# so the oracle lands on the same side of every half-integer boundary.
# ---------------------------------------------------------------------------
TARGET_BYTES_PER_PIXEL = 2 / 12
BYTE_SAVINGS_THRESHOLD = 4096


def oracle_ideal(width: int, height: int) -> int:
    return math.floor(TARGET_BYTES_PER_PIXEL * (width * height) + 0.5)


def oracle_saving(nbytes: int, width: int, height: int) -> int:
    px = width * height
    if nbytes / px <= TARGET_BYTES_PER_PIXEL:
        return 0
    return nbytes - oracle_ideal(width, height)


# Parses one gate finding line, e.g.
#   OVER-BUDGET  /path/x.png: 65540B at 400x400, ideal 26667, saving 38873 > 4096
_LINE = re.compile(
    r"^(?P<verdict>OVER-BUDGET|WARN-EXEMPT)\s+(?P<path>.+?): "
    r"(?P<bytes>\d+)B at (?P<w>\d+)x(?P<h>\d+), ideal (?P<ideal>\d+), "
    r"saving (?P<saving>\d+) > (?P<slack>\d+)")


class Harness:
    def __init__(self, gate: Path) -> None:
        self.gate = gate
        self.passed = 0
        self.failed = 0

    def ok(self, cond: bool, desc: str, detail: str = "") -> None:
        if cond:
            self.passed += 1
            print(f"PASS: {desc}")
        else:
            self.failed += 1
            print(f"FAIL: {desc}{(' -- ' + detail) if detail else ''}")

    def run_gate(self, *targets: str) -> subprocess.CompletedProcess:
        # Invoke by the gate's REAL path so its __file__-anchored registry
        # resolution (<repo>/tools -> <repo>/usr/share/mw-static-generator) works
        # exactly as in the deploy lane; a target's parent dir is also trusted,
        # which the exempt-case sidecar below relies on.
        return subprocess.run(
            [sys.executable, "-Bsu", str(self.gate), *targets],
            capture_output=True, text=True)

    def finding_for(self, out: str, path: Path):
        """The parsed gate finding line whose path matches `path`, or None."""
        want = str(path)
        for line in out.splitlines():
            m = _LINE.match(line)
            if m and m.group("path") == want:
                return m
        return None


def _png(path: Path, size, color=None, noise: bool = False) -> None:
    from PIL import Image
    if noise:
        import os as _os
        im = Image.frombytes("RGB", size, _os.urandom(size[0] * size[1] * 3))
    else:
        im = Image.new("RGB", size, color or (32, 96, 200))
    im.save(path, "PNG")


def _png_padded(path: Path, size, total_bytes: int) -> None:
    """A flat PNG of `size`, then zero-padded to EXACTLY total_bytes. The gate reads
    dimensions header-only (so the trailing bytes do not change w x h) and the byte
    size from the file, so padding gives deterministic control of the saving -- the
    only way to land a fixture on a chosen side of the 4096-byte threshold or a
    half-integer rounding boundary, which encoder output size cannot hit on purpose."""
    from PIL import Image
    Image.new("RGB", size, (10, 20, 30)).save(path, "PNG")
    pad = total_bytes - path.stat().st_size
    if pad < 0:
        raise ValueError(f"base PNG already {path.stat().st_size}B > target {total_bytes}B")
    with path.open("ab") as fh:
        fh.write(b"\0" * pad)


def _webp_lossless(path: Path, size, noise: bool = False) -> None:
    from PIL import Image
    if noise:
        import os as _os
        im = Image.frombytes("RGB", size, _os.urandom(size[0] * size[1] * 3))
    else:
        im = Image.new("RGB", size, (32, 96, 200))
    im.save(path, "WEBP", lossless=True, quality=100, method=4)


def _avif_overbudget(png_src: Path, dest: Path) -> None:
    # Debian's Pillow predates native AVIF, so encode with avifenc (the same
    # encoder the generator uses). Lossless over a noise source guarantees the
    # output overshoots the budget, exercising the gate's stdlib ispe-box parse.
    subprocess.run(
        ["avifenc", "--lossless", "-j", "1", str(png_src), str(dest)],
        check=True, capture_output=True, text=True)


def main() -> int:
    # The entrypoint resolves the subject and exports MW_STATIC_GENERATOR_REPO
    # only when the gate exists, so these are defensive FATALs, never a skip.
    repo = os.environ.get("MW_STATIC_GENERATOR_REPO", "").strip()
    gate = Path(repo) / "tools" / "check-img-compression.py" if repo else Path()
    if not repo or not gate.is_file():
        print("mw-static-image-delivery-tests: FATAL "
              f"(gate not resolvable: MW_STATIC_GENERATOR_REPO={repo!r})",
              file=sys.stderr)
        return 1

    # Required fixture dependencies: a present subject with an absent declared
    # dep is a broken environment (FATAL), never a skip.
    try:
        import PIL  # noqa: F401
    except ImportError:
        print("mw-static-image-delivery-tests: FATAL (python3-pil missing)",
              file=sys.stderr)
        return 1
    from shutil import which
    if which("avifenc") is None:
        print("mw-static-image-delivery-tests: FATAL (avifenc missing; "
              "install libavif-bin)", file=sys.stderr)
        return 1

    h = Harness(gate)
    work = Path(tempfile.mkdtemp(prefix="mw-img-delivery."))

    # -- Case 1: an over-budget raster is FLAGGED, and the gate reproduces
    #    PageSpeed's per-image saving byte-for-byte (the core regression). --
    d1 = work / "c1"
    d1.mkdir()
    f1 = d1 / "distai_overbudget_fixture.png"
    _png(f1, (400, 400), noise=True)
    r1 = h.run_gate(str(d1))
    m1 = h.finding_for(r1.stdout, f1)
    h.ok(r1.returncode == 1, "over-budget raster fails the gate (canary: can fail)",
         f"rc={r1.returncode} out={r1.stdout!r} err={r1.stderr!r}")
    if m1 is None:
        h.ok(False, "over-budget raster is reported as OVER-BUDGET", r1.stdout)
    else:
        nbytes = int(m1.group("bytes"))
        w, ht = int(m1.group("w")), int(m1.group("h"))
        ideal = int(m1.group("ideal"))
        saving = int(m1.group("saving"))
        h.ok(m1.group("verdict") == "OVER-BUDGET",
             "fixture reported with OVER-BUDGET verdict")
        h.ok((w, ht) == (400, 400), "gate reads intrinsic dimensions", f"{w}x{ht}")
        h.ok(nbytes == f1.stat().st_size, "gate reports the true file byte size",
             f"{nbytes} vs {f1.stat().st_size}")
        h.ok(ideal == oracle_ideal(w, ht),
             "ideal size reproduces Lighthouse byte-for-byte",
             f"gate {ideal} vs oracle {oracle_ideal(w, ht)}")
        h.ok(saving == oracle_saving(nbytes, w, ht),
             "reported saving reproduces Lighthouse byte-for-byte",
             f"gate {saving} vs oracle {oracle_saving(nbytes, w, ht)}")
        h.ok(saving == nbytes - ideal and saving > BYTE_SAVINGS_THRESHOLD,
             "saving = bytes - ideal and exceeds the 4096-byte threshold")

    # -- Case 2: a within-budget raster PASSES, nothing reported for it. --
    d2 = work / "c2"
    d2.mkdir()
    f2 = d2 / "distai_withinbudget_fixture.png"
    _png(f2, (400, 400), color=(10, 20, 30))  # flat -> tiny, bpp << target
    r2 = h.run_gate(str(d2))
    h.ok(r2.returncode == 0, "within-budget raster passes the gate (canary: can pass)",
         f"rc={r2.returncode} out={r2.stdout!r} err={r2.stderr!r}")
    h.ok(h.finding_for(r2.stdout, f2) is None,
         "within-budget raster is NOT flagged")

    # -- Case 3: exemption keys on the SOURCE File NAME, not mere sidecar presence.
    #    Scan a media dir holding TWO over-budget images -- one whose source name is
    #    in the sidecar, one that is NOT -- with the sidecar in the dir's PARENT (a
    #    trusted exempt dir; a scan-target dir's own sidecar is intentionally not
    #    read). The listed one must WARN-EXEMPT, the UNLISTED one must stay
    #    OVER-BUDGET and fail the run (exit 1). A gate that exempted every readable
    #    image whenever a sidecar exists would pass both -> exit 0, caught here. The
    #    served-name form (<Source>.png.webp) also proves _source_base strips the
    #    derivative extension to key on the source File name. --
    d3 = work / "c3"
    media3 = d3 / "media"
    media3.mkdir(parents=True)
    f3_listed = media3 / "Distai_exempt_fixture.png.webp"
    f3_unlisted = media3 / "Distai_unlisted_fixture.png.webp"
    _webp_lossless(f3_listed, (300, 300), noise=True)
    _webp_lossless(f3_unlisted, (300, 300), noise=True)
    (d3 / "img-budget-photo-exempt.txt").write_text(
        "# dist-ai image-delivery suite fixture\nDistai_exempt_fixture.png\n",
        encoding="utf-8")
    r3 = h.run_gate(str(media3))
    m3_listed = h.finding_for(r3.stdout, f3_listed)
    m3_unlisted = h.finding_for(r3.stdout, f3_unlisted)
    h.ok(m3_listed is not None and m3_listed.group("verdict") == "WARN-EXEMPT",
         "allowlisted image reported as WARN-EXEMPT", r3.stdout)
    h.ok(m3_unlisted is not None and m3_unlisted.group("verdict") == "OVER-BUDGET",
         "an UNLISTED over-budget image beside the sidecar stays OVER-BUDGET "
         "(exemption keys on the name, not sidecar presence)", r3.stdout)
    h.ok(r3.returncode == 1, "the unlisted over-budget image fails the run (exit 1)",
         f"rc={r3.returncode} out={r3.stdout!r} err={r3.stderr!r}")

    # -- Case 4: an UNREADABLE file is never exempt -- fail-closed even with its
    #    source name in the same sidecar (the inverse canary of case 3). --
    d4 = work / "c4"
    d4.mkdir()
    f4 = d4 / "Distai_exempt_fixture.png.webp"
    f4.write_bytes(b"RIFF....WEBPnot a real image, truncated garbage")
    (d4 / "img-budget-photo-exempt.txt").write_text(
        "Distai_exempt_fixture.png\n", encoding="utf-8")
    r4 = h.run_gate(str(f4))
    h.ok(r4.returncode == 1, "unreadable raster fails the gate even when allowlisted",
         f"rc={r4.returncode} out={r4.stdout!r} err={r4.stderr!r}")
    h.ok("unreadable" in (r4.stdout + r4.stderr).lower(),
         "unreadable raster is reported as unreadable")

    # -- Case 5: AVIF is measured via the stdlib ispe-box parse (no Pillow-AVIF).
    #    A lossless AVIF of noise overshoots the budget; assert dims + flag. --
    d5 = work / "c5"
    d5.mkdir()
    src5 = d5 / "_src_noise.png"
    _png(src5, (96, 96), noise=True)
    f5 = d5 / "distai_avif_fixture.avif"
    _avif_overbudget(src5, f5)
    src5.unlink()  # scan only the avif
    r5 = h.run_gate(str(f5))
    m5 = h.finding_for(r5.stdout, f5)
    h.ok(r5.returncode == 1, "over-budget AVIF fails the gate",
         f"rc={r5.returncode} out={r5.stdout!r} err={r5.stderr!r}")
    h.ok(m5 is not None and (int(m5.group("w")), int(m5.group("h"))) == (96, 96),
         "gate reads AVIF dimensions via the ispe-box parse",
         r5.stdout)
    if m5 is not None:
        aw, ah = int(m5.group("w")), int(m5.group("h"))
        h.ok(int(m5.group("ideal")) == oracle_ideal(aw, ah),
             "AVIF ideal reproduces Lighthouse byte-for-byte")

    # -- Case 6: HALF-UP rounding + the UPPER threshold edge, pinned with one padded
    #    fixture. 399x401 = 159999 px puts TARGET*px on an exact half-integer
    #    (26666.5), where Chromium's Math.round (floor(x+0.5) = 26667) and Python's
    #    ties-to-even round() (26666) DIVERGE -- so a gate using the wrong rounding is
    #    caught by the ideal assertion. Padded to ideal+6000 bytes: the saving (6000)
    #    sits ABOVE 4096 but BELOW 8192, so a gate with an inflated threshold would not
    #    flag it -- caught by requiring OVER-BUDGET here. --
    d6 = work / "c6"
    d6.mkdir()
    f6 = d6 / "distai_halfint_fixture.png"
    ideal6 = oracle_ideal(399, 401)  # 26667 (half-up); a ties-to-even gate yields 26666
    _png_padded(f6, (399, 401), ideal6 + 6000)
    r6 = h.run_gate(str(d6))
    m6 = h.finding_for(r6.stdout, f6)
    h.ok(m6 is not None and m6.group("verdict") == "OVER-BUDGET",
         "half-integer fixture (saving 6000, in (4096,8192)) is flagged "
         "(pins the 4096 threshold from above)", r6.stdout)
    if m6 is not None:
        h.ok(int(m6.group("ideal")) == ideal6,
             "gate rounds the ideal HALF-UP at a half-integer boundary "
             "(not ties-to-even)", f"gate {m6.group('ideal')} vs half-up {ideal6}")
        h.ok(BYTE_SAVINGS_THRESHOLD < int(m6.group("saving")) < 2 * BYTE_SAVINGS_THRESHOLD,
             "fixture saving lies in the (4096, 8192) window that pins the threshold",
             m6.group("saving"))

    # -- Case 7: the LOWER threshold edge. Padded to ideal+2000: over the per-pixel
    #    TARGET but UNDER the 4096 savings threshold, so it must NOT be flagged. A gate
    #    that dropped/lowered the threshold would flag it -- caught by requiring a pass. --
    d7 = work / "c7"
    d7.mkdir()
    f7 = d7 / "distai_underslack_fixture.png"
    _png_padded(f7, (400, 400), oracle_ideal(400, 400) + 2000)
    r7 = h.run_gate(str(d7))
    h.ok(r7.returncode == 0, "image over TARGET but under the 4096 saving threshold passes",
         f"rc={r7.returncode} out={r7.stdout!r} err={r7.stderr!r}")
    h.ok(h.finding_for(r7.stdout, f7) is None,
         "under-threshold image is NOT flagged (pins the 4096 threshold from below)")

    # -- Case 8: usage error on no arguments (exit 2). --
    r6 = h.run_gate()
    h.ok(r6.returncode == 2, "no arguments yields the usage exit code (2)",
         f"rc={r6.returncode}")

    # -- Case 9: a missing scan target fails closed (exit 1). --
    r7 = h.run_gate(str(work / "does-not-exist"))
    h.ok(r7.returncode == 1, "missing scan target fails closed",
         f"rc={r7.returncode} out={r7.stdout!r} err={r7.stderr!r}")

    # Cleanup best-effort.
    try:
        from shutil import rmtree
        rmtree(work, ignore_errors=True)
    except OSError:
        pass

    print(f"\nmw-static-image-delivery-tests: {h.passed} pass, {h.failed} fail")
    return 1 if h.failed else 0


if __name__ == "__main__":
    sys.exit(main())
