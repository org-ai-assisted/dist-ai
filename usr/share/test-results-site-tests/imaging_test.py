#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## AI-Assisted

"""Unit + canary tests for screenshot normalization (imaging.py).

Canaries:
  - a change ONLY inside a masked rect normalizes to the SAME bytes as the unchanged
    frame (the mask blanks it) -- so a non-deterministic clock does not perturb a shot;
  - the very same change OUTSIDE the mask normalizes to DIFFERENT bytes (proves the
    mask, not normalization in general, did it);
  - an off-image / oversized rect is clamped, never raises;
  - top_right_rect lands in the top-right corner with a positive size.

Pillow absent -> exit 78 (env-unmet), surfaced distinctly, never folded into a pass.
Pure logic otherwise: tiny in-memory images, no root/network.

Exit: 0 all pass, 1 any fail, 78 env-unmet.
"""

import os
import shutil
import sys
import tempfile

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

try:
    from PIL import Image
    from dm_test_results import imaging
except ImportError as exc:
    print("test-results-site imaging_test: env-unmet (Pillow): %s" % exc, file=sys.stderr)
    sys.exit(78)

_failures = 0


def check(label, cond):
    global _failures
    if cond:
        print("ok: %s" % label)
    else:
        print("FAIL: %s" % label, file=sys.stderr)
        _failures += 1


## 20x20 canvas; the clock mask is the top-right 6x6.
SIZE = (20, 20)
MASK = [(14, 0, 6, 6)]


def write_png(path, painted=None):
    image = Image.new("RGB", SIZE, (255, 255, 255))
    if painted:
        (x, y, w, h), color = painted
        image.paste(Image.new("RGB", (w, h), color), (x, y))
    image.save(path, format="PNG")
    return path


def norm_bytes(path, rects):
    return imaging.normalize_image(path, rects).tobytes()


work = tempfile.mkdtemp(prefix="test-results-imaging.")

base = write_png(os.path.join(work, "base.png"))

## 1. A change ONLY inside the masked rect -> same normalized bytes as the base (masked away).
clock = write_png(os.path.join(work, "clock.png"), painted=((15, 1, 4, 4), (255, 0, 0)))
check("masked-clock-only change normalizes identically",
      norm_bytes(clock, MASK) == norm_bytes(base, MASK))
## ...and WITHOUT the mask that same change DIFFERS (proves the mask did it).
check("same change unmasked differs", norm_bytes(clock, None) != norm_bytes(base, None))

## 2. A real change OUTSIDE the mask -> differs even with the mask applied (never silently equal).
real = write_png(os.path.join(work, "real.png"), painted=((0, 0, 5, 5), (0, 0, 255)))
check("change outside mask differs under mask", norm_bytes(real, MASK) != norm_bytes(base, MASK))

## 3. An off-image / oversized rect is clamped, never raises.
try:
    imaging.normalize_image(base, [(100, 100, 999, 999), (-5, -5, 3, 3)])
    clamped_ok = True
except Exception:  # noqa: BLE001
    clamped_ok = False
check("off-image / oversized rect is clamped (no raise)", clamped_ok)

## 4. top_right_rect lands in the top-right corner with a positive size.
x, y, w, h = imaging.top_right_rect(SIZE)
check("top_right_rect y is 0 (top edge)", y == 0)
check("top_right_rect spans to the right edge", x + w == SIZE[0])
check("top_right_rect has positive size", w > 0 and h > 0)

shutil.rmtree(work, ignore_errors=True)

if _failures:
    print("\n%d imaging assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall imaging assertions passed")
