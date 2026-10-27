#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

"""Regression gate for the dm-calamares-install content GOLDENS.

Each usr/share/dm-calamares-install-golden/<stage>.tokens must, against the OCR of the healthy
seed run (captured in golden-fixtures.ocr):
  - be WELL-FORMED: assert at least one non-empty token (a golden that asserts nothing is the
    exit-2 "broken golden" the lane fails loud on -- never a silent pass);
  - PASS its own stage's frame (every token present);
  - FAIL every OTHER stage's frame (at least one token absent), except a few legitimately-identical
    sibling stages (the two partition panels; the LUKS-prompt family) -- so a token can never be so
    generic that a WRONG frame would ride green in that stage's slot.
Plus a canary: `keyboard` stays UNVALIDATED (no golden), the documented graduated-coverage example.

Drives the REAL matching logic: image-text-assert.read_spec (the golden parser) + dm_test_results.
ocr.missing_tokens (the token matcher). Pure text, no tesseract -- the fixture is pre-captured OCR.

Exit: 0 all pass, 1 any fail.
"""

import importlib.machinery
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.realpath(__file__))
_LIB = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dm_test_results.ocr import missing_tokens  # noqa: E402


def _load_image_text_assert():
    """Import the real image-text-assert as a module so read_spec is the SAME golden parser the
    lane runs (no reimplementation drift). The in-tree sibling by default, the installed one
    otherwise; the file's bash-guard line is an inert string under Python import."""
    for cand in (
        os.environ.get("IMAGE_TEXT_ASSERT_BIN") or "",
        os.path.join(os.path.dirname(os.path.dirname(_HERE)), "bin", "image-text-assert"),
        "/usr/bin/image-text-assert",
    ):
        if cand and os.path.isfile(cand):
            loader = importlib.machinery.SourceFileLoader("image_text_assert", cand)
            spec = importlib.util.spec_from_loader("image_text_assert", loader)
            assert spec is not None
            mod = importlib.util.module_from_spec(spec)
            loader.exec_module(mod)
            return mod
    raise SystemExit("FATAL: image-text-assert not found")


def _golden_dir():
    for cand in (
        os.environ.get("CALAMARES_GOLDEN_DIR") or "",
        os.path.join(os.path.dirname(os.path.dirname(_HERE)), "share",
                     "dm-calamares-install-golden"),
        "/usr/share/dm-calamares-install-golden",
    ):
        if cand and os.path.isdir(cand):
            return cand
    raise SystemExit("FATAL: dm-calamares-install-golden dir not found")


def _load_fixture(path):
    stages = {}
    cur = None
    buf: list[str] = []
    for line in open(path, encoding="ascii"):
        if line.startswith("@@@STAGE:"):
            if cur is not None:
                stages[cur] = "".join(buf)
            cur = line[len("@@@STAGE:"):].strip()
            buf = []
        else:
            buf.append(line)
    if cur is not None:
        stages[cur] = "".join(buf)
    return stages


## Stages whose frame may legitimately satisfy another stage's golden (same on-screen content), so
## a cross-match between them is NOT a defect: the two partition panels show the same warning; the
## LUKS passphrase prompt is the same frame across its captures.
_SIBLINGS = {
    "partitions": {"partitions-luks-filled"},
    "partitions-luks-filled": {"partitions"},
    "luks-prompt": {"luks-passphrase-typed", "luks-unlocked", "sysmaint-luks-prompt"},
    "sysmaint-luks-prompt": {"luks-prompt", "luks-passphrase-typed", "luks-unlocked"},
}

_failures = 0


def check(label, cond):
    global _failures
    if cond:
        print("ok: %s" % label)
    else:
        print("FAIL: %s" % label, file=sys.stderr)
        _failures += 1


ita = _load_image_text_assert()
golden_dir = _golden_dir()
fixture = _load_fixture(os.path.join(_HERE, "golden-fixtures.ocr"))
check("fixture carries the seed-run frames", len(fixture) >= 20)

goldens = sorted(f for f in os.listdir(golden_dir) if f.endswith(".tokens"))
check("goldens present", len(goldens) >= 1)

for fname in goldens:
    stage = fname[:-len(".tokens")]
    tokens = ita.read_spec(os.path.join(golden_dir, fname))
    ## Well-formed: asserts at least one non-empty token (never a broken golden).
    check("%s golden asserts >=1 non-empty token" % stage,
          any(tok.strip() for tok in tokens))
    ## Every seeded golden must have a fixture frame to verify against (a new golden without one is
    ## a gap -- add its frame to golden-fixtures.ocr).
    if stage not in fixture:
        check("%s has a fixture frame" % stage, False)
        continue
    check("%s golden PASSES its own frame" % stage,
          missing_tokens(fixture[stage], tokens) == [])
    siblings = _SIBLINGS.get(stage, set())
    bad = [other for other, text in fixture.items()
           if other != stage and other not in siblings and not missing_tokens(text, tokens)]
    check("%s golden FAILS every non-sibling frame (cross-match: %s)" % (stage, bad), not bad)

## Canary: no keyboard golden ships. Its OCR is noisy, so the README keeps it as the
## graduated-coverage example; a golden appearing here means someone flipped it -- update the
## README and this canary together, deliberately.
check("keyboard stays UNVALIDATED (no golden)",
      not os.path.isfile(os.path.join(golden_dir, "keyboard.tokens")))

if _failures:
    print("\n%d golden-token assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall golden-token assertions passed")
