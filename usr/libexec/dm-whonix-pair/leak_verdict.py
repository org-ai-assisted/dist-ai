#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Importable module (dh installs usr/libexec +x, so it carries a shebang and is harmless to run:
## it only defines functions). Imported by leak-exit-classify and battery-story-cards siblings.

"""Single source of the leak-battery verdict: classify anon-leak-test's JSON verdict.

anon-leak-test (--json) emits ONE top-level object (json.dumps indent=2 sort_keys=True):
  {"exit_code": int, "leak_detected": bool, "results": [...]}
The verdict is that object's TOP-LEVEL integer "exit_code": 0 clear / 1 leak / else
inconclusive.

Read the top-level key via a REAL JSON parse, NEVER a line match. A sed keyed on an
"exit_code" line at any indent + tail -1 picks the LAST such line -- and under sort_keys
the top-level "exit_code" sorts FIRST while "results" sorts LAST, so a NESTED exit_code
in a probe's detail (one 'returncode'->'exit_code' rename away) is the last line and wins:
a real leak (top-level 1) with a detail "exit_code": 0 is read as CLEAR. probe_verdict is
the AUTHORITATIVE leak-fail gate, so that is a silently-dropped leak, not a cosmetic bug.
A top-level dict.get("exit_code") returns the top-level key only; a nested one is invisible.

Shared by dm-whonix-pair's probe_verdict (via the leak-exit-classify CLI) and the
battery-story-cards story helper (imported), so the published story can NEVER disagree
with the classified run. Fail-closed on ambiguity: zero or more than one top-level
integer-exit_code object, a truncated/garbled capture, or a boolean/float/string/absent
exit_code all classify INCONCLUSIVE -- never a false clear.

Scope: the input is OUR OWN anon-leak-test's honest output, captured over guestcontrol;
the hazards are accidental corruption (a transport cut, a nested-exit_code rename), which
fail closed. It is NOT an adversarial-JSON parser -- a guest compromised enough to forge
the capture already controls the verdict outright, so no parser can defend against that.
"""

import json

CLEAR = "clear"
LEAK = "leak"
INCONCLUSIVE = "inconclusive"


def classify_exit_code(code):
    """Map a top-level integer exit_code to the verdict: 0 clear / 1 leak / else inconclusive."""
    if code == 0:
        return CLEAR
    if code == 1:
        return LEAK
    return INCONCLUSIVE


## The verdict is a few KB; a far larger capture is garbage or a flood -> fail closed, O(1).
_MAX_CAPTURE = 1 << 20  # 1 MiB


def _reject_duplicate_keys(pairs):
    """json object_pairs_hook: a JSON object from json.dumps never repeats a key, so a duplicate
    -- including one forged by \\uXXXX-escaping a key to collide (exit_\\u0063ode decodes to
    exit_code) -- is a crafted or garbled object. Raise (reject the whole object) rather than
    silently keep the last value, which could flip a top-level exit_code 1 to a trailing 0."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key: %r" % key)
        result[key] = value
    return result


def parse_verdict(text):
    """Return (objects, incomplete): every COLUMN-0 top-level JSON object carrying a STRICT integer
    'exit_code', and whether any column-0 opener FAILED to parse (truncated, garbled, or a forged
    duplicate key) -- the caller fails closed on either an unexpected count or incomplete=True.

    anon-leak-test emits exactly one object via json.dumps(indent=2, sort_keys=True), whose
    top-level '{' sits at column 0 while every nested brace is indented; a transport warning is
    other text. So a top-level object starts ONLY at a column-0 '{', and the real json parser
    (raw_decode) consumes each whole object in one call -- it never descends to a nested
    'exit_code', and a stray quote or brace inside a value cannot desync the scan (the bug class
    a hand-rolled tokenizer invites). A boolean exit_code is excluded (type(True) is int is False,
    though isinstance(True, int) is True), so a boolean decoy cannot pose as the verdict."""
    if len(text) > _MAX_CAPTURE:
        return [], True
    decoder = json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys)
    found = []
    incomplete = False
    pos = 0
    length = len(text)
    while pos < length:
        brace = text.find("{", pos)
        if brace == -1:
            break
        if brace != text.rfind("\n", 0, brace) + 1:  # not at column 0 -> not a top-level opener
            pos = brace + 1
            continue
        try:
            obj, end = decoder.raw_decode(text, brace)
        except ValueError:
            ## a column-0 opener that will not parse: truncated tail, garbled, or a dup key ->
            ## fail closed. Resume at the next line so a nested indented brace is never an anchor.
            incomplete = True
            newline = text.find("\n", brace)
            pos = length if newline == -1 else newline + 1
            continue
        if isinstance(obj, dict) and type(obj.get("exit_code")) is int:  # exact int: reject bool
            found.append(obj)
        pos = max(end, brace + 1)
    return found, incomplete


def classify(text):
    """The run's authoritative verdict: clear / leak / inconclusive. EXACTLY one clean top-level
    integer-exit_code object yields a definite verdict; zero / more than one (an ambiguous or
    decoyed capture) or ANY failed column-0 opener (a truncated or garbled capture) is
    INCONCLUSIVE -- fail-closed, never a false clear from guessing which object is real."""
    objects, incomplete = parse_verdict(text)
    if incomplete or len(objects) != 1:
        return INCONCLUSIVE
    return classify_exit_code(objects[0]["exit_code"])
