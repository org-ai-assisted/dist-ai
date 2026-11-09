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


def _reject_duplicate_keys(pairs):
    """json object_pairs_hook: a JSON object from json.dumps never repeats a key, so a duplicate
    -- including one forged by \\uXXXX-escaping a key to collide (exit_\\u0063ode decodes to
    exit_code) -- is a crafted or garbled object. Reject it (ValueError) rather than silently
    keep the last value, which could flip a top-level exit_code 1 to a trailing 0."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key: %r" % key)
        result[key] = value
    return result


def _top_level_object_spans(text):
    """(start, end) of every CLOSED top-level {...} in text, string-aware so a brace inside a
    JSON string value is ignored. A truncated object that never closes yields NO span: the scan
    never descends into an unclosed outer object, so it cannot promote a nested detail fragment
    (e.g. a probe detail's own {"exit_code": 0}) to the verdict -- fail-closed on a transport cut."""
    spans = []
    depth = 0
    start = None
    in_str = False
    escape = False
    for i, ch in enumerate(text):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0:
                spans.append((start, i + 1))
    return spans


def verdict_objects(text):
    """Every TOP-LEVEL JSON object carrying a STRICT integer 'exit_code', in order. A JSON boolean
    is excluded (type(True) is int is False, though isinstance(True, int) is True), so a boolean
    decoy cannot pose as the verdict; a nested exit_code lives in a sub-dict and is invisible to
    the top-level dict.get. Only CLOSED top-level objects are considered (a truncated tail is
    dropped), and a duplicate-key object is rejected -- so neither a transport cut nor a forged
    duplicate can flip the verdict. Transport may wrap the real output in noise and emit earlier
    irrelevant objects (e.g. a '{"results": []}' warning, which carries no exit_code); the real
    anon-leak-test output is exactly one qualifying object."""
    found = []
    for start, end in _top_level_object_spans(text):
        try:
            obj = json.loads(text[start:end], object_pairs_hook=_reject_duplicate_keys)
        except ValueError:
            continue
        if isinstance(obj, dict) and type(obj.get("exit_code")) is int:  # exact int: reject bool
            found.append(obj)
    return found


def classify(text):
    """The run's authoritative verdict: clear / leak / inconclusive. EXACTLY one top-level
    integer-exit_code object yields a definite verdict; zero (nothing ran to completion) or more
    than one (an ambiguous or decoyed capture) is INCONCLUSIVE -- fail-closed, never a false
    clear from guessing which object is real."""
    objects = verdict_objects(text)
    if len(objects) != 1:
        return INCONCLUSIVE
    return classify_exit_code(objects[0]["exit_code"])
