#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Randomized in-process fuzzer for msgcollector's CLI-rendering bash.

The --messagecli path rewrites an HTML message for the terminal, and part of it
runs over ATTACKER-INFLUENCEABLE content (systemcheck feeds it journal lines,
Tor control output, package names, ...). The riskiest piece is
cli_links_to_footnotes: a `while [[ =~ ]]` loop that rewrites <a href> anchors
and does an in-place string replacement each pass. A crafted message must never
make it hang (the replacement re-introducing a match), crash, or leave a
well-formed anchor un-rewritten (a URL that would then reach the flow text).

Properties checked, per fuzzed message:
  * TERMINATES within a timeout           -- a hang is the loop bug we fear most
  * exits 0 (no bash error / unbound var)
  * consumes every WELL-FORMED anchor      -- none survive in the output
  * footer is consistent                   -- one "[N] url" line per inline [N]
  * output is a rearrangement              -- injects no tag/char not in the input

Run: fuzz_cli_rendering.py [--iterations N] [--seed N]. On failure it prints the
seed and the offending message so the case replays deterministically.
"""

import argparse
import random
import re
import subprocess
import sys

import msgcollector_testlib as T

WELL_FORMED_ANCHOR = re.compile(r'<a href="?[^">]*"?>[^<]*</a>')

## Fragments that make the anchor rewriter interesting: valid/edge anchors,
## nesting, unclosed tags, odd quoting, control bytes, entities, other markup.
_FRAGMENTS = [
    '<a href="https://example.com/a">link</a>',
    '<a href=https://example.com/b>unquoted</a>',
    '<a href="">empty</a>',
    '<a href="x">',                 # unclosed
    '</a>',                         # stray close
    '<a href="a"><a href="b">nested</a></a>',
    '<a href="<a href=">weird</a>',
    '<a href="url">a</a><a href="url2">b</a>',
    '<a href="u">text with ] and [ and (parens)</a>',
    '<font color="green">OK.</font>',
    '<br/>', '<br>', '<p>', '</p>', '<code>x</code>', '<b>y</b>',
    '&amp;', '&lt;', '&gt;', '"', "'", '\\', '/', '[1]', 'Links:',
    '\t', '\n', '\x1b[31m', '\x07', 'plain words',
]


## Curated regressions -- inputs a fuzz run once found, kept so they are always
## retried regardless of the random seed. The nested/crafted-href cases used to
## hang cli_links_to_footnotes (an in-place replace that could re-form a match
## and loop forever).
_REGRESSIONS = [
    '<a href="a"><a href="b">nested</a></a>',
    '<a href="<a href=">weird</a>',
    '</p><a href="a"><a href="b">nested</a></a><a href="<a href=">weird</a>'
    + '<a href="url">a</a><a href="url2">b</a><a href="x">&gt;</a>',
    '<a href="a"><a href="b">nested</a></a>&lt;&gt;'
    + '<a href="x"><a href="a"><a href="b">nested</a></a>',
]


def gen_message(rng: random.Random) -> str:
    parts = [rng.choice(_FRAGMENTS) for _ in range(rng.randint(0, 8))]
    ## Occasionally splice a long run to probe pathological backtracking.
    if rng.random() < 0.1:
        parts.append('<a href="' + "a" * rng.randint(1, 400) + '">'
                     + "b" * rng.randint(1, 400) + "</a>")
    return "".join(parts)


def run(func_def: str, message: str, timeout: float = 5.0):
    """Run cli_links_to_footnotes on `message`. Returns (rc, stdout).
    Raises subprocess.TimeoutExpired on a hang (the bug we hunt)."""
    script = func_def + '\ncli_links_to_footnotes "$1"\n'
    proc = subprocess.run(
        ["bash", "-c", script, "bash", message],
        capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout


def check(func_def: str, message: str) -> None:
    """Raise AssertionError (or let TimeoutExpired propagate) on a violation.

    These invariants deliberately do NOT parse the "Links:" footer -- an input
    can contain that literal text, so splitting on it is unreliable. The regex's
    url group is [^">]*, so a rewritten URL can never contain '>' and thus never
    forms an anchor; the output is therefore anchor-free everywhere and a second
    pass is a no-op.
    """
    rc, out = run(func_def, message)
    assert rc == 0, f"non-zero exit {rc}"
    ## Every well-formed anchor is rewritten away (body consumed; footer URLs
    ## have no '>', so they cannot form one either).
    assert not WELL_FORMED_ANCHOR.search(out), "a well-formed anchor survived"
    ## Idempotent: the output has no anchors left, so re-running is the identity.
    rc2, out2 = run(func_def, out)
    assert rc2 == 0, f"non-zero exit {rc2} on second pass"
    assert out2 == out, "not idempotent"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    seed = args.seed if args.seed is not None else random.randrange(2**32)
    rng = random.Random(seed)
    print(f"fuzz_cli_rendering: seed={seed} iterations={args.iterations}",
          file=sys.stderr)

    script = T.msgcollector_script()
    try:
        func_def = T.extract_bash_function(script, "cli_links_to_footnotes")
    except LookupError as exc:
        print(f"SKIP: {exc}", file=sys.stderr)
        return 77

    ## Always retry the curated regressions first, then the random sweep.
    cases = [("regression", m) for m in _REGRESSIONS]
    cases += [("random", None)] * args.iterations
    for i, (kind, fixed) in enumerate(cases):
        message = fixed if fixed is not None else gen_message(rng)
        try:
            check(func_def, message)
        except subprocess.TimeoutExpired:
            print(f"FAIL (hang, {kind}): seed={seed} i={i} message={message!r}",
                  file=sys.stderr)
            return 1
        except AssertionError as exc:
            print(f"FAIL ({kind}): {exc}: seed={seed} i={i} message={message!r}",
                  file=sys.stderr)
            return 1
    print("ok", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
