#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Hypothesis property-based tests for msgcollector's CLI link rewriter.

Layer 1 of the fuzzing convention: complements the randomized in-process fuzzer
(fuzz_cli_rendering.py) by generating arbitrary anchor-rich messages and
asserting the invariants that must hold for ALL inputs to cli_links_to_footnotes
-- the rewriter that turns <a href> anchors into "text[N]" plus a Links footer,
run over attacker-influenceable content:

  * it terminates (a timeout is a hang bug) and exits 0;
  * no well-formed anchor survives (the url group is [^">]*, so a rewritten URL
    cannot contain '>' and thus cannot form an anchor either);
  * it is idempotent (a second pass over the anchor-free output is a no-op).

Needs python3-hypothesis (Debian apt); skipped cleanly if it is absent.
"""

import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

pytest.importorskip("hypothesis")
# pylint: disable=wrong-import-position
from hypothesis import given, settings, strategies as st  # noqa: E402

import msgcollector_testlib as T  # noqa: E402

try:
    FUNC = T.extract_bash_function(T.msgcollector_script(), "cli_links_to_footnotes")
except (LookupError, SystemExit):
    pytest.skip("cli_links_to_footnotes not available", allow_module_level=True)

WELL_FORMED_ANCHOR = re.compile(r'<a href="?[^">]*"?>[^<]*</a>')

## Fragments that make the anchor rewriter interesting; hypothesis stitches
## these together with arbitrary text.
_FRAGMENTS = [
    '<a href="https://example.com/a">link</a>',
    '<a href=https://example.com/b>unquoted</a>',
    '<a href="">empty</a>',
    '<a href="q">',                 # unclosed
    '</a>',                         # stray close
    '<a href="a"><a href="b">nested</a></a>',
    '<a href="<a href=">weird</a>',
    '<font color="green">OK.</font>', '</font>',
    '<br/>', '<p>', '</p>', 'Links:', '[1]', '&amp;', '\t', '\x1b[31m',
]

## Exclude codepoint 0 (NUL): a real msgcollector message is passed as an argv
## string, which cannot contain NUL, so generating it would only ValueError in
## subprocess, not exercise the rewriter.
_MESSAGES = st.lists(
    st.one_of(
        st.sampled_from(_FRAGMENTS),
        st.text(alphabet=st.characters(min_codepoint=1), max_size=16),
    ),
    max_size=10,
).map("".join)


def _run(message: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", FUNC + '\ncli_links_to_footnotes "$1"', "bash", message],
        capture_output=True, text=True, timeout=5)


@settings(max_examples=400, deadline=None)
@given(_MESSAGES)
def test_rewrite_invariants(message: str) -> None:
    proc = _run(message)
    assert proc.returncode == 0, f"non-zero exit {proc.returncode}"
    assert WELL_FORMED_ANCHOR.search(proc.stdout) is None, "a well-formed anchor survived"
    assert _run(proc.stdout).stdout == proc.stdout, "not idempotent"
