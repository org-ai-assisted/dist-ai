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

import msgcollector_testlib as T

try:
    FUNC = T.extract_bash_function(T.msgcollector_script(), "cli_links_to_footnotes")
except (LookupError, SystemExit):
    pytest.skip("cli_links_to_footnotes not available", allow_module_level=True)

WELL_FORMED_ANCHOR = re.compile(r'<a href="?[^">]*"?>[^<]*</a>')


def _run(message: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", FUNC + '\ncli_links_to_footnotes "$1"', "bash", message],
        capture_output=True, text=True, timeout=5)


## ---------------------------------------------------------------------------
## Concrete examples (no hypothesis needed): an anchor whose text is already
## the URL must NOT become a footnote, because the footnote would only print
## that same URL a second time. It is emitted as the bare URL inline instead.
## ---------------------------------------------------------------------------

def test_url_as_text_anchor_is_inlined_not_footnoted() -> None:
    url = "https://www.example.com/wiki/Donate"
    out = _run(f"See: <a href={url}>{url}</a>").stdout
    assert out == f"See: {url}", out
    assert "Links:" not in out, "a redundant footnote section was emitted"
    assert out.count(url) == 1, "the URL was printed more than once"


def test_manual_footnote_list_stays_clean() -> None:
    ## The "[N] <a href=url>url</a>" idiom (a hand-numbered link list) must not
    ## gain a second, auto-numbered footnote on top of the manual one.
    a = "https://www.example.com/wiki/TimeSync"
    b = "https://www.example.com/wiki/KVM"
    out = _run(f"design [1].\n[1] <a href={a}>{a}</a>\n[2] <a href={b}>{b}</a>").stdout
    assert out == f"design [1].\n[1] {a}\n[2] {b}", out
    assert "Links:" not in out


def test_labelled_anchor_still_becomes_a_footnote() -> None:
    ## Regression guard: a human-labelled link keeps the footnote treatment.
    url = "https://www.example.com/wiki/Systemcheck#Build_Version"
    out = _run(f"Kicksecure <a href={url}>build version</a>: 1.0").stdout
    assert out == f"Kicksecure build version[1]: 1.0\n\nLinks:\n[1] {url}\n", out


def test_mixed_labelled_and_url_text_anchors() -> None:
    a = "https://example.com/a"
    b = "https://example.com/b"
    out = _run(f"See <a href={a}>Login</a> and <a href={b}>{b}</a> now").stdout
    ## Only the labelled anchor consumes a footnote number; the url==text one
    ## is inlined verbatim.
    assert out == f"See Login[1] and {b} now\n\nLinks:\n[1] {a}\n", out


## ---------------------------------------------------------------------------
## Property-based invariants (needs python3-hypothesis). Unlike the concrete
## examples above -- which must always run -- this layer is skipped cleanly
## when hypothesis is absent, so a plain 'pytest' still exercises the fix.
## ---------------------------------------------------------------------------

try:
    from hypothesis import given, settings, strategies as st
    _HAVE_HYPOTHESIS = True
except ImportError:  # pragma: no cover
    _HAVE_HYPOTHESIS = False

if _HAVE_HYPOTHESIS:
    ## Fragments that make the anchor rewriter interesting; hypothesis stitches
    ## these together with arbitrary text.
    _FRAGMENTS = [
        '<a href="https://example.com/a">link</a>',
        '<a href=https://example.com/b>unquoted</a>',
        '<a href="https://example.com/c">https://example.com/c</a>',  # text == url
        '<a href="">empty</a>',
        '<a href="q">',                 # unclosed
        '</a>',                         # stray close
        '<a href="a"><a href="b">nested</a></a>',
        '<a href="<a href=">weird</a>',
        '<font color="green">OK.</font>', '</font>',
        '<br/>', '<p>', '</p>', 'Links:', '[1]', '&amp;', '\t', '\x1b[31m',
    ]

    ## A real msgcollector message is passed as an argv string, so exclude what
    ## cannot be: NUL (codepoint 0) and lone surrogates (category Cs, not UTF-8
    ## encodable). Generating those would only error in subprocess, not
    ## exercise the rewriter.
    _ARGV_TEXT = st.text(
        alphabet=st.characters(min_codepoint=1, exclude_categories=("Cs",)),
        max_size=16)
    _MESSAGES = st.lists(
        st.one_of(st.sampled_from(_FRAGMENTS), _ARGV_TEXT),
        max_size=10,
    ).map("".join)

    @settings(max_examples=400, deadline=None)
    @given(_MESSAGES)
    def test_rewrite_invariants(message: str) -> None:
        proc = _run(message)
        assert proc.returncode == 0, f"non-zero exit {proc.returncode}"
        assert WELL_FORMED_ANCHOR.search(proc.stdout) is None, "a well-formed anchor survived"
        assert _run(proc.stdout).stdout == proc.stdout, "not idempotent"
