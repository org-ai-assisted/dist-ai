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
    FUNC = T.extract_bash_function(T.msgcollector_script(), 'cli_links_to_footnotes')
except (LookupError, SystemExit):
    pytest.skip('cli_links_to_footnotes not available', allow_module_level=True)

WELL_FORMED_ANCHOR = re.compile(r'<a href="?[^">]*"?>[^<]*</a>')

## cli_translate_gui_markup wraps cli_links_to_footnotes plus the color-tag and
## <br> translation; absent on an older msgcollector -> that lane is skipped.
try:
    TRANSLATE_FUNC: str | None = T.extract_bash_function(
        T.msgcollector_script(), 'cli_translate_gui_markup')
except (LookupError, SystemExit):
    TRANSLATE_FUNC = None
## The markup cli_translate_gui_markup OWNS (color disabled): the four handled
## <font color> openers, </font>, and every <br> spelling.
TRANSLATED_FONT = re.compile(r'<font color="(?:green|orange|yellow|red)">')
TRANSLATED_BR = re.compile(r'<br ?/?>')


def _run(message: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['bash', '-c', FUNC + '\ncli_links_to_footnotes "$1"', 'bash', message],
        capture_output=True, text=True, timeout=5)


def _run_translate(message: str) -> subprocess.CompletedProcess:
    ## Color disabled: the handled font tags are removed and <br> -> newline.
    script = (FUNC + '\n' + str(TRANSLATE_FUNC)
              + '\ngreen="" yellow="" red="" reset=""\n'
              + 'cli_translate_gui_markup "$1"')
    return subprocess.run(['bash', '-c', script, 'bash', message],
                          capture_output=True, text=True, timeout=5)


## ---------------------------------------------------------------------------
## Concrete examples (no hypothesis needed): an anchor whose text is already
## the URL must NOT become a footnote, because the footnote would only print
## that same URL a second time. It is emitted as the bare URL inline instead.
## ---------------------------------------------------------------------------

def test_url_as_text_anchor_is_inlined_not_footnoted() -> None:
    url = 'https://www.example.com/wiki/Donate'
    out = _run(f"See: <a href={url}>{url}</a>").stdout
    assert out == f"See: {url}", out
    assert 'Links:' not in out, 'a redundant footnote section was emitted'
    assert out.count(url) == 1, 'the URL was printed more than once'


def test_manual_footnote_list_stays_clean() -> None:
    ## The "[N] <a href=url>url</a>" idiom (a hand-numbered link list) must not
    ## gain a second, auto-numbered footnote on top of the manual one.
    a = 'https://www.example.com/wiki/TimeSync'
    b = 'https://www.example.com/wiki/KVM'
    out = _run(f"design [1].\n[1] <a href={a}>{a}</a>\n[2] <a href={b}>{b}</a>").stdout
    assert out == f"design [1].\n[1] {a}\n[2] {b}", out
    assert 'Links:' not in out


def test_labelled_anchor_still_becomes_a_footnote() -> None:
    ## Regression guard: a human-labelled link keeps the footnote treatment.
    url = 'https://www.example.com/wiki/Systemcheck#Build_Version'
    out = _run(f"Kicksecure <a href={url}>build version</a>: 1.0").stdout
    assert out == f"Kicksecure build version[1]: 1.0\n\nLinks:\n[1] {url}\n", out


def test_mixed_labelled_and_url_text_anchors() -> None:
    a = 'https://example.com/a'
    b = 'https://example.com/b'
    out = _run(f"See <a href={a}>Login</a> and <a href={b}>{b}</a> now").stdout
    ## Only the labelled anchor consumes a footnote number; the url==text one
    ## is inlined verbatim.
    assert out == f"See Login[1] and {b} now\n\nLinks:\n[1] {a}\n", out


## ---------------------------------------------------------------------------
## Concrete cli_translate_gui_markup examples: verify the SUBSTITUTIONS and that
## content survives. The property lane only checks that owned tags are gone,
## which a transform that DELETED <br> or dropped text would also satisfy.
## ---------------------------------------------------------------------------

@pytest.mark.skipif(TRANSLATE_FUNC is None,
                    reason='cli_translate_gui_markup not available')
def test_translate_br_becomes_newline_not_deleted() -> None:
    assert _run_translate('a<br>b').stdout == 'a\nb'
    assert _run_translate('a<br/>b<br />c').stdout == 'a\nb\nc'


@pytest.mark.skipif(TRANSLATE_FUNC is None,
                    reason='cli_translate_gui_markup not available')
def test_translate_line_leading_br_collapses_source_newline() -> None:
    ## Regression: callers write multi-line HTML with a literal source newline
    ## AND a line-leading <br> per line (the newline is insignificant HTML
    ## whitespace; the <br> is the break). One logical break must render as ONE
    ## newline, not a blank line. Mirrors systemcheck's "Time Synchronization
    ## Result" message shape.
    msg = ('<p>Result: OK.\n'
           '<br/>status: <code>success</code>\n'
           '<br/>sdwdate reports: <code>done</code></p>')
    ## <p>/<code> are removed by strip-markup downstream; here we only assert the
    ## line-break translation leaves single newlines between the fields.
    out = _run_translate(msg).stdout
    assert '\n\n' not in out, f'blank line from doubled newline: {out!r}'
    assert out.count('\n') == 2, f'expected 2 line breaks, got: {out!r}'


@pytest.mark.skipif(TRANSLATE_FUNC is None,
                    reason='cli_translate_gui_markup not available')
def test_translate_intentional_double_br_keeps_blank_line() -> None:
    ## An explicit blank line (<br><br> with no whitespace between) must survive
    ## the whitespace-absorbing collapse as two newlines.
    assert _run_translate('a<br/><br/>b').stdout == 'a\n\nb'


@pytest.mark.skipif(TRANSLATE_FUNC is None,
                    reason='cli_translate_gui_markup not available')
def test_translate_preserves_plain_text() -> None:
    assert _run_translate('plain words kept').stdout == 'plain words kept'
    ## A CLI-native message (literal newlines, no <br>) must be left untouched
    ## by the collapse -- only whitespace adjacent to a <br> is absorbed.
    assert _run_translate('line1\nline2\nline3').stdout == 'line1\nline2\nline3'


@pytest.mark.skipif(TRANSLATE_FUNC is None,
                    reason='cli_translate_gui_markup not available')
def test_translate_font_tag_removed_text_kept() -> None:
    ## Color disabled: the handled font tag is removed, its text stays.
    assert _run_translate('<font color="green">colored</font>').stdout == 'colored'


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
        alphabet=st.characters(min_codepoint=1, exclude_categories=('Cs',)),
        max_size=16)
    _MESSAGES = st.lists(
        st.one_of(st.sampled_from(_FRAGMENTS), _ARGV_TEXT),
        max_size=10,
    ).map(''.join)

    @settings(max_examples=400, deadline=None)
    @given(_MESSAGES)
    def test_rewrite_invariants(message: str) -> None:
        proc = _run(message)
        assert proc.returncode == 0, f"non-zero exit {proc.returncode}"
        assert WELL_FORMED_ANCHOR.search(proc.stdout) is None, 'a well-formed anchor survived'
        assert _run(proc.stdout).stdout == proc.stdout, 'not idempotent'

    @settings(max_examples=400, deadline=None)
    @given(_MESSAGES)
    def test_translate_invariants(message: str) -> None:
        ## Full markup translation: the tags cli_translate_gui_markup owns must
        ## be gone. Anchors are NOT asserted -- cli_links handles most (above),
        ## and the <br>-to-newline pass can make a <br>-containing anchor text
        ## well-formed, which strip-markup removes downstream (not a leak).
        if TRANSLATE_FUNC is None:
            pytest.skip('cli_translate_gui_markup not available')
        proc = _run_translate(message)
        assert proc.returncode == 0, f"non-zero exit {proc.returncode}"
        assert TRANSLATED_FONT.search(proc.stdout) is None, 'a handled <font color> survived'
        assert '</font>' not in proc.stdout, 'a </font> survived'
        assert TRANSLATED_BR.search(proc.stdout) is None, 'a <br> survived'
        ## Content preservation: with no markup the transform is the identity;
        ## guards against a version that empties or drops text (which the
        ## tag-absence checks alone would not catch). subprocess text mode
        ## normalizes CR/CRLF to \n on read, so compare against that view.
        if '<' not in message:
            ## cli_translate_gui_markup runs the text through bash command
            ## substitutions, which strip TRAILING newlines, so compare content
            ## up to trailing-newline stripping (and subprocess CR/CRLF
            ## normalization). A dropped/emptied non-newline character still fails.
            expected = message.replace('\r\n', '\n').replace('\r', '\n').rstrip('\n')
            assert proc.stdout.rstrip('\n') == expected, 'plain text content was not preserved'
