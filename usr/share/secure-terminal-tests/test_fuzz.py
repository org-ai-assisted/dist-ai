#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Property-based fuzz tests for secure-terminal's pure parsers of untrusted input
(secure_terminal.sanitize), using hypothesis. These are the functions that see
hostile bytes: the output renderer, the paste sanitizer/classifier, the title
sanitizer, the safe-colour SGR parser and the per-cell TUI sanitizer. For every
input they must not raise and must uphold their safety invariant (no unsafe
character escapes strip mode, a title is plain ASCII, a cell is one wide, ...).

hypothesis is a declared dependency (installed in CI); a missing one is a hard
FAILURE, not a skip. Exit 0 on full pass, 1 on any failure.
"""

import sys

try:
    from hypothesis import given, settings, strategies as st
    from secure_terminal import sanitize as S
except Exception as exc:  # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(fuzz): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

FAIL = 0
SAFE_OUTPUT = frozenset((0x08, 0x09, 0x0A, 0x0D)) | frozenset(range(0x20, 0x7F))
RUN = settings(max_examples=400, deadline=None)


@RUN
@given(st.text(), st.sampled_from(S.DISPLAY_MODES))
def prop_render_output(text, mode):
    out = S.render_output(text, mode)
    assert isinstance(out, str)
    if mode == 'strip':
        # strip mode must emit only printable ASCII + tab/newline + the two
        # honored cursor controls; nothing hostile can survive.
        assert all(ord(ch) in SAFE_OUTPUT for ch in out)


@RUN
@given(st.text())
def prop_sanitize_paste(text):
    out = S.sanitize_paste(text)
    assert all(ch in ('\t', '\r') or 0x20 <= ord(ch) <= 0x7E for ch in out)


@RUN
@given(st.text())
def prop_sanitize_paste_unicode(text):
    out = S.sanitize_paste_unicode(text)
    # keeps printable (incl. non-ASCII) + the two submit controls; never a
    # control, bidi, zero-width or other invisible that could inject or deceive.
    assert all(ch in ('\r', '\t') or ch.isprintable() for ch in out)


@RUN
@given(st.text())
def prop_sanitize_title(text):
    out = S.sanitize_title(text)
    assert len(out) <= 80
    assert all(0x20 <= ord(ch) <= 0x7E for ch in out)
    assert '\n' not in out and '\t' not in out


@RUN
@given(st.text())
def prop_paste_findings(text):
    result = S.paste_findings(text)
    assert isinstance(result, tuple) and len(result) == 2
    assert all(isinstance(flag, bool) for flag in result)


@RUN
@given(st.text())
def prop_classify_paste(text):
    result = S.classify_paste(text)
    assert isinstance(result, list)
    assert all(isinstance(label, str) and isinstance(count, int) and count > 0
               for label, count in result)


@RUN
@given(st.text(alphabet='0123456789;:', max_size=48))
def prop_parse_sgr(param):
    state = {'fg': None, 'bg': None, 'bold': False}
    S.parse_sgr(param, state)
    assert state['fg'] is None or 0 <= state['fg'] <= 15
    assert state['bg'] is None or 0 <= state['bg'] <= 15
    assert isinstance(state['bold'], bool)


@RUN
@given(st.text(min_size=0, max_size=4), st.sampled_from(S.DISPLAY_MODES))
def prop_tui_cell(ch, mode):
    # a pyte cell may hold a multi-codepoint grapheme, so feed strings of any
    # length; tui_cell must never raise (this is where cat /dev/random crashed).
    out = S.tui_cell(ch, mode)
    assert isinstance(out, str)
    # any control codepoint in the cell -> the whole cell is neutralized to '_'
    if any(ord(c) < 0x20 for c in ch):
        assert out == '_'


@RUN
@given(st.text(), st.sampled_from(S.DISPLAY_MODES))
def prop_feed_line_edits(text, mode):
    # the line-mode logical-cell editor: hostile output must never smuggle an
    # escape byte into a cell, the cursor must stay within the current line, and
    # in strip mode the rendered line must be all-safe. It must not raise.
    comp, cells, col, sgr = S.feed_line_edits([], 0, {}, text)
    assert 0 <= col <= len(cells)
    for ch, _key in cells:
        assert ch != '\x1b'                      # no escape survives into a cell
    if mode == 'strip':
        rendered = ''.join(S.render_output(c, 'strip') for c, _ in cells)
        assert all(ord(ch) in SAFE_OUTPUT for ch in rendered)
    # feeding the SAME chunk again from the resulting state must still not raise
    S.feed_line_edits(cells, col, sgr, text)


PROPS = [
    ('render_output', prop_render_output),
    ('feed_line_edits', prop_feed_line_edits),
    ('sanitize_paste', prop_sanitize_paste),
    ('sanitize_paste_unicode', prop_sanitize_paste_unicode),
    ('sanitize_title', prop_sanitize_title),
    ('paste_findings', prop_paste_findings),
    ('classify_paste', prop_classify_paste),
    ('parse_sgr', prop_parse_sgr),
    ('tui_cell', prop_tui_cell),
]

for name, prop in PROPS:
    try:
        prop()
    except Exception as exc:  # pylint: disable=broad-except
        FAIL += 1
        sys.stderr.write('FAIL: property %s: %s\n' % (name, exc))

sys.stdout.write('secure-terminal-tests(fuzz): %d propert%s checked, %d failed\n'
                 % (len(PROPS), 'y' if len(PROPS) == 1 else 'ies', FAIL))
sys.exit(0 if FAIL == 0 else 1)
