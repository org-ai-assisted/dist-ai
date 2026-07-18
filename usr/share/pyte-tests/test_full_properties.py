"""Property-based tests for pyte using Hypothesis.

These assert invariants that must hold for *any* input, plus round-trip and
idempotency properties. Sequences that would hit the four known crash defects
(see ``BUGS/``) are excluded from the strict no-crash properties so this file
stays green on upstream master; the fuzz harness (``fuzz_pyte.py``) tracks
those separately via an allowlist.
"""
import re

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

import pyte  # noqa: E402
from pyte import modes as mo  # noqa: E402


# Printable + a few control characters; deliberately excludes ESC/CSI so these
# properties exercise the ``draw`` path and simple controls without building
# escape sequences (those are covered by the CSI strategy below).
text_chars = st.text(
    alphabet=st.characters(
        min_codepoint=0x20, max_codepoint=0x2FFF,
        blacklist_categories=("Cs",)),
    max_size=40)

control_chars = st.sampled_from(["\n", "\r", "\t", "\x08", "\x07", " "])
draw_stream = st.lists(st.one_of(text_chars, control_chars), max_size=20) \
    .map("".join)

sizes = st.integers(min_value=1, max_value=40)


def check_invariants(screen):
    assert len(screen.display) == screen.lines
    assert 0 <= screen.cursor.x <= screen.columns
    assert 0 <= screen.cursor.y < screen.lines
    # Every buffered cell holds a Char with a string ``data`` field.
    for line in screen.buffer.values():
        for cell in line.values():
            assert isinstance(cell.data, str)


@given(cols=sizes, rows=sizes, data=draw_stream)
@settings(max_examples=300, deadline=None)
def test_draw_keeps_invariants(cols, rows, data):
    screen = pyte.Screen(cols, rows)
    pyte.Stream(screen).feed(data)
    check_invariants(screen)


@given(cols=sizes, rows=sizes, data=st.binary(max_size=60))
@settings(max_examples=300, deadline=None)
def test_bytestream_never_crashes_on_arbitrary_bytes(cols, rows, data):
    # ByteStream feeds raw bytes; the parser only builds escape sequences from
    # a genuine ESC, which random bytes rarely form -- and never the crash
    # sequences from BUGS/. Invariants must hold and feed() must not raise.
    screen = pyte.Screen(cols, rows)
    pyte.ByteStream(screen).feed(data)
    check_invariants(screen)


@given(cols=sizes, rows=sizes, ncols=sizes, nrows=sizes, data=draw_stream)
@settings(max_examples=200, deadline=None)
def test_resize_keeps_invariants(cols, rows, ncols, nrows, data):
    screen = pyte.Screen(cols, rows)
    pyte.Stream(screen).feed(data)
    screen.resize(nrows, ncols)
    assert screen.lines == nrows and screen.columns == ncols
    assert len(screen.display) == screen.lines
    assert all(isinstance(row, str) for row in screen.display)
    # NB: the cursor is intentionally NOT asserted in-bounds here -- shrinking
    # the screen clamps neither axis, so cursor.x/cursor.y can be left outside
    # the new bounds (BUG-E, see BUGS/ and
    # test_full_regressions.py::test_resize_shrink_keeps_cursor_in_bounds).


@given(data=draw_stream)
@settings(max_examples=200, deadline=None)
def test_reset_returns_to_blank(data):
    screen = pyte.Screen(10, 5)
    pyte.Stream(screen).feed(data)
    screen.reset()
    assert screen.display == [" " * 10] * 5
    assert (screen.cursor.x, screen.cursor.y) == (0, 0)
    assert screen.margins is None


# SGR parameters restricted to codes pyte recognises; property: any recognised
# SGR run leaves the cursor attrs a valid Char and never raises.
sgr_codes = st.lists(
    st.integers(min_value=0, max_value=107), min_size=0, max_size=8)


@given(codes=sgr_codes)
@settings(max_examples=300, deadline=None)
def test_sgr_never_crashes(codes):
    screen = pyte.Screen(5, 2)
    screen.select_graphic_rendition(*codes)
    a = screen.cursor.attrs
    assert isinstance(a.fg, str) and isinstance(a.bg, str)
    assert isinstance(a.bold, bool)


# Cursor-movement commands must always keep the cursor in-bounds regardless of
# argument magnitude.
move_ops = st.sampled_from([
    "cursor_up", "cursor_down", "cursor_forward", "cursor_back",
    "cursor_up1", "cursor_down1", "cursor_to_column", "cursor_to_line"])


@given(ops=st.lists(st.tuples(move_ops, st.integers(0, 500)), max_size=30))
@settings(max_examples=300, deadline=None)
def test_cursor_moves_stay_in_bounds(ops):
    screen = pyte.Screen(12, 8)
    for name, arg in ops:
        getattr(screen, name)(arg)
        assert 0 <= screen.cursor.x <= screen.columns
        assert 0 <= screen.cursor.y < screen.lines


@given(data=draw_stream, history=st.integers(5, 50))
@settings(max_examples=150, deadline=None)
def test_historyscreen_invariants(data, history):
    screen = pyte.HistoryScreen(8, 4, history=history)
    stream = pyte.Stream(screen)
    stream.feed(data)
    for _ in range(3):
        screen.prev_page()
    for _ in range(6):
        screen.next_page()
    check_invariants(screen)
    assert len(screen.history.top) <= history
    assert len(screen.history.bottom) <= history


# Feeding text one character at a time must yield the same screen as feeding it
# all at once. This holds for simple single-width, non-combining text. It does
# NOT hold for grapheme clusters (combining marks, ZWJ emoji) that straddle a
# feed() boundary, because pyte does not buffer a partial cluster across feed()
# calls -- a documented design limitation, not tested here.
simple_text = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    max_size=40)


@given(data=simple_text)
@settings(max_examples=200, deadline=None)
def test_feed_is_chunk_invariant_for_text(data):
    whole = pyte.Screen(15, 4)
    pyte.Stream(whole).feed(data)

    piecewise = pyte.Screen(15, 4)
    stream = pyte.Stream(piecewise)
    for ch in data:
        stream.feed(ch)

    assert whole.display == piecewise.display
    assert (whole.cursor.x, whole.cursor.y) == \
           (piecewise.cursor.x, piecewise.cursor.y)
