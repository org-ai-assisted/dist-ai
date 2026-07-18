"""Comprehensive public-API coverage for pyte.

Every public class / method / function of :mod:`pyte` is exercised here with
explicit behavioural assertions. These tests are expected to pass on pyte
upstream master; regressions for known defects live in
``test_full_regressions.py`` and the property/fuzz surface in
``test_full_properties.py`` / ``fuzz_pyte.py``.

Style intentionally follows the upstream test-suite idiom (plain ``pytest``
functions, ``import pyte``, small helpers) rather than the Kicksecure house
style, since this code targets the upstream fork.
"""
import io

import pytest

import pyte
from pyte import charsets as cs, control as ctrl, graphics as g, modes as mo
from pyte.screens import Char, Cursor, Margins, \
    StaticDefaultDict, grapheme_clusters


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def chars(screen, y):
    """Rendered text of line *y* as a plain string."""
    return "".join(screen.buffer[y][x].data for x in range(screen.columns))


# --------------------------------------------------------------------------
# Char / Cursor / small containers
# --------------------------------------------------------------------------

def test_char_defaults():
    c = Char("x")
    assert c.data == "x"
    assert c.fg == "default"
    assert c.bg == "default"
    assert not any([c.bold, c.italics, c.underscore, c.strikethrough,
                    c.reverse, c.blink])


def test_char_is_namedtuple_replace():
    c = Char("a")._replace(bold=True, fg="red")
    assert c.data == "a" and c.bold and c.fg == "red"


def test_cursor_slots_and_defaults():
    cur = Cursor(3, 4)
    assert (cur.x, cur.y) == (3, 4)
    assert cur.hidden is False
    assert isinstance(cur.attrs, Char)
    with pytest.raises(AttributeError):
        cur.nonexistent_slot = 1  # __slots__ forbids new attributes


def test_margins_namedtuple():
    m = Margins(1, 9)
    assert (m.top, m.bottom) == (1, 9)


def test_static_default_dict():
    d = StaticDefaultDict(42)
    assert d["missing"] == 42
    assert "missing" not in d           # query must not insert
    d["real"] = 7
    assert d["real"] == 7


# --------------------------------------------------------------------------
# grapheme_clusters
# --------------------------------------------------------------------------

def test_grapheme_clusters_plain():
    assert list(grapheme_clusters("abc")) == ["a", "b", "c"]


def test_grapheme_clusters_combining():
    # 'e' + combining acute accent -> single cluster.
    assert list(grapheme_clusters("e\u0301x")) == ["e\u0301", "x"]


def test_grapheme_clusters_zwj_emoji():
    text = "\U0001f469\u200d\U0001f469"  # woman ZWJ woman
    assert list(grapheme_clusters(text)) == [text]


def test_grapheme_clusters_skin_tone():
    text = "\U0001f44d\U0001f3fb"  # thumbs up + skin tone modifier
    assert list(grapheme_clusters(text)) == [text]


def test_grapheme_clusters_empty():
    assert list(grapheme_clusters("")) == []


# --------------------------------------------------------------------------
# Screen construction / repr / reset
# --------------------------------------------------------------------------

def test_screen_repr():
    assert repr(pyte.Screen(3, 2)) == "Screen(3, 2)"


def test_screen_initial_state():
    screen = pyte.Screen(4, 3)
    assert screen.columns == 4 and screen.lines == 3
    assert (screen.cursor.x, screen.cursor.y) == (0, 0)
    assert screen.display == ["    "] * 3
    assert screen.margins is None
    assert screen.charset == 0
    assert mo.DECAWM in screen.mode and mo.DECTCEM in screen.mode


def test_screen_default_char_reverse_follows_mode():
    screen = pyte.Screen(2, 2)
    assert screen.default_char.reverse is False
    screen.set_mode(mo.DECSCNM >> 5, private=True)
    assert screen.default_char.reverse is True


def test_reset_restores_defaults():
    screen = pyte.Screen(4, 3)
    screen.draw("xxxx")
    screen.cursor_position(2, 2)
    screen.set_margins(1, 2)
    screen.reset()
    assert screen.display == ["    "] * 3
    assert (screen.cursor.x, screen.cursor.y) == (0, 0)
    assert screen.margins is None
    assert screen.tabstops == set(range(8, screen.columns, 8))


def test_default_tabstops():
    screen = pyte.Screen(20, 3)
    assert screen.tabstops == {8, 16}


# --------------------------------------------------------------------------
# draw
# --------------------------------------------------------------------------

def test_draw_basic():
    screen = pyte.Screen(5, 2)
    screen.draw("foo")
    assert chars(screen, 0) == "foo  "
    assert screen.cursor.x == 3


def test_draw_wrap_decawm():
    screen = pyte.Screen(3, 2)
    screen.draw("abcd")
    assert chars(screen, 0) == "abc"
    assert chars(screen, 1) == "d  "
    assert (screen.cursor.x, screen.cursor.y) == (1, 1)


def test_draw_no_wrap_without_decawm():
    screen = pyte.Screen(3, 2)
    screen.reset_mode(mo.DECAWM)
    screen.draw("abcd")
    assert chars(screen, 0) == "abd"   # last char overwrites column 2
    assert screen.cursor.y == 0


def test_draw_wide_char_occupies_two_cells():
    screen = pyte.Screen(4, 1)
    screen.draw("\u4e00")              # a full-width CJK ideograph
    assert screen.buffer[0][0].data == "\u4e00"
    assert screen.buffer[0][1].data == ""    # stub cell
    assert screen.cursor.x == 2


def test_draw_combining_merges_with_previous():
    screen = pyte.Screen(4, 1)
    screen.draw("e")
    screen.draw("\u0301")             # combining acute accent
    assert screen.buffer[0][0].data == "\u00e9"   # NFC-normalised 'e'
    assert screen.cursor.x == 1


def test_draw_irm_insert_mode():
    screen = pyte.Screen(5, 1)
    screen.draw("abc")
    screen.cursor_position(1, 1)
    screen.set_mode(mo.IRM)
    screen.draw("X")
    assert chars(screen, 0) == "Xabc "


def test_draw_marks_dirty():
    screen = pyte.Screen(5, 2)
    screen.dirty.clear()
    screen.draw("z")
    assert 0 in screen.dirty


def test_draw_via_g1_charset():
    screen = pyte.Screen(3, 1)
    screen.define_charset("0", "(")   # G0 -> VT100 graphics
    screen.draw("q")                  # 'q' maps to horizontal line in VT100
    assert screen.buffer[0][0].data == "\u2500"


# --------------------------------------------------------------------------
# Cursor movement
# --------------------------------------------------------------------------

def test_carriage_return():
    screen = pyte.Screen(5, 1)
    screen.cursor.x = 3
    screen.carriage_return()
    assert screen.cursor.x == 0


def test_cursor_up_down_forward_back():
    screen = pyte.Screen(10, 10)
    screen.cursor_position(5, 5)
    screen.cursor_up(2)
    assert screen.cursor.y == 2
    screen.cursor_down(3)
    assert screen.cursor.y == 5
    screen.cursor_forward(2)
    assert screen.cursor.x == 6
    screen.cursor_back(4)
    assert screen.cursor.x == 2


def test_cursor_up1_down1_reset_column():
    screen = pyte.Screen(10, 10)
    screen.cursor_position(5, 5)
    screen.cursor_up1()
    assert (screen.cursor.x, screen.cursor.y) == (0, 3)
    screen.cursor_position(5, 5)
    screen.cursor_down1()
    assert (screen.cursor.x, screen.cursor.y) == (0, 5)


def test_cursor_movement_clamped():
    screen = pyte.Screen(5, 5)
    screen.cursor_up(100)
    assert screen.cursor.y == 0
    screen.cursor_down(100)
    assert screen.cursor.y == 4
    screen.cursor_back(100)
    assert screen.cursor.x == 0
    screen.cursor_forward(100)
    assert screen.cursor.x == 4


def test_cursor_position_is_one_based():
    screen = pyte.Screen(10, 10)
    screen.cursor_position(3, 7)
    assert (screen.cursor.x, screen.cursor.y) == (6, 2)


def test_cursor_position_defaults_home():
    screen = pyte.Screen(10, 10)
    screen.cursor_position(5, 5)
    screen.cursor_position()
    assert (screen.cursor.x, screen.cursor.y) == (0, 0)


def test_cursor_to_column_and_line():
    screen = pyte.Screen(10, 10)
    screen.cursor_to_column(4)
    assert screen.cursor.x == 3
    screen.cursor_to_line(6)
    assert screen.cursor.y == 5


def test_backspace_and_tab():
    screen = pyte.Screen(20, 1)
    screen.tab()
    assert screen.cursor.x == 8
    screen.tab()
    assert screen.cursor.x == 16
    screen.backspace()
    assert screen.cursor.x == 15


def test_tab_past_last_stop():
    screen = pyte.Screen(10, 1)
    screen.cursor.x = 9
    screen.tab()
    assert screen.cursor.x == 9   # columns - 1


def test_set_and_clear_tab_stop():
    screen = pyte.Screen(20, 1)
    screen.cursor.x = 3
    screen.set_tab_stop()
    assert 3 in screen.tabstops
    screen.clear_tab_stop()
    assert 3 not in screen.tabstops
    screen.clear_tab_stop(3)
    assert screen.tabstops == set()


# --------------------------------------------------------------------------
# index / reverse_index / linefeed scrolling
# --------------------------------------------------------------------------

def test_index_scrolls_at_bottom():
    screen = pyte.Screen(3, 2)
    screen.draw("aaa")
    screen.cursor_position(2, 1)
    screen.draw("bbb")
    screen.index()            # cursor at bottom -> scroll
    assert chars(screen, 0) == "bbb"
    assert chars(screen, 1) == "   "


def test_reverse_index_scrolls_at_top():
    screen = pyte.Screen(3, 2)
    screen.draw("aaa")
    screen.cursor_position(2, 1)
    screen.draw("bbb")
    screen.cursor_position(1, 1)
    screen.reverse_index()
    assert chars(screen, 0) == "   "
    assert chars(screen, 1) == "aaa"


def test_linefeed_lnm_carriage_return():
    screen = pyte.Screen(5, 3)
    screen.set_mode(mo.LNM)
    screen.cursor.x = 3
    screen.linefeed()
    assert screen.cursor.x == 0


def test_index_within_margins():
    screen = pyte.Screen(3, 4)
    for row in "abcd":
        screen.draw(row * 3)
        if row != "d":
            screen.linefeed()
            screen.carriage_return()
    screen.set_margins(2, 3)      # rows 1..2 (0-based)
    screen.cursor_position(3, 1)  # bottom margin
    screen.index()
    assert chars(screen, 0) == "aaa"   # outside margins, unchanged
    assert chars(screen, 1) == "ccc"
    assert chars(screen, 3) == "ddd"


# --------------------------------------------------------------------------
# insert / delete lines & characters, erase
# --------------------------------------------------------------------------

def test_insert_lines():
    screen = pyte.Screen(3, 3)
    screen.draw("aaa"); screen.linefeed(); screen.carriage_return()
    screen.draw("bbb"); screen.linefeed(); screen.carriage_return()
    screen.draw("ccc")
    screen.cursor_position(1, 1)
    screen.insert_lines(1)
    assert chars(screen, 0) == "   "
    assert chars(screen, 1) == "aaa"


def test_delete_lines():
    screen = pyte.Screen(3, 3)
    screen.draw("aaa"); screen.linefeed(); screen.carriage_return()
    screen.draw("bbb"); screen.linefeed(); screen.carriage_return()
    screen.draw("ccc")
    screen.cursor_position(1, 1)
    screen.delete_lines(1)
    assert chars(screen, 0) == "bbb"
    assert chars(screen, 1) == "ccc"


def test_insert_characters():
    screen = pyte.Screen(5, 1)
    screen.draw("abcde")
    screen.cursor_position(1, 2)
    screen.insert_characters(2)
    assert chars(screen, 0) == "a  bc"


def test_delete_characters():
    screen = pyte.Screen(5, 1)
    screen.draw("abcde")
    screen.cursor_position(1, 1)
    screen.delete_characters(2)
    assert chars(screen, 0) == "cde  "


def test_erase_characters():
    screen = pyte.Screen(5, 1)
    screen.draw("abcde")
    screen.cursor_position(1, 2)
    screen.erase_characters(2)
    assert chars(screen, 0) == "a  de"


def test_erase_in_line_modes():
    for how, expected in [(0, "ab   "), (1, "   de"), (2, "     ")]:
        screen = pyte.Screen(5, 1)
        screen.draw("abcde")
        screen.cursor_position(1, 3)
        screen.erase_in_line(how)
        assert chars(screen, 0) == expected, how


def test_erase_in_display_modes():
    def build():
        s = pyte.Screen(3, 3)
        for y, row in enumerate("abc"):
            s.cursor_position(y + 1, 1)
            s.draw(row * 3)
        s.cursor_position(2, 2)
        return s

    s = build(); s.erase_in_display(0)
    assert chars(s, 0) == "aaa" and chars(s, 2) == "   "
    s = build(); s.erase_in_display(1)
    assert chars(s, 0) == "   " and chars(s, 2) == "ccc"
    s = build(); s.erase_in_display(2)
    assert all(chars(s, y) == "   " for y in range(3))


def test_alignment_display():
    screen = pyte.Screen(3, 2)
    screen.alignment_display()
    assert all(chars(screen, y) == "EEE" for y in range(2))


# --------------------------------------------------------------------------
# margins / modes / resize
# --------------------------------------------------------------------------

def test_set_margins():
    screen = pyte.Screen(10, 10)
    screen.set_margins(3, 7)
    assert screen.margins == Margins(2, 6)
    assert (screen.cursor.x, screen.cursor.y) == (0, 0)


def test_set_margins_none_resets():
    screen = pyte.Screen(10, 10)
    screen.set_margins(3, 7)
    screen.set_margins()
    assert screen.margins is None


def test_set_reset_mode():
    screen = pyte.Screen(5, 5)
    screen.set_mode(mo.IRM)
    assert mo.IRM in screen.mode
    screen.reset_mode(mo.IRM)
    assert mo.IRM not in screen.mode


def test_dectcem_toggles_cursor_hidden():
    screen = pyte.Screen(5, 5)
    screen.reset_mode(mo.DECTCEM >> 5, private=True)
    assert screen.cursor.hidden is True
    screen.set_mode(mo.DECTCEM >> 5, private=True)
    assert screen.cursor.hidden is False


def test_deccolm_resizes_to_132():
    screen = pyte.Screen(80, 24)
    screen.set_mode(mo.DECCOLM >> 5, private=True)
    assert screen.columns == 132
    screen.reset_mode(mo.DECCOLM >> 5, private=True)
    assert screen.columns == 80


def test_resize_grow_and_shrink():
    screen = pyte.Screen(5, 5)
    screen.resize(3, 3)
    assert (screen.lines, screen.columns) == (3, 3)
    screen.resize(6, 8)
    assert (screen.lines, screen.columns) == (6, 8)
    assert screen.display == ["        "] * 6


def test_resize_noop_same_size():
    screen = pyte.Screen(5, 5)
    screen.dirty.clear()
    screen.resize(5, 5)
    assert screen.dirty == set()


def test_resize_clips_columns_from_right():
    screen = pyte.Screen(5, 1)
    screen.draw("abcde")
    screen.resize(1, 3)
    assert chars(screen, 0) == "abc"


# --------------------------------------------------------------------------
# charsets / shift in-out
# --------------------------------------------------------------------------

def test_shift_in_out():
    screen = pyte.Screen(3, 1)
    screen.shift_out()
    assert screen.charset == 1
    screen.shift_in()
    assert screen.charset == 0


def test_define_charset_g0_g1():
    screen = pyte.Screen(3, 1)
    screen.define_charset("0", "(")
    assert screen.g0_charset == cs.VT100_MAP
    screen.define_charset("B", ")")
    assert screen.g1_charset == cs.LAT1_MAP


def test_define_charset_unknown_ignored():
    screen = pyte.Screen(3, 1)
    before = screen.g0_charset
    screen.define_charset("Z", "(")
    assert screen.g0_charset == before


# --------------------------------------------------------------------------
# save / restore cursor
# --------------------------------------------------------------------------

def test_save_restore_cursor():
    screen = pyte.Screen(10, 10)
    screen.cursor_position(3, 4)
    screen.save_cursor()
    screen.cursor_position(1, 1)
    screen.restore_cursor()
    assert (screen.cursor.x, screen.cursor.y) == (3, 2)


def test_restore_cursor_empty_stack_homes():
    screen = pyte.Screen(10, 10)
    screen.cursor_position(5, 5)
    screen.restore_cursor()
    assert (screen.cursor.x, screen.cursor.y) == (0, 0)


def test_save_restore_roundtrips_charset():
    screen = pyte.Screen(10, 10)
    screen.shift_out()
    screen.save_cursor()
    screen.shift_in()
    screen.restore_cursor()
    assert screen.charset == 1


# --------------------------------------------------------------------------
# select_graphic_rendition
# --------------------------------------------------------------------------

def test_sgr_reset():
    screen = pyte.Screen(3, 1)
    screen.select_graphic_rendition(1)
    assert screen.cursor.attrs.bold
    screen.select_graphic_rendition(0)
    assert not screen.cursor.attrs.bold


def test_sgr_colors():
    screen = pyte.Screen(3, 1)
    screen.select_graphic_rendition(31, 42)
    assert screen.cursor.attrs.fg == "red"
    assert screen.cursor.attrs.bg == "green"


def test_sgr_text_attributes():
    screen = pyte.Screen(3, 1)
    screen.select_graphic_rendition(1, 3, 4, 7, 9)
    a = screen.cursor.attrs
    assert a.bold and a.italics and a.underscore and a.reverse and a.strikethrough


def test_sgr_aixterm_bright():
    screen = pyte.Screen(3, 1)
    screen.select_graphic_rendition(90, 101)
    assert screen.cursor.attrs.fg == "brightblack"
    assert screen.cursor.attrs.bg == "brightred"


def test_sgr_256_color():
    screen = pyte.Screen(3, 1)
    screen.select_graphic_rendition(38, 5, 196)
    assert screen.cursor.attrs.fg == g.FG_BG_256[196]


def test_sgr_truecolor():
    screen = pyte.Screen(3, 1)
    screen.select_graphic_rendition(38, 2, 255, 128, 0)
    assert screen.cursor.attrs.fg == "ff8000"


def test_sgr_private_ignored():
    screen = pyte.Screen(3, 1)
    screen.select_graphic_rendition(1, private=True)
    assert not screen.cursor.attrs.bold


def test_sgr_truecolor_incomplete_is_swallowed():
    screen = pyte.Screen(3, 1)
    # Missing the last two components -> IndexError is caught internally.
    screen.select_graphic_rendition(38, 2, 1)
    assert isinstance(screen.cursor.attrs.fg, str)


# --------------------------------------------------------------------------
# device reports
# --------------------------------------------------------------------------

def test_report_device_attributes_writes_primary_da():
    seen = []
    screen = pyte.Screen(3, 1)
    screen.write_process_input = seen.append
    screen.report_device_attributes(0)
    assert seen == [ctrl.CSI + "?6c"]


def test_report_device_attributes_private_noop():
    seen = []
    screen = pyte.Screen(3, 1)
    screen.write_process_input = seen.append
    screen.report_device_attributes(0, private=True)
    assert seen == []


def test_report_device_status_5_and_6():
    seen = []
    screen = pyte.Screen(10, 10)
    screen.write_process_input = seen.append
    screen.report_device_status(5)
    screen.cursor_position(3, 4)
    screen.report_device_status(6)
    assert seen == [ctrl.CSI + "0n", ctrl.CSI + "3;4R"]


def test_bell_and_debug_and_wpi_are_noops():
    screen = pyte.Screen(3, 1)
    assert screen.bell() is None
    assert screen.debug(1, 2, x=3) is None
    assert screen.write_process_input("data") is None


def test_set_title_and_icon():
    screen = pyte.Screen(3, 1)
    screen.set_title("t")
    screen.set_icon_name("i")
    assert screen.title == "t" and screen.icon_name == "i"


# --------------------------------------------------------------------------
# Stream
# --------------------------------------------------------------------------

def test_stream_feed_moves_cursor():
    screen = pyte.Screen(80, 24)
    pyte.Stream(screen).feed("\x1b[5B")
    assert screen.cursor.y == 5


def test_stream_draw_plain_text():
    screen = pyte.Screen(10, 2)
    pyte.Stream(screen).feed("hello")
    assert chars(screen, 0) == "hello     "


def test_stream_requires_listener():
    with pytest.raises(RuntimeError):
        pyte.Stream().feed("x")


def test_stream_attach_detach():
    screen = pyte.Screen(5, 5)
    stream = pyte.Stream()
    stream.attach(screen)
    stream.feed("a")
    assert chars(screen, 0)[0] == "a"
    stream.detach(screen)
    assert stream.listener is None


def test_stream_strict_missing_event():
    class Incomplete:
        pass
    with pytest.raises(TypeError):
        pyte.Stream(Incomplete(), strict=True)


def test_stream_non_strict_allows_partial_screen():
    # ``set_title`` is dispatched lazily (only on an OSC sequence), so a screen
    # missing it is rejected up-front under strict mode but accepted otherwise.
    class MissingTitle:
        def __init__(self):
            self._s = pyte.Screen(5, 5)

        def __getattr__(self, name):
            if name == "set_title":
                raise AttributeError(name)
            return getattr(self._s, name)

    with pytest.raises(TypeError):
        pyte.Stream(MissingTitle(), strict=True)

    target = MissingTitle()
    stream = pyte.Stream(target, strict=False)   # no completeness check
    stream.feed("hi")                            # non-OSC input dispatches fine
    assert chars(target, 0).startswith("hi")


def test_stream_events_frozenset():
    assert "draw" in pyte.Stream.events
    assert "cursor_up" in pyte.Stream.events
    assert isinstance(pyte.Stream.events, frozenset)


def test_stream_osc_set_title():
    screen = pyte.Screen(10, 2)
    pyte.Stream(screen).feed("\x1b]2;hello\x07")
    assert screen.title == "hello"


def test_stream_osc_set_icon_name():
    screen = pyte.Screen(10, 2)
    pyte.Stream(screen).feed("\x1b]1;ic\x07")
    assert screen.icon_name == "ic"


def test_stream_osc_st_terminator():
    screen = pyte.Screen(10, 2)
    pyte.Stream(screen).feed("\x1b]2;via-st\x1b\\")
    assert screen.title == "via-st"


def test_stream_cancels_sequence_on_can():
    screen = pyte.Screen(10, 2)
    pyte.Stream(screen).feed("\x1b[1\x18")   # CAN aborts the CSI
    assert screen.cursor.y == 0


def test_stream_recovers_after_exception():
    class Boom(Exception):
        pass

    screen = pyte.Screen(5, 5)
    calls = {"n": 0}
    real_cursor_down = screen.cursor_down

    def boom(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise Boom()                     # fail the first dispatch only
        return real_cursor_down(*args, **kwargs)

    # Patch before attaching: the stream binds handlers statically at attach.
    screen.cursor_down = boom
    stream = pyte.Stream(screen)
    with pytest.raises(Boom):
        stream.feed("\x1b[B")                # CUD -> boom raises
    # Parser must remain usable afterwards (see PR #101).
    stream.feed("ok")
    assert chars(screen, 0).startswith("ok")


def test_stream_param_clamped_to_9999():
    screen = pyte.Screen(3, 1)
    seen = []
    screen.cursor_forward = lambda *a, **k: seen.append(a)
    pyte.Stream(screen, strict=False).feed("\x1b[100000C")
    assert seen == [(9999,)]


def test_stream_ignores_shifts_in_utf8():
    screen = pyte.Screen(3, 1)
    stream = pyte.Stream(screen)
    stream.feed("\x0e")             # SO ignored in utf-8 mode
    assert screen.charset == 0


# --------------------------------------------------------------------------
# ByteStream
# --------------------------------------------------------------------------

def test_bytestream_utf8_default():
    screen = pyte.Screen(5, 1)
    pyte.ByteStream(screen).feed("h\u00e9llo".encode("utf-8")[:6])
    assert screen.buffer[0][1].data == "\u00e9"


def test_bytestream_incremental_multibyte():
    screen = pyte.Screen(5, 1)
    stream = pyte.ByteStream(screen)
    data = "\u4e00".encode("utf-8")
    stream.feed(data[:1])           # partial
    stream.feed(data[1:])           # remainder
    assert screen.buffer[0][0].data == "\u4e00"


def test_bytestream_select_other_charset_latin1():
    screen = pyte.Screen(5, 1)
    stream = pyte.ByteStream(screen)
    stream.select_other_charset("@")
    assert stream.use_utf8 is False
    stream.feed(b"\xe9")            # latin-1 e-acute
    assert screen.buffer[0][0].data == "\u00e9"
    stream.select_other_charset("G")
    assert stream.use_utf8 is True


def test_bytestream_invalid_utf8_replacement():
    screen = pyte.Screen(5, 1)
    pyte.ByteStream(screen).feed(b"\xff\xfe")
    # Invalid bytes decode to U+FFFD replacement characters, no crash.
    assert screen.buffer[0][0].data == "\ufffd"


# --------------------------------------------------------------------------
# DiffScreen (deprecated) / dirty tracking
# --------------------------------------------------------------------------

def test_diffscreen_deprecation_warning():
    with pytest.warns(DeprecationWarning):
        pyte.DiffScreen(5, 5)


def test_dirty_tracks_drawn_lines():
    screen = pyte.Screen(5, 3)
    screen.dirty.clear()
    screen.draw("a")
    screen.linefeed()
    screen.draw("b")
    assert 0 in screen.dirty and 1 in screen.dirty


# --------------------------------------------------------------------------
# HistoryScreen
# --------------------------------------------------------------------------

def test_historyscreen_construction():
    screen = pyte.HistoryScreen(5, 3, history=10, ratio=0.5)
    assert screen.history.size == 10
    assert screen.history.position == 10


def test_historyscreen_collects_on_scroll():
    screen = pyte.HistoryScreen(3, 2, history=10)
    stream = pyte.Stream(screen)
    for i in range(6):
        stream.feed(f"line{i}\r\n")
    assert len(screen.history.top) > 0


def test_historyscreen_prev_next_page():
    screen = pyte.HistoryScreen(3, 3, history=20, ratio=0.5)
    stream = pyte.Stream(screen)
    for i in range(12):
        stream.feed(f"{i}\r\n")
    pos0 = screen.history.position
    screen.prev_page()
    assert screen.history.position <= pos0
    screen.next_page()
    assert screen.history.position >= 0


def test_historyscreen_reset_clears_history():
    screen = pyte.HistoryScreen(3, 2, history=10)
    stream = pyte.Stream(screen)
    for i in range(6):
        stream.feed(f"x{i}\r\n")
    screen.reset()
    assert len(screen.history.top) == 0
    assert screen.history.position == screen.history.size


def test_historyscreen_erase_display_3_resets_history():
    screen = pyte.HistoryScreen(3, 2, history=10)
    stream = pyte.Stream(screen)
    for i in range(6):
        stream.feed(f"y{i}\r\n")
    screen.erase_in_display(3)
    assert len(screen.history.top) == 0


# --------------------------------------------------------------------------
# DebugScreen / DebugEvent / pyte.dis
# --------------------------------------------------------------------------

def test_debugscreen_dumps_events():
    buf = io.StringIO()
    stream = pyte.Stream(pyte.DebugScreen(to=buf))
    stream.feed("\x1b[1;24r")
    assert '"set_margins", [1, 24]' in buf.getvalue()


def test_debugscreen_only_filter():
    buf = io.StringIO()
    stream = pyte.Stream(pyte.DebugScreen(to=buf, only=["draw"]))
    stream.feed("a\x1b[5B")
    out = buf.getvalue()
    assert "draw" in out and "cursor_down" not in out


def test_dis_smoke(capsys):
    pyte.dis(b"\x07")
    assert "bell" in capsys.readouterr().out
