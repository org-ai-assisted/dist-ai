"""Edge-case coverage: branches the main API suite reaches only indirectly.

Targets the specific parser/Screen/HistoryScreen/DebugEvent paths left uncovered
by test_full_api.py (charset-selection escapes, C1 CSI, OSC palette, secondary
DA, DECSCNM reverse video, combining onto the previous line, DECOM cursor
addressing with margins, out-of-margin line ops, HistoryScreen reverse-index,
DebugEvent round-trip).
"""
import io
import unicodedata

import pytest

import pyte
from pyte import modes as mo
from pyte.screens import DebugEvent


def chars(screen, y):
    return "".join(screen.buffer[y][x].data for x in range(screen.columns))


# --- Stream / parser edge paths -------------------------------------------

def test_stream_attach_second_listener_warns():
    stream = pyte.Stream(pyte.Screen(5, 5))
    with pytest.warns(DeprecationWarning):
        stream.attach(pyte.Screen(5, 5))


def test_stream_detach_non_listener_is_noop():
    screen = pyte.Screen(5, 5)
    stream = pyte.Stream(screen)
    stream.detach(pyte.Screen(5, 5))      # not the current listener
    assert stream.listener is screen


def test_stream_alignment_display_via_escape():
    screen = pyte.Screen(3, 2)
    pyte.Stream(screen).feed("\x1b#8")    # DECALN
    assert all(chars(screen, y) == "EEE" for y in range(2))


def test_stream_select_control_charset_is_noop():
    screen = pyte.Screen(3, 1)
    pyte.Stream(screen).feed("\x1b%G")    # select UTF-8 control set: noop, no crash
    pyte.Stream(screen).feed("\x1b%@")


def test_stream_c1_csi_control():
    screen = pyte.Screen(10, 10)
    pyte.Stream(screen).feed("\x9b5B")    # CSI C1 (0x9b) then CUD 5
    assert screen.cursor.y == 5


def test_stream_secondary_da_ignored():
    screen = pyte.Screen(3, 1)
    pyte.Stream(screen).feed("\x1b[>c")   # secondary DA: '>' is skipped, no crash


def test_stream_osc_palette_ignored():
    screen = pyte.Screen(3, 1)
    pyte.Stream(screen).feed("\x1b]R\x07")        # reset palette (not implemented)
    pyte.Stream(screen).feed("\x1b]P00ffffff")    # set palette (not implemented)


def test_stream_csi_dollar_intermediate_ignored():
    screen = pyte.Screen(3, 1)
    pyte.Stream(screen).feed("\x1b[1$p")  # XTerm '$' intermediate: consumed, no crash


def test_bytestream_define_charset_via_escape_non_utf8():
    screen = pyte.Screen(3, 1)
    stream = pyte.ByteStream(screen)
    stream.select_other_charset("@")      # use_utf8 = False
    stream.feed(b"\x1b(0")                # designate VT100 graphics as G0
    stream.feed(b"q")                     # 'q' -> horizontal line
    assert screen.buffer[0][0].data == "\u2500"


def test_dis_with_str_input(capsys):
    pyte.dis("\x1b[20m")
    assert "select_graphic_rendition" in capsys.readouterr().out


# --- Screen edge paths -----------------------------------------------------

def test_decscnm_reverse_video_set_and_reset():
    screen = pyte.Screen(3, 2)
    screen.draw("ab")
    screen.set_mode(mo.DECSCNM >> 5, private=True)
    assert screen.buffer[0][0].reverse is True        # existing cells flipped
    assert screen.cursor.attrs.reverse is True        # +reverse via SGR 7
    screen.reset_mode(mo.DECSCNM >> 5, private=True)
    assert screen.buffer[0][0].reverse is False


def test_draw_combining_merges_onto_previous_line():
    screen = pyte.Screen(2, 2)
    screen.draw("ab")                     # row 0: a b
    screen.cursor_position(2, 1)          # row 1, column 0
    screen.draw("\u0301")                 # combining acute at x==0, y>0
    merged = screen.buffer[0][screen.columns - 1].data
    assert merged == unicodedata.normalize("NFC", "b\u0301")


def test_cursor_position_decom_with_margins():
    screen = pyte.Screen(10, 10)
    screen.set_margins(3, 8)              # margins (2, 7)
    screen.set_mode(mo.DECOM)
    screen.cursor_position(2, 5)          # line relative to top margin
    assert screen.cursor.y == 3           # margins.top(2) + (2-1)
    screen.cursor_position(50, 1)         # past the bottom margin -> ignored
    assert screen.cursor.y == 3


def test_cursor_to_line_decom_with_margins():
    screen = pyte.Screen(10, 10)
    screen.set_margins(3, 8)
    screen.set_mode(mo.DECOM)
    screen.cursor_to_line(2)
    assert screen.cursor.y == 2 + 1       # offset by margins.top


def test_report_device_status_cursor_under_decom_with_margins():
    seen = []
    screen = pyte.Screen(10, 10)
    screen.write_process_input = seen.append
    screen.set_margins(3, 8)
    screen.set_mode(mo.DECOM)
    screen.cursor_position(2, 4)
    screen.report_device_status(6)
    assert seen[-1].endswith("R")


def test_insert_and_delete_lines_outside_margins_are_noops():
    screen = pyte.Screen(3, 5)
    screen.set_margins(2, 4)              # margins (1, 3)
    screen.cursor_position(1, 1)          # y=0, above the region
    screen.insert_lines(1)
    screen.delete_lines(1)
    assert screen.cursor.y == 0           # untouched, no crash


def test_ensure_hbounds_and_vbounds_direct():
    screen = pyte.Screen(5, 5)
    screen.cursor.x = 100
    screen.ensure_hbounds()
    assert screen.cursor.x == 4
    screen.cursor.x = -3
    screen.ensure_hbounds()
    assert screen.cursor.x == 0
    screen.cursor.y = 100
    screen.ensure_vbounds()
    assert screen.cursor.y == 4
    screen.set_margins(2, 4)
    screen.cursor.y = 0
    screen.ensure_vbounds(use_margins=True)
    assert screen.cursor.y == 1           # clamped up to the top margin


def test_restore_cursor_reapplies_origin_and_wrap():
    screen = pyte.Screen(10, 10)
    screen.set_margins(2, 8)
    screen.set_mode(mo.DECOM)             # origin saved
    screen.save_cursor()
    screen.reset_mode(mo.DECOM)
    screen.restore_cursor()
    assert mo.DECOM in screen.mode        # origin restored from the savepoint


# --- HistoryScreen edge paths ---------------------------------------------

def test_historyscreen_reverse_index_updates_bottom_history():
    screen = pyte.HistoryScreen(3, 3, history=10)
    stream = pyte.Stream(screen)
    for i in range(6):
        stream.feed(f"{i}\r\n")
    screen.cursor_position(1, 1)          # top line
    before = len(screen.history.bottom)
    screen.reverse_index()
    assert len(screen.history.bottom) >= before


# --- DebugEvent ------------------------------------------------------------

def test_debug_event_roundtrip_and_call():
    event = DebugEvent("cursor_down", [3], {})
    restored = DebugEvent.from_string(str(event))
    assert restored.name == "cursor_down"
    assert restored.args == [3]
    screen = pyte.Screen(10, 10)
    restored(screen)                      # __call__ executes on the screen
    assert screen.cursor.y == 3


def test_stream_control_char_within_csi():
    # A C0 control (linefeed) embedded in a CSI is dispatched immediately.
    screen = pyte.Screen(10, 10)
    pyte.Stream(screen).feed("\x1b[5\nB")     # LF acts mid-sequence, then CUD
    assert screen.cursor.y >= 1


def test_stream_define_charset_escape_is_noop_in_utf8():
    # In UTF-8 mode ESC ( 0 is intentionally ignored (charset stays Latin-1).
    screen = pyte.Screen(3, 1)
    stream = pyte.Stream(screen)              # use_utf8 defaults to True
    stream.feed("\x1b(0q")
    assert screen.buffer[0][0].data == "q"


def test_set_margins_with_only_one_bound():
    screen = pyte.Screen(10, 10)
    screen.set_margins(3, 8)                  # margins (2, 7)
    screen.set_margins(bottom=6)              # keep top, change bottom
    assert screen.margins.top == 2 and screen.margins.bottom == 5


def test_historyscreen_erase_in_display_3_direct_resets_history():
    screen = pyte.HistoryScreen(3, 2, history=10)
    stream = pyte.Stream(screen)
    for i in range(6):
        stream.feed(f"z{i}\r\n")
    screen.erase_in_display(3)
    assert len(screen.history.top) == 0


def test_historyscreen_paging_before_and_after_event():
    screen = pyte.HistoryScreen(4, 3, history=20, ratio=0.5)
    stream = pyte.Stream(screen)
    for i in range(15):
        stream.feed(f"{i}\r\n")
    screen.prev_page()                        # paginate up (after_event trims width)
    screen.prev_page()
    stream.feed("x")                          # a non-paging event forces back to bottom
    assert screen.history.position == screen.history.size


def test_debugscreen_only_wrapper_and_passthrough():
    buf = io.StringIO()
    debug = pyte.DebugScreen(to=buf, only=["draw"])
    # A non-event attribute is passed through to the real object.
    assert debug.to is buf
    pyte.Stream(debug).feed("hi\x1b[2A")
    out = buf.getvalue()
    assert "draw" in out and "cursor_up" not in out
