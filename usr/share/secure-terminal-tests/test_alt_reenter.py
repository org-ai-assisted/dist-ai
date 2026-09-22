#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression: a full-screen program (alt screen) that RE-ENTERS the alt screen while
the widget already holds the alt view -- nano's rmcup+smcup burst on a SIGWINCH/resize
(?1049l then ?1049h in one read) -- must NOT leave primary scrollback stacked under the
grid, and the vertical scrollbar must stay OFF.

The old bug: _alt_enter's forced primary-scrollback snapshot render (1) restored a
pre-existing _alt_view True, so the next alt render skipped _reset_grid_view and STACKED
the grid under the leftover scrollback rows (blockCount > grid rows -> a frame pushed off
the top pin), and (2) showed the AsNeeded vertical bar, which narrowed the viewport ->
resizeEvent -> new child winsize -> SIGWINCH -> the program repainted (rmcup+smcup) ->
_alt_enter again: a non-stop winsize/repaint loop (the reported viewport 'jumping').

Runs on the real headless-Wayland widget path (feed_output drives _on_readable)."""

from test_widget_common import *   # noqa: F401,F403  (shared harness)


def _nano_frame(term):
    """A full-screen (alt) repaint: enter alt, clear, title at row 0, status at the last
    row -- the shape nano draws (drawn via absolute cursor addressing, no scrollback)."""
    lines = term._screen.lines
    return (b'\x1b[?1049h\x1b[2J\x1b[H\x1b[7m  GNU nano 8.4  New Buffer\x1b[0m'
            b'\x1b[%d;1H\x1b[7m^X Exit\x1b[0m' % lines)


# --- no primary scrollback stacked under the alt grid after a resize re-enter ----------
_t = SecureTerminal(command='/bin/cat', tui=True)
_t.resize(930, 470)
_t.show()
APP.processEvents()
# primary output EXCEEDING one screen, so pyte keeps scrollback in history.top -- the
# rows the old bug resurrected and stacked.
feed_output(_t, b''.join(b'PRIMARY-%02d\r\n' % _i for _i in range(60)))
_t._render_tui()
APP.processEvents()
feed_output(_t, _nano_frame(_t))          # a program takes the alt screen
_t._render_tui()
APP.processEvents()
eq(_t.document().blockCount(), _t._grid_rows,
   'alt screen shows ONLY the grid (no primary scrollback stacked) on first entry')

# nano's SIGWINCH redraw: rmcup then smcup in ONE read (no render between, so _alt_leave
# leaves _alt_view True), then the repaint. This is the re-enter that triggered the bug.
_lines = _t._screen.lines
_reenter = (b'\x1b[?1049l\x1b[?1049h\x1b[2J\x1b[H\x1b[7m  GNU nano 8.4  New Buffer\x1b[0m'
            b'\x1b[%d;1H\x1b[7m^X Exit\x1b[0m' % _lines)
feed_output(_t, _reenter)
_t._render_tui()
APP.processEvents()
eq(_t.document().blockCount(), _t._grid_rows,
   'alt RE-ENTER (rmcup+smcup) does NOT stack primary scrollback under the grid')
_bar = _t.verticalScrollBar()
ok(not _bar.isVisible() and _bar.maximum() == 0,
   'alt RE-ENTER keeps the vertical scrollbar off with no scroll range (top-pinned frame)')
ok(_t.verticalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAlwaysOff,
   'alt RE-ENTER leaves the vscroll policy AlwaysOff (a fixed canvas)')
_t.close()

# --- the _alt_snapshotting guard forces the bar OFF on a non-alt overflowing canvas ----
# This is what keeps the snapshot render from flickering the bar (and thus the child
# winsize) during _alt_enter. On a primary grid taller than the viewport the policy is
# normally AsNeeded; while snapshotting it MUST be forced AlwaysOff.
_g = SecureTerminal(command='/bin/cat', tui=True)
_g.resize(930, 470)
_g.show()
APP.processEvents()
feed_output(_g, b''.join(b'LINE-%02d\r\n' % _i for _i in range(60)))
_g._render_tui()
APP.processEvents()
ok(not _g._grid_fixed_canvas(),
   'a primary grid taller than the viewport is NOT a fixed canvas (bar wanted)')
_g._alt_snapshotting = False
_g._apply_vscroll_policy()
eq(_g.verticalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAsNeeded,
   'without the snapshot guard an overflowing primary grid keeps AsNeeded')
_g._alt_snapshotting = True
_g._apply_vscroll_policy()
eq(_g.verticalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAlwaysOff,
   '_alt_snapshotting forces the bar OFF (no flicker -> no winsize/repaint loop)')
_g._alt_snapshotting = False
_g.close()

finish('alt-reenter')
