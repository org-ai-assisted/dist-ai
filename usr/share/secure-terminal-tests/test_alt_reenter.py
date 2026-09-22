#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression: a full-screen program (alt screen) that RE-ENTERS the alt screen while
the widget already holds the alt view -- nano's rmcup+smcup burst on a SIGWINCH/resize
(?1049l then ?1049h in one read) -- must NOT leave primary scrollback stacked under the
grid, and the snapshot render inside _alt_enter must keep the vertical scrollbar OFF.

The old bug (secure-terminal terminal.py, _alt_enter): the forced primary-scrollback
snapshot render (1) restored a pre-existing _alt_view True, so the next alt render skipped
_reset_grid_view and STACKED the grid under the leftover scrollback rows; and (2) showed
the AsNeeded vertical bar, which narrowed the viewport -> resizeEvent -> new child winsize
-> SIGWINCH -> the program repainted (re-entered) -> a non-stop winsize/repaint loop (the
reported viewport 'jumping').

Runs on the real headless-Wayland widget path (feed_output drives _on_readable)."""

from test_widget_common import *   # noqa: F401,F403  (shared harness)

_ALWAYS_OFF = Qt.ScrollBarPolicy.ScrollBarAlwaysOff
_AS_NEEDED = Qt.ScrollBarPolicy.ScrollBarAsNeeded


def _nano_frame(term):
    """A full-screen (alt) repaint: enter alt, clear, title at row 0, status at the last
    row -- the shape nano draws (absolute cursor addressing, no scrollback)."""
    lines = term._screen.lines
    return (b'\x1b[?1049h\x1b[2J\x1b[H\x1b[7m  GNU nano 8.4  New Buffer\x1b[0m'
            b'\x1b[%d;1H\x1b[7m^X Exit\x1b[0m' % lines)


def _reenter_frame(term):
    """nano's SIGWINCH redraw: rmcup then smcup in ONE read (no render between, so
    _alt_leave leaves _alt_view True), then the repaint -- the burst that triggered the bug."""
    lines = term._screen.lines
    return (b'\x1b[?1049l\x1b[?1049h\x1b[2J\x1b[H\x1b[7m  GNU nano 8.4  New Buffer\x1b[0m'
            b'\x1b[%d;1H\x1b[7m^X Exit\x1b[0m' % lines)


def _fill_scrollback(term):
    """Feed primary output that EXCEEDS the current grid at ANY DPI (the runner overrides
    QT_FONT_DPI), so pyte always keeps rows in history.top -- the rows the old bug
    resurrected and stacked. Sizing off _screen.lines avoids codex's fixed-60-lines trap
    where a tall low-DPI grid swallowed the scrollback and invalidated the setup."""
    n = term._screen.lines * 2 + 5
    feed_output(term, b''.join(b'PRIMARY-%03d\r\n' % i for i in range(n)))
    term._render_tui()
    APP.processEvents()


def _new_term():
    t = SecureTerminal(command='/bin/cat', tui=True)
    t.resize(930, 470)
    t.show()
    APP.processEvents()
    return t


# --- alt RE-ENTER: no stacking AND the bar stays off THROUGHOUT the re-enter -----------
_t = _new_term()
_fill_scrollback(_t)
feed_output(_t, _nano_frame(_t))          # a program takes the alt screen
_t._render_tui()
APP.processEvents()
eq(_t.document().blockCount(), _t._grid_rows,
   'alt screen shows ONLY the grid (no primary scrollback stacked) on first entry')

# Record the vscroll policy at EVERY _apply_vscroll_policy call across the whole re-enter,
# so the check covers the TRANSIENT snapshot render inside _alt_enter -- not just the
# settled state after it returned. A target that leaves _alt_view correct but drops the
# _alt_snapshotting assignments in _alt_enter shows an AsNeeded bar HERE and fails this,
# where an after-the-fact maximum()/policy check (codex #1, grok #1) would still pass.
_seen = []
_orig_policy = _t._apply_vscroll_policy


def _spy_policy():
    _orig_policy()
    _seen.append(_t.verticalScrollBarPolicy())


_t._apply_vscroll_policy = _spy_policy
feed_output(_t, _reenter_frame(_t))
_t._render_tui()
APP.processEvents()
_t._apply_vscroll_policy = _orig_policy

eq(_t.document().blockCount(), _t._grid_rows,
   'alt RE-ENTER (rmcup+smcup) does NOT stack primary scrollback under the grid')
ok(len(_seen) > 0 and all(p == _ALWAYS_OFF for p in _seen),
   'the snapshot render inside _alt_enter keeps the vscrollbar AlwaysOff (no AsNeeded '
   'flicker -> no winsize/repaint loop); saw policies: %r' % (_seen,))
# Do NOT assert maximum()==0: Qt can keep a 1-unit internal range on a hidden AlwaysOff
# bar under a DPI/scale override (codex #2). The meaningful property is a hidden bar on a
# fixed canvas.
ok(not _t.verticalScrollBar().isVisible()
   and _t.verticalScrollBarPolicy() == _ALWAYS_OFF,
   'alt RE-ENTER leaves the vertical scrollbar hidden on a fixed canvas')
_t.close()

# --- the _alt_snapshotting guard forces the bar OFF on a non-alt overflowing canvas ----
# Unit-level companion to the integration check above: on a primary grid taller than the
# viewport the policy is normally AsNeeded; while snapshotting it MUST be forced AlwaysOff.
_g = _new_term()
_fill_scrollback(_g)
ok(not _g._grid_fixed_canvas(),
   'a primary grid taller than the viewport is NOT a fixed canvas (bar wanted)')
_g._alt_snapshotting = False
_g._apply_vscroll_policy()
eq(_g.verticalScrollBarPolicy(), _AS_NEEDED,
   'without the snapshot guard an overflowing primary grid keeps AsNeeded')
_g._alt_snapshotting = True
_g._apply_vscroll_policy()
eq(_g.verticalScrollBarPolicy(), _ALWAYS_OFF,
   '_alt_snapshotting forces the bar OFF (no flicker -> no winsize/repaint loop)')
_g._alt_snapshotting = False
_g.close()

# --- alt-ENTER from a scrolled primary reclaims the scrollbar column (ai-review grok#1) -
# The snapshot render hides the bar while _alt_screen is False, so the later alt paint no
# longer toggles the bar; _alt_enter must reconcile the winsize itself, or the full-screen
# program is left one column short (a dead strip on the right).
_e = _new_term()
_fill_scrollback(_e)                        # > one screen -> the vertical bar is shown
if _e.verticalScrollBar().isVisible():      # (a taller low-DPI grid may not overflow)
    feed_output(_e, _nano_frame(_e))
    _e._render_tui()
    APP.processEvents()
    eq(_e._screen.columns, _e._tui_grid_size()[0],
       'alt-enter reclaims the scrollbar column: child width == alt grid width, not one short')
_e.close()

finish('alt-reenter')
