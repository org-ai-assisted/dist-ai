#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""End-to-end "jump to bottom" regression: a REAL fake-Claude TUI child + the REAL widget.

Reproduces the two coupled user reports against a Claude Code session in secure-terminal:
  1. the LAST TUI row is truncated at the bottom of the tab, and
  2. clicking "jump to bottom" / pressing Ctrl+End does nothing.

Both share one root cause: the winsize rows were computed from fontMetrics().height() while
the document paints each row ~1px taller (QTextLine.height()), so a full-screen, top-pinned
TUI overran the viewport and the bottom row was clipped -- which is also why Ctrl+End (the
key IS delivered, encoded as ESC[1;5F) looked like a no-op: the row it reveals was the
clipped one.

Why a real child (not feed_output): this must prove the ROUND TRIP -- ST encodes Ctrl+End,
WRITES ESC[1;5F to the pty, and the child reacts. fake_claude_tui.py draws a primary-buffer
fixed canvas with a status line on the very last row and, on ESC[1;5F, overwrites that last
row with the sentinel BOTTOMMARK. We assert ST wrote the bytes AND BOTTOMMARK renders on the
last, un-clipped row.

Real-child E2E (forks a python child), so it runs in the PLAIN runner, not the coverage gate
-- like test_user_scenarios / test_instances."""

import os
import sys

from test_widget_common import (          # noqa: F401  (harness hub re-exports)
    spawn_live, key, pump, ok, finish, Qt,
)

_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fake_claude_tui.py')
CMD = [sys.executable, '-u', _FIXTURE]


def read_doc(term):
    term._force_current_frame()               # flush the debounced grid paint -> latest frame
    return term.toPlainText()


def settle_contains(term, needle, timeout_ms=8000, quiet_ms=300):
    """Pump until `needle` is in the rendered doc AND the doc has been byte-stable for
    quiet_ms (a sustained-quiet window, not two quick equal polls)."""
    import time
    prev = None
    last_change = time.monotonic()
    deadline = last_change + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        pump(25)
        cur = read_doc(term)
        now = time.monotonic()
        if cur != prev:
            last_change = now
            prev = cur
            continue
        if needle in cur and (now - last_change) * 1000.0 >= quiet_ms:
            return True
    return needle in read_doc(term)


def last_block_with(term, needle):
    """(block, top_y, bottom_y) in viewport coords for the LAST visible block whose text
    contains `needle`, or None. Uses the widget's own visible-block walk."""
    hits = [(b, t, bot) for (b, t, bot) in term._visible_blocks() if needle in b.text()]
    return hits[-1] if hits else None


def test_jump_to_bottom():
    term = spawn_live(command=CMD, tui=True)
    try:
        term.resize(1000, 640)
        term.show()
        # a zoom where the real painted pitch exceeds fontMetrics().height() -- the band the
        # unit test (test_core_fixes) sweeps; pick a value inside it so the clip would bite
        # pre-fix. Synchronous apply (no debounce) so the frame settles deterministically.
        term._zoom_debounce_ms = 0
        term.apply_zoom(170)
        pump(50)

        # (1) the fake-Claude footer renders and its STATUS line (the very last row) is
        #     fully on-screen -- the truncation repro.
        ok(settle_contains(term, 'FAKECLAUDE'),
           'jump-bottom: the fake-Claude status line never rendered')
        status = last_block_with(term, 'FAKECLAUDE')
        ok(status is not None and status[2] <= term.viewport().height(),
           'jump-bottom: the status line (last TUI row) is clipped at the bottom')

        # (2) Ctrl+End is delivered to the child as ESC[1;5F. Tee _write so we both RECORD
        #     the bytes and FORWARD them to the real pty (spy_writes would drop the write and
        #     the child would never react).
        sent = []
        _orig_write = term._write

        def _tee(data):
            sent.append(data)
            return _orig_write(data)

        term._write = _tee
        key(term, Qt.Key.Key_End, '', Qt.KeyboardModifier.ControlModifier)
        ok(b'\x1b[1;5F' in b''.join(sent),
           'jump-bottom: Ctrl+End not encoded/delivered as ESC[1;5F (got %r)' % (b''.join(sent),))

        # (3) the child reacted: BOTTOMMARK now sits on the last row, fully visible. Pre-fix
        #     this row was clipped, so the "jump to bottom" looked like a no-op.
        ok(settle_contains(term, 'BOTTOMMARK'),
           'jump-bottom: child did not react to Ctrl+End (no BOTTOMMARK on the last row)')
        mark = last_block_with(term, 'BOTTOMMARK')
        ok(mark is not None and mark[2] <= term.viewport().height(),
           'jump-bottom: BOTTOMMARK row is clipped -- the bottom row is still not fully visible')
    finally:
        try:
            term.shutdown()
        except Exception:                 # pylint: disable=broad-except
            pass


if __name__ == '__main__':
    test_jump_to_bottom()
    finish('tui-jump-to-bottom')
