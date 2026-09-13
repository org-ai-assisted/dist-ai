#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Deterministic terminal-output feed, shared by the widget and mainwin harnesses.

Kept side-effect-free (no Qt app, no XDG mutation, no require_wayland) so BOTH
test_widget_common and test_mainwin_common can import it without the two harnesses'
module-level setup clashing. Single source: a copy in either harness would drift."""

import os


def feed_output(term, raw):
    """Drive the real _on_readable with `raw` bytes via a pipe, as if the child had
    printed them, so the full output path (pyte feed + _handle_osc + line render)
    runs -- not a shortcut that skips the OSC read handlers.

    Chunked at the pty read size (65536): a single os.write of MORE than the pipe
    buffer would block forever (no concurrent reader in this synchronous helper), and
    _read_and_render only os.read()s 65536 per call anyway -- so a large payload is fed
    as successive reads, exactly as a real pty delivers it. An EMPTY `raw` still feeds
    once (the child-exit / EOF path)."""
    old = term._fd                             # pylint: disable=protected-access
    first = True
    try:
        while raw or first:
            first = False
            chunk, raw = raw[:65536], raw[65536:]
            r, w = os.pipe()
            term._fd = r
            w_open = True
            try:
                os.write(w, chunk)             # <= pipe buffer, so this cannot block
                os.close(w)
                w_open = False
                term._on_readable()            # pylint: disable=protected-access
            finally:
                os.close(r)
                if w_open:
                    os.close(w)
    finally:
        term._fd = old
    # CLI line-mode paints are debounced to ~60fps by a single-shot timer; in the
    # live app the paint fires from the event loop shortly after the read. These
    # synchronous tests feed then inspect at once, so flush the pending paint here
    # (the same flush teardown and every transcript/copy getter perform) so the
    # document reflects the just-fed bytes without pumping a real 16ms wait.
    term._flush_paint()
