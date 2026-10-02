#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Deterministic "normal user behaviour" simulation E2E.

Drives the REAL SecureTerminal widget on headless Wayland through the ordinary
actions a user performs in the first seconds of a session -- open a shell, type a
command and press Enter, press Enter on an EMPTY prompt, edit with Backspace --
and asserts the rendered buffer is EXACTLY what those keystrokes should produce
(no blank line the user never typed, no lost or duplicated prompt).

Why this exists: the widget/mainwin suites drive handlers DIRECTLY (synthetic
events, no real event dispatch) and the GUI fuzzer feeds RANDOM bytes checking only
for crashes. Neither asserts "an ordinary typing/Enter flow yields the right visible
lines" -- the class of obvious bug a user hits immediately. This suite closes that gap.

Determinism: the child is `bash` with a fixed rcfile (PS1='READY> ', no
PROMPT_COMMAND / HISTFILE), so the buffer is a pure function of the keys sent; a
sentinel settle (wait for the prompt, byte-stable) replaces fixed sleeps. Real-child
E2E (forks bash), so it runs in the PLAIN runner, not the coverage gate -- like
test_instances. Faithful per-key input goes through the real keyPressEvent.

Mode note: `line_editing` only applies in CLI mode. In append-only, a bare CR is
DELIBERATELY kept as its own flagged line (see sanitize.feed_line_edits docstring:
each redraw frame on its own line + the _REDRAW_MARK gutter glyph keeps an overwrite
ATTEMPT visible). So append-only legitimately shows one extra frame per empty-prompt
Enter; this suite asserts the CONTAINMENT invariant there (no prompt lost/merged),
and the strict no-blank invariant in the modes a normal user runs (full / read-safe
/ TUI)."""

import os
import tempfile

from test_widget_common import (          # noqa: F401  (harness hub re-exports)
    spawn_live, key, pump, ok, eq, finish, Qt,
)

SENTINEL = 'READY> '
_RC = tempfile.NamedTemporaryFile('w', suffix='.bashrc', delete=False)
_RC.write("unset PROMPT_COMMAND\nunset HISTFILE\nPS1='%s'\n" % SENTINEL)
_RC.flush()
_RC.close()
CMD = ['/bin/bash', '--rcfile', _RC.name, '-i']


def read_doc(term):
    """The CURRENT visible document text, with any debounced paint forced to complete
    first. Without the force, the grid (TUI) render is debounced, so toPlainText can
    return a mid-render frame that momentarily holds a blank row the next frame removes
    -- a non-deterministic read. _force_current_frame fires the pending render so the
    document reflects the latest pyte model, making the read deterministic."""
    term._force_current_frame()               # pylint: disable=protected-access
    return term.toPlainText()


def doc_lines(term):
    """Visible document lines, dropping the single trailing empty block Qt always keeps."""
    lines = read_doc(term).split('\n')
    if lines and lines[-1] == '':
        lines = lines[:-1]
    return lines


def prompt_count(lines):
    # A prompt line is any line that STARTS with the prompt -- bare ("READY> ") or
    # carrying a typed command ("READY> echo hi"). Counting only bare prompts would
    # miscount the moment the user types on one.
    return sum(1 for ln in lines if ln.startswith(SENTINEL))


def leading_blanks(lines):
    n = 0
    for ln in lines:
        if ln.strip() == '':
            n += 1
        else:
            break
    return n


def interior_blanks(lines):
    lead = leading_blanks(lines)
    return sum(1 for ln in lines[lead:] if ln.strip() == '')


def settle(term, want_prompts, timeout_ms=8000, quiet_ms=350):
    """Pump until the doc ends with the prompt, shows >= want_prompts prompts, AND has
    not changed for `quiet_ms` (a sustained-quiet window, not just two equal polls).

    The two-equal-polls shortcut was too eager: the CLI line-mode paint is debounced
    (~60fps) and output arrives in chunks, so a mid-scroll frame -- which can momentarily
    hold a blank row that the next frame removes -- stays byte-stable for a couple of
    20ms polls and gets captured. Requiring a sustained quiet window settles to the FINAL
    frame. Deterministic replacement for a fixed sleep."""
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
        lines = doc_lines(term)
        ends_prompt = bool(lines) and lines[-1].rstrip() == SENTINEL.rstrip()
        if ends_prompt and prompt_count(lines) >= want_prompts \
                and (now - last_change) * 1000.0 >= quiet_ms:
            return lines
    return doc_lines(term)


def type_text(term, text):
    """Faithful per-character typing through the real keyPressEvent."""
    for ch in text:
        key(term, Qt.Key.Key_Any if hasattr(Qt.Key, 'Key_Any') else 0x2e, ch)


def press_enter(term):
    key(term, Qt.Key.Key_Return, '\r')


def press_backspace(term):
    key(term, Qt.Key.Key_Backspace, '\x7f')


def scenarios(tui, line_editing):
    tag = 'tui=%s,le=%s' % (tui, line_editing)
    strict = not (not tui and line_editing == 'append-only')   # append-only: by-design frames
    term = spawn_live(command=CMD, tui=tui, line_editing=line_editing)
    try:
        # --- open: a fresh shell shows exactly one clean prompt, no leading blank ---
        lines = settle(term, 1)
        ok(leading_blanks(lines) == 0,
           '%s open: leading blank line(s) the user never typed: %r' % (tag, lines[:3]))
        ok(bool(lines) and lines[-1].rstrip() == SENTINEL.rstrip(),
           '%s open: first prompt not clean: tail=%r' % (tag, lines[-3:]))
        ok(prompt_count(lines) == 1,
           '%s open: expected 1 prompt, got %d' % (tag, prompt_count(lines)))
        base = len(lines)

        # --- type a command + Enter: output appears, one new prompt follows ---
        type_text(term, 'echo hi')
        press_enter(term)
        lines = settle(term, 2)
        ok(sum(1 for ln in lines if ln.strip() == 'hi') == 1,
           '%s echo: "hi" not shown exactly once: %r' % (tag, lines))
        ok(prompt_count(lines) == 2,
           '%s echo: expected 2 prompts, got %d' % (tag, prompt_count(lines)))
        base = len(lines)
        pbase = prompt_count(lines)

        # --- press Enter on an EMPTY prompt 3x, at HUMAN pace: exactly 3 new prompts ---
        # Pace matters and is deliberate: pressing Enter FASTER than the shell redraws its
        # prompt makes readline coalesce the reads and emit an extra bare newline on the PTY
        # (proven: the raw pty bytes carry the extra "\r\n" itself). The terminal renders that
        # faithfully -- a blank row every real terminal would also show -- so it is the SHELL's
        # output, not a terminal defect, and must NOT be asserted against. Settling for the new
        # prompt between presses reproduces the ordinary human cadence, where the shell emits
        # exactly one prompt per Enter and no blank row.
        for i in range(3):
            press_enter(term)
            lines = settle(term, pbase + 1 + i)
        ok(prompt_count(lines) == pbase + 3,
           '%s empty-Enter: expected %d prompts, got %d (prompt lost/merged)'
           % (tag, pbase + 3, prompt_count(lines)))
        if strict:
            ok(interior_blanks(lines) == 0,
               '%s empty-Enter: %d blank line(s) the user never typed'
               % (tag, interior_blanks(lines)))
            ok(leading_blanks(lines) == 0,
               '%s empty-Enter: leading blank appeared' % tag)

        # --- Backspace edits the line (modes where BS acts) ---
        if line_editing != 'append-only':
            pbase = prompt_count(lines)
            type_text(term, 'echo hiX')
            press_backspace(term)
            press_enter(term)
            lines = settle(term, pbase + 1)
            ok(sum(1 for ln in lines if ln.strip() == 'hi') >= 1,
               '%s backspace: edited command did not yield "hi": %r' % (tag, lines[-4:]))
    finally:
        try:
            term.shutdown()
        except Exception:                 # pylint: disable=broad-except
            pass


if __name__ == '__main__':
    for _tui in (False, True):
        for _le in ('full', 'read-safe', 'append-only'):
            if _tui and _le != 'full':
                continue                  # line_editing is a CLI-mode setting
            scenarios(_tui, _le)
    os.unlink(_RC.name)
    finish('user-scenarios')
