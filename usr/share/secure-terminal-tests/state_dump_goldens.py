#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Committed golden state dumps: the SCENARIOS here each build a SYNTHETIC pyte screen
at a fixed size and dump it via secure_terminal.state_dump. Pure (no Qt / no widget), so
the output is deterministic and independent of the font / grid geometry a live widget
would introduce -- exactly what a byte-for-byte committed golden needs.

test_state_dump.py imports SCENARIOS and byte-compares each against its committed file in
state-dumps/. Regenerate the committed files (from the secure-terminal-tests dir, with the
secure_terminal package on PYTHONPATH) with:

    python3 -c 'import state_dump_goldens as g; g.write_all()'

Recorded dumps are small (single-digit KB, elision keeps blank rows out) and diffable, so
they live in-repo as review-readable evidence of what a given terminal state serializes to.
"""

import os

import pyte

from secure_terminal import state_dump as sd


def _rich_tui():
    """A TUI state exercising every dumped field: a coloured/bold run in the grid, a
    hidden cursor (DECTCEM), a scroll region (DECSTBM), a DEC special-graphics G0
    designation, active mouse reporting and OSC palette overrides."""
    screen = pyte.HistoryScreen(24, 4, history=20)
    stream = pyte.Stream(screen)
    stream.feed('\x1b[1;31mERR\x1b[0m ok\r\n'   # row 0: red bold ERR run, then ok
                'plain line 2'                   # row 1: default text
                '\x1b[?25l'                      # hide the cursor (DECTCEM)
                '\x1b[2;3r')                     # scroll region top=1 bottom=2 (0-based)
    # The live widget designates charsets through its own _Utf8CharsetByteStream (plain
    # pyte.Stream here does not parse ESC ( 0), so set the G0 special-graphics designation
    # directly -- the golden documents the dumped field, the LIVE charset reset is proven
    # by the widget reset tests).
    screen.g0_charset = pyte.charsets.VT100_MAP
    return sd.dump_text(sd.collect(
        screen, mode='tui', columns=24, alt_screen=False, saved_primary=None,
        mouse_modes={1000, 1006}, palette={1: '#ff0000', 'fg': '#00ff00'}, title='vim'))


def _rich_cli():
    """A CLI (line-mode) state: an SGR pen, active mouse reporting, palette overrides and
    a rendered line document -- the fields a CLI dump carries (no cell grid)."""
    return sd.dump_text(sd.collect(
        None, mode='cli', columns=80, alt_screen=False, saved_primary=None,
        mouse_modes={1002}, palette={'bg': '#000080'}, title='build',
        cli_pen={'fg': 3, 'bg': None, 'bold': True}, document='build ok\n$ '))


def _baseline_tui():
    """The canonical clean prompt baseline a fresh screen dumps to -- the target state
    _reset_vt_to_prompt_baseline() restores. Committed so the baseline itself is a
    reviewable, drift-guarded reference."""
    screen = pyte.HistoryScreen(24, 4, history=20)
    return sd.dump_text(sd.collect(
        screen, mode='tui', columns=24, alt_screen=False, saved_primary=None,
        mouse_modes=set(), palette={}, title=''))


SCENARIOS = {
    'rich-tui.dump': _rich_tui,
    'rich-cli.dump': _rich_cli,
    'baseline-tui.dump': _baseline_tui,
}


def _dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'state-dumps')


def write_all():
    """(Re)write every committed golden. Called by the regenerate one-liner in the
    module docstring; never by the test (the test only compares)."""
    out = _dir()
    os.makedirs(out, exist_ok=True)
    for name, build in SCENARIOS.items():
        with open(os.path.join(out, name), 'w', encoding='utf-8') as handle:
            handle.write(build())
        print('wrote', name)


if __name__ == '__main__':
    write_all()
