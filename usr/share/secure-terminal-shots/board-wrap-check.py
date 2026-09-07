#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guard: a full-viewport truecolour board (truecolor-art.py / truecolor-gradient.py) must be
## sized to EXACTLY secure-terminal's grid width at the shot geometry. Pin it too wide and every
## board line overflows the grid and HARD-WRAPS: the remainder spills onto its own short row, so
## the render becomes a stripe (a full row) alternating with a short continuation row (the classic
## "striped board" shot). The board cols are a pinned constant (ST_BOARD_COLS in lib-capture.sh),
## calibrated to st_win_w/st_win_h + the shot font -- a value that SILENTLY drifts when the app
## chrome changes (a wider scrollbar, a toolbar reflow), which is exactly how the striped shots
## shipped once.
##
## This turns that silent drift LOUD. secure-terminal writes its rendered transcript to
## SECURE_TERMINAL_TRANSCRIPT_FILE; a hard-wrap shows there as a SHORT board row among the
## full-width ones. The check is mode-AGNOSTIC: it drops the shell prompt / command echo, then a
## clean board is a rectangle -- every remaining row the SAME width; a wrap makes it ragged. This
## catches BOTH the Show board (rows of the U+2580 half-block) AND the neutralised Box board (each
## cell an inert multi-char box, no U+2580 to key on). Detail mode expands each cell and flows by
## design (never a clean rectangle), so it is not checked. In Show mode the rows ARE the column
## count, so the pinned cols are additionally asserted exactly -- and that exact width is the value
## to re-pin ST_BOARD_COLS to.

import argparse
import sys

HALF_BLOCK = '\u2580'   # U+2580 UPPER HALF BLOCK; ASCII-escaped source per R-001


def board_rows(transcript, prompt):
    """The board's rendered rows: non-blank transcript lines that are not the shell prompt / the
    injected 'cat' echo. transcript_text() walks the RENDERED document, so a hard-wrapped source
    line appears as a full-width row followed by a short fragment row -- both are board rows.
    Trailing whitespace (grid padding, were the app to emit any) is not width, so compare rstrip'd
    lengths. `prompt` is matched on its core (trailing space stripped) so the returning bare prompt
    is dropped too."""
    core = prompt.strip()
    rows = []
    for line in transcript.split('\n'):
        if not line.strip():
            continue
        if core and core in line:
            continue
        rows.append(line.rstrip())
    return rows


def check(transcript, cols, prompt):
    """Return (ok, message). ok is False when the board wrapped, rendered uniformly narrow, or
    never rendered."""
    rows = board_rows(transcript, prompt)
    if not rows:
        return False, 'no board rows in transcript (board never rendered)'
    widths = sorted({len(r) for r in rows})
    is_show = all(set(r) <= {HALF_BLOCK} for r in rows)
    if len(widths) > 1:
        full = widths[-1]
        frags = widths[:-1]
        hint = ((' Re-pin ST_BOARD_COLS in lib-capture.sh to %d.' % full) if is_show
                else ' Re-derive ST_BOARD_COLS (the Show board check reports the exact column count).')
        return False, (
            'board WRAPPED: rows are ragged (full row width %d, wrap-fragment width(s) %s) '
            '-- the pinned board overflows the live grid.%s' % (full, frags, hint))
    w = widths[0]
    if is_show and w != cols:
        # A uniformly-narrow Show board: the payload width does not match the pinned cols (a
        # payload/flag mismatch, or a grid that is an exact divisor of the payload so the wrap is
        # not ragged). The rendered width is the value to size to.
        return False, (
            'board width %d != pinned cols %d: the Show board rendered uniformly narrow '
            '(payload/grid mismatch). Re-pin ST_BOARD_COLS to %d.' % (w, cols, w))
    return True, 'board OK: %d row(s), uniform width %d, no wrap' % (len(rows), w)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Fail if a captured truecolour board wrapped (pinned cols > live grid).')
    parser.add_argument('transcript', help='path to the SECURE_TERMINAL_TRANSCRIPT_FILE dump')
    parser.add_argument('--cols', type=int, required=True,
                        help='the board width pinned in lib-capture.sh (ST_BOARD_COLS)')
    parser.add_argument('--prompt', default='',
                        help="the shell prompt (SHOT_PROMPT), dropped from the board rows")
    args = parser.parse_args(argv)
    try:
        with open(args.transcript, encoding='utf-8', errors='replace') as fh:
            transcript = fh.read()
    except OSError as exc:
        sys.stderr.write('board-wrap-check: cannot read %s: %s\n' % (args.transcript, exc))
        return 2
    ok, message = check(transcript, args.cols, args.prompt)
    sys.stderr.write('board-wrap-check: %s\n' % message)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
