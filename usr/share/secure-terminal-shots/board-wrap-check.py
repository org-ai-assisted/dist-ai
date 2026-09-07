#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guard: a full-viewport truecolour board (truecolor-art.py / truecolor-gradient.py) must be
## sized to EXACTLY secure-terminal's grid width at the shot geometry. Pin it too wide and every
## board line overflows the grid and HARD-WRAPS: the remainder spills onto its own short row, so
## the render becomes a colour stripe alternating with a near-blank continuation row (the classic
## "striped gradient" shot). The board cols are a pinned constant in lib-capture.sh, calibrated to
## st_win_w/st_win_h + the shot font -- a value that SILENTLY drifts when the app chrome changes
## (a wider scrollbar, a toolbar reflow), which is exactly how the striped shots shipped once.
##
## This turns that silent drift LOUD. secure-terminal writes its rendered transcript to
## SECURE_TERMINAL_TRANSCRIPT_FILE; a hard-wrap shows there as a board row (a run of the U+2580
## half-block glyph) SHORTER than the board width. Read the transcript, find the board rows, and
## fail if any is short (a wrap fragment) or if none rendered. The board fills the viewport, so
## the widest board row IS the live grid width -- reported on failure so the pin can be re-derived.

import argparse
import sys

HALF_BLOCK = '\u2580'   # U+2580 UPPER HALF BLOCK; ASCII-escaped source per R-001


def board_row_lengths(transcript):
    """Half-block-glyph run length for every transcript line that is a board row.

    A board row is a line whose printable content is the half-block glyph (the boards emit
    ONLY SGR colour + U+2580 + newlines). transcript_text() walks the RENDERED document, so a
    hard-wrapped line appears as a full-width row followed by a short fragment row -- both are
    half-block runs, so both are counted, and the fragment is what betrays the wrap."""
    lengths = []
    for line in transcript.split('\n'):
        if not line:
            continue
        # A board row is all half-block glyphs. Anything else (the 'cat' echo, the shell prompt,
        # stray text) is not a board row and is ignored.
        if all(ch == HALF_BLOCK for ch in line):
            lengths.append(len(line))
    return lengths


def check(transcript, cols):
    """Return (ok, message). ok is False when the board wrapped or never rendered."""
    lengths = board_row_lengths(transcript)
    if not lengths:
        return False, 'no board rows in transcript (board never rendered)'
    grid = max(lengths)
    short = [n for n in lengths if n < cols]
    if short:
        return False, (
            'board WRAPPED: pinned cols=%d exceeds the live grid width=%d '
            '(%d full row(s), %d wrap-fragment row(s) of width %s). '
            'Re-pin the board cols in lib-capture.sh to %d.'
            % (cols, grid, sum(1 for n in lengths if n >= cols), len(short),
               sorted(set(short)), grid))
    if grid > cols:
        return False, (
            'board OVERSHOOT: a board row is %d wide but cols=%d was expected '
            '(payload/grid mismatch)' % (grid, cols))
    return True, 'board OK: %d row(s), all %d wide (no wrap)' % (len(lengths), grid)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Fail if a captured truecolour board wrapped (pinned cols > live grid).')
    parser.add_argument('transcript', help='path to the SECURE_TERMINAL_TRANSCRIPT_FILE dump')
    parser.add_argument('--cols', type=int, required=True,
                        help='the board width pinned in lib-capture.sh')
    args = parser.parse_args(argv)
    try:
        with open(args.transcript, encoding='utf-8', errors='replace') as fh:
            transcript = fh.read()
    except OSError as exc:
        sys.stderr.write('board-wrap-check: cannot read %s: %s\n' % (args.transcript, exc))
        return 2
    ok, message = check(transcript, args.cols)
    sys.stderr.write('board-wrap-check: %s\n' % message)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
