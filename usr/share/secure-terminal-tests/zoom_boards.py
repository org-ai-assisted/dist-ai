#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Zoom-sweep board byte-generators, Qt-FREE on purpose.

Split out of zoom_regression_lib so the terminal-safe-corpus drift gate can
regenerate each board with `python3 zoom_boards.py <name>` in a bare container
(no PyQt6). zoom_regression_lib re-imports BOARDS / board_spec from here, so the
board bytes are single-sourced across the capture harness, the shot publisher, and
the corpus. Each board is display-only, safe-to-cat output (colour, box glyphs,
Unicode, a short alt-screen frame); the sole side effects are a title/alt-screen
switch undone by `reset`.
"""

import sys

# ---------------------------------------------------------------------------
# Boards. Each is bytes fed as child output. A board also declares per-detector
# expectations so a legitimately-sparse board (an alt-screen frame pinned to the top)
# is not mis-flagged. `interior_blanks` is the count of INTENTIONAL blank lines that
# sit between content lines; `dense` marks a board that should fill the screen (so a
# near-empty render is the blank-screen artifact); `tui_altscreen` marks a board whose
# TUI form legitimately leaves the lower viewport blank (top-pinned alt screen).
# ---------------------------------------------------------------------------

def _box(width, title):
    # ASCII source (no raw non-ASCII in test source); \u escapes render byte-identical.
    # 250c/2500/2510 = box down+right / horizontal / down+left; 2502 vertical;
    # 2514/2518 = up+right / up+left.
    top = '\u250c' + '\u2500' * width + '\u2510'
    body = '\u2502' + (' ' + title).ljust(width) + '\u2502'
    bot = '\u2514' + '\u2500' * width + '\u2518'
    return (top + '\r\n' + body + '\r\n' + bot + '\r\n').encode('utf-8')


def _tui_showcase():
    # Box frame + colour SGR + a Unicode row + mixed content: the general-purpose
    # showcase, close to the site's tui-showcase board but synthesized so the board
    # needs no external payload file.
    parts = [_box(46, 'secure-terminal zoom showcase')]
    parts.append(b'\x1b[1mbold\x1b[0m \x1b[4munderline\x1b[0m \x1b[7mreverse\x1b[0m normal\r\n')
    parts.append(b'\x1b[31mred \x1b[32mgreen \x1b[33myellow \x1b[34mblue \x1b[35mmagenta \x1b[36mcyan\x1b[0m\r\n')
    parts.append('unicode: \u00e9\u00e8\u00ea caf\u00e9 na\u00efve -- quotes \u201cx\u201d \u2018y\u2019\r\n'.encode('utf-8'))
    parts.append('box glyphs: \u250c\u2500\u2510 \u2502 \u2514\u2500\u2518 \u2588\u2593\u2592\u2591\r\n'.encode('utf-8'))
    parts.append(b'path: /usr/lib/python3/dist-packages/secure_terminal/terminal.py\r\n')
    parts.append(b'$ prompt line, then a tail marker >>\r\n')
    return b''.join(parts)


def _colorgrad(rows=24, cols=100):
    # Dense truecolor gradient: every cell a distinct 24-bit colour, full width,
    # many rows -- the payload most prone to reflow striping / hard-wrap when the grid
    # narrows under zoom.
    out = []
    for r in range(rows):
        line = []
        for c in range(cols):
            red = (c * 255) // max(1, cols - 1)
            grn = (r * 255) // max(1, rows - 1)
            blu = 255 - red
            line.append('\x1b[48;2;%d;%d;%dm ' % (red, grn, blu))
        line.append('\x1b[0m\r\n')
        out.append(''.join(line))
    return ''.join(out).encode('utf-8')


def _longline_box():
    # Box frame + several UNBROKEN long lines longer than any tested grid -- directly
    # targets "words cut off the right edge" and wrap behaviour across zoom.
    parts = [_box(60, 'long-line + box board')]
    parts.append(b'short line\r\n')
    parts.append(b'L' + b'ong-unbroken-line-' * 18 + b'END\r\n')     # ~330 chars, no spaces
    parts.append(b'word ' * 60 + b'lastword\r\n')                    # ~300 chars, wrappable
    parts.append(('\u2502' + '=' * 200 + '\u2502\r\n').encode('utf-8'))
    parts.append(b'tail marker line >>\r\n')
    return b''.join(parts)


def _art():
    art = r"""
   ____                           _______                    _             _
  / ___|  ___  ___ _   _ _ __ ___|_   _|__ _ __ _ __ ___ (_)_ __   __ _| |
  \___ \ / _ \/ __| | | | '__/ _ \ | |/ _ \ '__| '_ ` _ \| | '_ \ / _` | |
   ___) |  __/ (__| |_| | | |  __/ | |  __/ |  | | | | | | | | | | (_| | |
  |____/ \___|\___|\__,_|_|  \___| |_|\___|_|  |_| |_| |_|_|_| |_|\__,_|_|
                                                                tail >>
"""
    return art.replace('\n', '\r\n').encode('utf-8')


def _exact_grid():
    # Lines at a spread of exact widths (incl. widths equal to common grid sizes) each
    # ended by a bare LF -- the classic pyte last-col wrap-pending + LF double-advance
    # that produced a spurious blank row. Every width here must render with NO extra
    # blank line between it and the next.
    out = []
    for w in (40, 79, 80, 81, 100, 117, 118, 119, 120):
        out.append(('#%d ' % w).ljust(w, 'x'))
        out.append('\r\n')
    out.append('tail marker >>\r\n')
    return ''.join(out).encode('utf-8')


def _trailing_ws():
    # Content followed by long trailing whitespace runs, then more content -- probes
    # "empty space" handling (trailing spaces must not become blank rows or shove the
    # tail off screen).
    out = []
    for i in range(6):
        out.append('row %d content' % i + ' ' * 80 + '\r\n')
    out.append('tail marker >>\r\n')
    return ''.join(out).encode('utf-8')


def _altscreen_short():
    # A SHORT alt-screen frame: enter alt screen, draw two lines at the top, leave the
    # rest blank. TUI must pin row 0 to the top (a short alt frame must not scroll off).
    seq = ('\x1b[?1049h'          # enter alt screen
           '\x1b[2J\x1b[H'        # clear + home
           'ALT SCREEN TOP LINE >>\r\n'
           'second line of the short alt frame\r\n')
    return seq.encode('utf-8')


def _wide_cjk():
    # Wide CJK + emoji interleaved with ASCII: width handling as the font scales.
    line1 = 'ASCII \u4f60\u597d\u4e16\u754c CJK mix \u65e5\u672c\u8a9e end\r\n'
    line2 = 'emoji \U0001f600 \U0001f680 \U0001f512 between ascii words\r\n'
    line3 = 'M' * 40 + ' ' + '\u5e45' * 20 + ' tail >>\r\n'
    return (line1 + line2 + line3).encode('utf-8')


# name -> (bytes, spec). spec keys: dense (bool -- should fill the screen, so a near-empty
# render is the blank-screen artifact), tui_altscreen (bool -- its TUI form legitimately
# leaves the lower viewport blank, a top-pinned alt frame, so the dense/ink check is
# skipped there).
BOARDS = {
    'tui-showcase': (_tui_showcase(), {}),
    'colorgrad': (_colorgrad(), {'dense': True}),
    'longline-box': (_longline_box(), {}),
    'art': (_art(), {}),
    'exact-grid': (_exact_grid(), {}),
    'trailing-ws': (_trailing_ws(), {}),
    'altscreen-short': (_altscreen_short(), {'tui_altscreen': True}),
    'wide-cjk': (_wide_cjk(), {}),
}


def board_spec(name):
    _bytes, spec = BOARDS[name]
    return {
        'dense': spec.get('dense', False),
        'tui_altscreen': spec.get('tui_altscreen', False),
    }


def board_bytes(name):
    return BOARDS[name][0]


def main(argv):
    if len(argv) != 2 or argv[1] not in BOARDS:
        sys.stderr.write('usage: zoom_boards.py <board>   (one of: %s)\n'
                         % ', '.join(sorted(BOARDS)))
        return 2
    sys.stdout.buffer.write(board_bytes(argv[1]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
