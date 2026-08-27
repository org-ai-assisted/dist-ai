#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Sweep the font-zoom levels and grab the LIVE TUI grid at each, headless and
deterministic, to expose a mid-screen "white band" (a blank horizontal strip)
in the grid when it is full of content.

Unlike display-modes-shot.py (which grabs the paste-REVIEW preview path,
SecureTerminal(preview=True) + render_preview), this drives the LIVE grid --
SecureTerminal(command='/bin/cat', tui=True) -- because the band under
investigation lives in the live grid sizing: _tui_grid_size()/_grid_size()
compute the row count as viewport_height // QFontMetrics.height(), while
QPlainTextEdit lays each block out at QFontMetrics.lineSpacing() (= height +
leading). If leading were > 0 the two would disagree and a partial row of Base
colour could appear. The full-screen box-drawing board makes any such strip
glaring; a fixed viewport is fed more rows than fit, so the grid is always full.

No display is needed: Qt's offscreen platform plus grab(). The child is
'/bin/cat' (silent with no input); the payload is fed straight into the pyte
stream (_feed_bytes) and rendered with _render_tui(), so the frame is
synchronous and byte-reproducible -- no pty timing, no compositor settle.

Outputs, into OUTPUT_DIR (argv[1]):
  zoom-<pct>.png        one full grab per level
  zoom-band-contact.png one labelled contact sheet of all levels side by side
Also prints, for each level, QFontMetrics height() vs lineSpacing() for Hack at
that point size and the viewport remainder (viewport_h mod lineSpacing), plus a
BAND verdict from scanning each grab for a long run of background rows.

    PYTHONPATH=<secure-terminal>/usr/lib/python3/dist-packages \
        usr/share/secure-terminal-shots/zoom-shot.py <output-dir> [LEVELS...]

Levels default to 50 75 100 125 150 175 200; override with the ZOOM_LEVELS env
var (space separated) or extra positional args. Usually driven via the
`secure-terminal-shots zoom` wrapper (this dir).

The box-drawing board is written with \\u escapes so this source stays ASCII;
the frame characters live only in the rendered image.
"""

import os
import sys

# A headless grab needs no real display; force offscreen before Qt initialises.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
# Pin the font DPI so a point size maps to the SAME pixel height every run,
# independent of the host's screen DPI -- the whole point is a deterministic grid.
os.environ.setdefault('QT_FONT_DPI', '72')
# Deterministic render mode (hidden caret, synchronous paint), like the other shots.
os.environ.setdefault('SECURE_TERMINAL_SHOT', '1')

## Parse via int(), not str.isdigit(): isdigit() accepts unicode digits that int()
## then rejects, which would crash at import.
try:
    SHOT_SCALE = int(os.environ.get('SHOT_SCALE', '2'))
except (TypeError, ValueError):
    SHOT_SCALE = 2
if SHOT_SCALE < 1:
    SHOT_SCALE = 2
## Assign, not setdefault: Qt reads QT_SCALE_FACTOR at QApplication construction,
## so an inherited value would desync the grab scale from the composition below.
os.environ['QT_SCALE_FACTOR'] = str(SHOT_SCALE)

from PyQt6.QtWidgets import QApplication                          # noqa: E402
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QImage, QPainter  # noqa: E402
from PyQt6.QtCore import Qt                                       # noqa: E402

from secure_terminal.terminal import (                           # noqa: E402
    SecureTerminal, THEMES, BASE_POINT_SIZE, FONT_SIZE_MIN, FONT_SIZE_MAX)

# Render on the app's shipped default theme so the grid never drifts from what
# users see; a white band is a Base-colour strip on this light background.
THEME_NAME = 'light'

DEFAULT_LEVELS = (50, 75, 100, 125, 150, 175, 200)

# A fixed LOGICAL viewport. The grab is this x SHOT_SCALE device pixels.
VIEW_W = 1000
VIEW_H = 760

# The full-height vertical bar, written as a \u escape so this source stays ASCII;
# the frame character lives only in the rendered board.
_V = '\u2502'      # BOX DRAWINGS LIGHT VERTICAL


def point_size(zoom):
    """The applied point size at this zoom (mirrors terminal._apply_font)."""
    return max(FONT_SIZE_MIN, min(FONT_SIZE_MAX, round(BASE_POINT_SIZE * zoom / 100.0)))


def board_bytes(width, nrows):
    """A full-screen board of box-drawing columns + text, sized to the live grid:
    every line is EXACTLY `width` columns and there are `nrows` of them, so pyte
    neither wraps a line (a short wrap fragment would leave a legitimately blank
    tail -- a false band) nor leaves the grid short. CR+LF because we feed pyte
    directly, bypassing the pty's ONLCR.

    Every row is UNIFORM and DENSE: a full-height vertical bar every 12 columns,
    'x' between them, a row-number gutter on the left. The vertical bars run
    unbroken DOWN each column (the glyph fills the whole cell height), so the only
    way a horizontal strip of pure background can appear is a genuinely blank grid
    row -- a mid-screen white band then cuts every vertical bar at once, glaring to
    the eye and unambiguous to the background-row scan."""
    lines = []
    for i in range(1, nrows + 1):
        body = ''.join(_V if c % 12 == 0 else 'x' for c in range(width))
        label = '%s row %04d ' % (_V, i)
        line = label + body[len(label):]
        lines.append(line[:width])
    return ('\r\n'.join(lines) + '\r\n').encode('utf-8')


def grab_level(app, zoom):
    """Grab the live TUI grid at `zoom`. Returns (image, cols, rows, viewport_h)."""
    term = SecureTerminal(command=['/bin/cat'], tui=True, mode='show',
                          theme=THEME_NAME)
    # Size, then show + settle: the grid rows come from the widget's REAL viewport
    # height, which is only correct once the fixed size has been laid out. Without
    # the show()+processEvents the first _tui_grid_size reads a stale viewport and
    # the grid under-fills (a false band).
    term.setFixedSize(VIEW_W, VIEW_H)
    term.show()
    app.processEvents()
    # Apply the zoom (a single call applies the font on the leading edge) and let
    # the font relayout + pyte resize settle before feeding.
    term.apply_zoom(zoom)
    app.processEvents()
    term._sync_tui_size()
    app.processEvents()
    cols = term._screen.columns
    rows = term._screen.lines
    # Build the board sized to THIS grid: exactly `cols` wide (no wrap) and more
    # than `rows` lines (so the grid is full and shows the tail), then feed + render.
    term._feed_bytes(board_bytes(cols, rows + 60))
    term._render_tui()
    app.processEvents()
    vh = term.viewport().height()
    img = term.grab().toImage()
    # Compose in RAW device pixels: pin DPR=1 so QPainter draws the grab at full
    # physical size (under QT_SCALE_FACTOR the grab can carry DPR>1).
    img.setDevicePixelRatio(1.0)
    # Release the child pty and widget before the next level.
    if term._fd is not None:
        try:
            os.close(term._fd)
        except OSError:
            pass
        term._fd = None
    term.deleteLater()
    app.processEvents()
    return img, cols, rows, vh


def longest_bg_run(img, gutter_px):
    """Longest run of EMPTY rows bounded by DENSE content rows both above and
    below -- i.e. a genuine mid-screen strip. Per row we take the fraction of
    dark samples across the width (past the left gutter). A row is EMPTY when that
    fraction is under 2%, DENSE when it is over 25%. A box-drawing "rule" row is
    sparse (a thin stroke plus ticks) so it is NEITHER -- it does not read as a
    band, and it does not close one. The trailing background below the last dense
    row (the sub-line bottom remainder plus a lone cursor fragment) has no dense
    row below it, so it is excluded. Returns (run_px, start_y)."""
    w, h = img.width(), img.height()
    xs = list(range(gutter_px, w, 4))
    n = max(1, len(xs))
    frac = []
    for y in range(h):
        dark = 0
        for x in xs:
            if img.pixelColor(x, y).lightnessF() < 0.6:
                dark += 1
        frac.append(dark / n)
    EMPTY, DENSE = 0.02, 0.25
    best = best_start = 0
    y = 0
    while y < h:
        if frac[y] < EMPTY:
            start = y
            while y < h and frac[y] < EMPTY:
                y += 1
            run = y - start
            above = any(frac[k] >= DENSE for k in range(max(0, start - 3), start))
            below = any(frac[k] >= DENSE for k in range(y, min(h, y + 3)))
            if above and below and run > best:
                best, best_start = run, start
        else:
            y += 1
    return best, best_start


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write('usage: zoom-shot.py <output-dir> [LEVELS...]\n')
        return 2
    out_dir = argv[0]
    rest = argv[1:]
    if rest:
        levels = [int(x) for x in rest]
    elif os.environ.get('ZOOM_LEVELS'):
        levels = [int(x) for x in os.environ['ZOOM_LEVELS'].split()]
    else:
        levels = list(DEFAULT_LEVELS)
    if not levels:
        sys.stderr.write('zoom-shot: no zoom levels to sweep '
                         '(ZOOM_LEVELS empty?)\n')
        return 2
    os.makedirs(out_dir, exist_ok=True)

    # Kept in a local so the application object outlives the grabs.
    app = QApplication.instance() or QApplication([])
    assert app is not None

    print('== QFontMetrics Hack @ QT_FONT_DPI=%s =='
          % os.environ.get('QT_FONT_DPI'))
    print('zoom  pt  height  lineSpacing  leading')
    for z in levels:
        pt = point_size(z)
        f = QFont('Hack')
        f.setFixedPitch(True)
        f.setPointSize(pt)
        fm = QFontMetrics(f)
        print('%4d  %2d  %6d  %11d  %7d'
              % (z, pt, fm.height(), fm.lineSpacing(), fm.leading()))

    print('\n== live TUI-grid grabs ==')
    panels = []
    any_band = False
    mech_ok = True     # the band mechanism needs leading>0 OR a >=1-line remainder
    for z in levels:
        img, cols, rows, vh = grab_level(app, z)
        pt = point_size(z)
        f = QFont('Hack')
        f.setFixedPitch(True)
        f.setPointSize(pt)
        fm = QFontMetrics(f)
        ls, lead = fm.lineSpacing(), fm.leading()
        out = os.path.join(out_dir, 'zoom-%03d.png' % z)
        if not img.save(out, 'PNG'):
            sys.stderr.write('zoom-shot: could not write %s\n' % out)
            return 1
        gutter_px = 60 * SHOT_SCALE
        run_px, run_y = longest_bg_run(img, gutter_px)
        # A genuine strip is at least one full grid row of emptiness bounded by
        # dense content above and below (longest_bg_run already enforces the
        # bounding); a sub-line gap between text rows is smaller than one line.
        band = run_px >= ls * SHOT_SCALE
        any_band = any_band or band
        rem = vh - rows * ls
        # The partial-row mechanism can only bite if lineSpacing != height, i.e.
        # leading > 0. (The remainder here is dominated by the document margin, not
        # an unfilled partial row, so it is reported but does not drive the verdict.)
        if lead != 0:
            mech_ok = False
        print('zoom=%3d pt=%2d grid=%dx%d img=%dx%d viewport_h=%d '
              'rows*lineSpacing=%d remainder=%d leading=%d  '
              'longest_interior_empty_run=%dpx@y=%d  BAND=%s  -> %s'
              % (z, pt, cols, rows, img.width(), img.height(), vh,
                 rows * ls, rem, lead, run_px, run_y,
                 'YES' if band else 'no', out))
        panels.append((img, z, pt, cols, rows, rem, band))

    contact = compose_contact(panels)
    contact_path = os.path.join(out_dir, 'zoom-band-contact.png')
    if not contact.save(contact_path, 'PNG'):
        sys.stderr.write('zoom-shot: could not write %s\n' % contact_path)
        return 1
    print('\ncontact sheet: %s (%dx%d)'
          % (contact_path, contact.width(), contact.height()))
    print('MECHANISM: leading==0 at every level -> lineSpacing==height, so the '
          'row count (viewport//height) fills the viewport exactly: %s'
          % ('HOLDS (no partial-row band possible)' if mech_ok else
             'DOES NOT HOLD -- a partial-row band is possible here'))
    print('VERDICT: %s'
          % ('a mid-grid white band WAS found at one or more levels'
             if any_band else
             'NO mid-grid white band at any level (grid fills the viewport; '
             'only a sub-line bottom remainder)'))
    return 0


def compose_contact(panels):
    """One labelled sheet: each level scaled to a fixed-width thumbnail in a
    single column, captioned with zoom%, point size, grid, remainder and the band
    verdict, so a white strip in any level is visible at a glance and comparable."""
    bg, fg = THEMES[THEME_NAME]
    pad = 12 * SHOT_SCALE
    label_h = 26 * SHOT_SCALE
    thumb_w = 900 * SHOT_SCALE // 2
    thumbs = []
    for img, z, pt, cols, rows, rem, band in panels:
        scaled = img.scaledToWidth(
            thumb_w, mode=Qt.TransformationMode.SmoothTransformation)
        caption = ('zoom %d%%  pt=%d  grid=%dx%d  remainder=%dpx  band=%s'
                   % (z, pt, cols, rows, rem, 'YES' if band else 'no'))
        thumbs.append((scaled, caption))
    total_h = pad + sum(label_h + t.height() + pad for t, _ in thumbs)
    canvas = QImage(thumb_w + 2 * pad, total_h, QImage.Format.Format_RGB32)
    canvas.fill(QColor(bg))
    light = QColor(bg).lightnessF() >= 0.5
    hairline = QColor(bg).darker(118) if light else QColor(bg).lighter(150)
    painter = QPainter(canvas)
    label_font = QFont('DejaVu Sans', 10 * SHOT_SCALE)
    label_font.setBold(True)
    painter.setFont(label_font)
    y = pad
    for thumb, caption in thumbs:
        painter.setPen(QColor(fg))
        painter.drawText(pad, y + label_h - 8 * SHOT_SCALE, caption)
        y += label_h
        painter.drawImage(pad, y, thumb)
        painter.setPen(hairline)
        painter.drawRect(pad, y, thumb.width() - 1, thumb.height() - 1)
        y += thumb.height() + pad
    painter.end()
    return canvas


if __name__ == '__main__':
    sys.exit(main())
