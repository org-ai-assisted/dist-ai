#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Render the four unicode display modes side by side, headless and deterministic.

ONE hostile payload, rendered four times by the REAL renderer
(secure_terminal.terminal.SecureTerminal in preview mode, the same path the paste
review panes use), then composed into a single labelled image. A static grid, not
an animation: the point is to compare the four renderings at once, which is what a
reader actually wants -- and unlike a GIF it is legible, pausable, diffable and
regenerable byte-for-byte.

This is also the honest answer to "is it ASCII only?". The four panels SHOW the
real handling instead of asserting it:
  - Box     every neutralized byte becomes one inert placeholder; the risk class
            is carried by colour, so a look-alike is louder than honest text.
  - Show    printable non-ASCII is kept as itself (the documented opt-in), while
            the invisible/bidi/control classes still collapse to a placeholder.
  - Reveal  each hidden character is named inline as <U+XXXX>.
  - Detail  the same, plus the Unicode NAME, so the reader needs no lookup.
            This is the DEFAULT mode (unicode_mode=detail).

No display is needed: Qt's offscreen platform plus grab(). Composition uses
QPainter, so this adds no dependency beyond the PyQt6 the app already needs.

    PYTHONPATH=<secure-terminal>/usr/lib/python3/dist-packages \
        usr/share/secure-terminal-shots/display-modes-shot.py <output.png>

Usually driven via the `secure-terminal-shots` wrapper (this dir).

The payload is written with \\u escapes so this source stays plain ASCII; the
hidden characters live only in the rendered image.
"""

import os
import sys

# A headless grab needs no real display; force the offscreen platform before Qt
# initialises, unless the caller already chose one.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PyQt6.QtWidgets import QApplication                          # noqa: E402
from PyQt6.QtGui import QColor, QFont, QImage, QPainter           # noqa: E402
from PyQt6.QtCore import Qt                                       # noqa: E402

ScrollBarPolicy = Qt.ScrollBarPolicy

from secure_terminal.terminal import SecureTerminal, THEMES       # noqa: E402

# Compose on the app's shipped default theme so the grid never drifts from what
# users see. Colours come from THEMES; only THEME_NAME needs touching if the
# app's default theme changes again. (The panels already use the live default.)
THEME_NAME = 'light'

# An `ls` listing where four of the five names are lying, so every class the modes
# treat differently is present at once:
#   report<RLO>fdp.txt   a right-to-left override (U+202E) reorders the extension
#   invoice<U+0430>.pdf  Cyrillic 'a' impersonating ASCII 'a'
#   notes<U+200B>.txt    a zero-width space splits the name
#   r<U+00E9>sum<U+00E9>.pdf  HONEST printable non-ASCII -- must stay readable in Show
#   <U+4E2D><U+6587>.txt     honest CJK -- likewise
PAYLOAD = (
    '$ ls\n'
    'report\u202efdp.txt   invoice\u0430.pdf   notes\u200b.txt\n'
    'r\u00e9sum\u00e9.pdf     \u4e2d\u6587.txt\n'
)

MODES = (
    ('box', 'Box -- every neutralized byte is one inert placeholder'),
    ('show', 'Show -- printable non-ASCII kept as itself; invisibles still marked'),
    ('reveal', 'Reveal -- each hidden character named inline as <U+XXXX>'),
    ('detail', 'Detail (the default) -- the same, plus the Unicode NAME'),
)

PANEL_W = 760
PANEL_MIN_H = 76
PANEL_INSET = 8
LABEL_H = 30
PAD = 16


def panel_image(mode):
    """A grab of the real renderer showing PAYLOAD under `mode`.

    Height follows the rendered document: Detail expands every hidden character to
    a full Unicode NAME and wraps to about twice the lines Box needs, so a single
    fixed height either clips it or leaves the others mostly empty.
    """
    view = SecureTerminal(preview=True)
    view.setFixedWidth(PANEL_W)
    # A preview pane is not scrollable by the reader, and an empty scrollbar
    # gutter in a published figure just reads as a rendering artefact.
    view.setVerticalScrollBarPolicy(ScrollBarPolicy.ScrollBarAlwaysOff)
    view.setHorizontalScrollBarPolicy(ScrollBarPolicy.ScrollBarAlwaysOff)
    view.setFixedHeight(PANEL_MIN_H)
    view.render_preview(PAYLOAD, mode=mode, markings=True)
    QApplication.processEvents()
    # Size from the rendered text, measured with the widget's own metrics.
    # Neither Qt measurement shortcut works here: document().size().height() is in
    # LINES for a QPlainTextEdit, lineCount() under-counts wrapped visual lines
    # (which silently clipped Detail), and the scrollbar range never settles once
    # the bars are forced off. Counting wrapped rows is deterministic.
    metrics = view.fontMetrics()
    usable = PANEL_W - 2 * PANEL_INSET - 4
    rows = 0
    for line in view.toPlainText().split('\n'):
        width = metrics.horizontalAdvance(line)
        rows += max(1, -(-width // usable))        # ceil division
    needed = rows * metrics.lineSpacing() + 2 * PANEL_INSET
    view.setFixedHeight(max(PANEL_MIN_H, needed))
    QApplication.processEvents()
    return view.grab().toImage()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write('usage: display-modes-shot.py <output.png>\n')
        return 2
    out_path = argv[0]

    # Kept in a local so the application object outlives the grabs.
    app = QApplication.instance() or QApplication([])
    assert app is not None

    panels = [(panel_image(mode), caption) for mode, caption in MODES]

    total_h = PAD + sum(LABEL_H + img.height() + PAD for img, _ in panels)
    canvas = QImage(PANEL_W + 2 * PAD, total_h, QImage.Format.Format_RGB32)
    # Compose on the app theme's background (THEMES = source of truth) so the grid
    # sits on the site without a seam and tracks the default theme automatically.
    bg, fg = THEMES[THEME_NAME]
    light = QColor(bg).lightnessF() >= 0.5
    hairline = QColor(bg).darker(118) if light else QColor(bg).lighter(150)
    canvas.fill(QColor(bg))

    painter = QPainter(canvas)
    label_font = QFont('DejaVu Sans', 10)
    label_font.setBold(True)
    painter.setFont(label_font)

    y = PAD
    for image, caption in panels:
        painter.setPen(QColor(fg))
        painter.drawText(PAD, y + LABEL_H - 10, caption)
        y += LABEL_H
        painter.drawImage(PAD, y, image)
        # A hairline so each panel reads as its own terminal, not one long block.
        painter.setPen(hairline)
        painter.drawRect(PAD, y, image.width() - 1, image.height() - 1)
        y += image.height() + PAD
    painter.end()

    if not canvas.save(out_path, 'PNG'):
        sys.stderr.write('display-modes-shot: could not write %s\n' % out_path)
        return 1
    print('display-modes-shot: wrote %s (%dx%d)'
          % (out_path, canvas.width(), canvas.height()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
