#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Render a short, realistic session for the site's hero image, headless.

The REAL renderer (secure_terminal.terminal.SecureTerminal in preview mode) in the
default display mode, showing what a reader actually gets: ordinary output that
looks ordinary, next to a hostile filename that cannot pretend to be ordinary.

Scope, so the figure caption can be honest: this is the terminal's DISPLAY, not a
window screenshot -- there is no title bar, tab strip or toolbar here. It is
deterministic and needs no display server, which a window capture would.

    PYTHONPATH=<secure-terminal>/usr/lib/python3/dist-packages \
        usr/share/secure-terminal-shots/hero-shot.py <output.png>

Usually driven via the `secure-terminal-shots` wrapper (this dir).

The payload is written with \\u escapes so this source stays plain ASCII; the
hidden characters live only in the rendered image.
"""

import os
import sys

# A headless grab needs no real display; force the offscreen platform before Qt
# initialises, unless the caller already chose one.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

# HiDPI: render at SHOT_SCALE x device pixels (default 2) so the shot stays crisp when a
# browser upscales it on a HiDPI display -- the site shows it at 1x via CSS, matching the
# 2x-source convention the rest of the site uses. This is a single grab (no composition),
# so QT_SCALE_FACTOR alone gives a SHOT_SCALE x image. Assign, do not setdefault: Qt reads
# it at QApplication construction, so the shot must pin its own factor over any inherited one.
## Parse via int(), not str.isdigit(): isdigit() accepts unicode digits (superscripts etc.)
## that int() then rejects, which would crash at import.
try:
    _shot_scale = int(os.environ.get('SHOT_SCALE', '2'))
except (TypeError, ValueError):
    _shot_scale = 2
if _shot_scale < 1:
    _shot_scale = 2
os.environ['QT_SCALE_FACTOR'] = str(_shot_scale)

from PyQt6.QtWidgets import QApplication                          # noqa: E402
from PyQt6.QtCore import Qt                                       # noqa: E402

from secure_terminal.terminal import SecureTerminal               # noqa: E402

ScrollBarPolicy = Qt.ScrollBarPolicy

# A believable few seconds of work. Ordinary lines stay ordinary -- that is half
# the point, since a terminal that mangles normal output is not usable. The two
# lies are a Cyrillic look-alike in a filename (U+0430) and a right-to-left
# override in a second one, each collapsing to one risk-coloured placeholder.
PAYLOAD = (
    '$ ls ~/Downloads\n'
    'installer.sh   invoice\u0430.pdf\n'
    'report\u202efdp.txt   notes.md\n'
    '$ head -2 deploy.log\n'
    'deploy: starting\n'
    'deploy: OK\n'
    '$ '
)

# Narrow on purpose: the site scales the hero to the viewport, and a wide
# 80-column capture squeezed into ~360px on a phone is unreadable.
WIDTH = 560
INSET = 8
MIN_H = 160


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write('usage: hero-shot.py <output.png>\n')
        return 2
    out_path = argv[0]

    # Kept in a local so the application object outlives the grab.
    app = QApplication.instance() or QApplication([])
    assert app is not None

    view = SecureTerminal(preview=True)
    view.setFixedWidth(WIDTH)
    view.setVerticalScrollBarPolicy(ScrollBarPolicy.ScrollBarAlwaysOff)
    view.setHorizontalScrollBarPolicy(ScrollBarPolicy.ScrollBarAlwaysOff)
    view.setFixedHeight(MIN_H)
    # The DEFAULT mode is detail (unicode_mode=detail), not box -- a hero captioned
    # "the default display" has to actually be it.
    view.render_preview(PAYLOAD, mode='detail', markings=True)
    QApplication.processEvents()

    # Size from wrapped rows using the widget's own metrics; see the note in
    # display-modes-shot.py for why the obvious Qt measurements do not work here.
    metrics = view.fontMetrics()
    usable = WIDTH - 2 * INSET - 4
    rows = 0
    for line in view.toPlainText().split('\n'):
        rows += max(1, -(-metrics.horizontalAdvance(line) // usable))
    view.setFixedHeight(max(MIN_H, rows * metrics.lineSpacing() + 2 * INSET))
    QApplication.processEvents()

    image = view.grab().toImage()
    image.setDevicePixelRatio(1.0)   # write raw device pixels, no DPR metadata
    if not image.save(out_path, 'PNG'):
        sys.stderr.write('hero-shot: could not write %s\n' % out_path)
        return 1
    print('hero-shot: wrote %s (%dx%d)'
          % (out_path, image.width(), image.height()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
