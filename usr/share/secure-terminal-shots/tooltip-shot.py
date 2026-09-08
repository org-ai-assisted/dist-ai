#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Render the InfoTip -- secure-terminal's selectable, theme-aware risk-explanation
tooltip -- to a PNG, headless and deterministic.

The tip is the real one the app shows (secure_terminal.main.InfoTip): unlike a plain
QToolTip you can move the pointer INTO it to select and copy the text, its colours
follow the current theme and its font follows the zoom. It is fed an AUTHENTIC risk
explanation -- the OSC 52 "System clipboard (write)" feature help from OSC_FEATURES --
so the shot shows exactly the wording a user reads in Global Settings / the OSC menu.
It floats on the terminal background, as it does over a real tab.

No display is needed: it uses Qt's offscreen platform and grab().

    PYTHONPATH=<secure-terminal>/usr/lib/python3/dist-packages \\
        usr/share/secure-terminal-shots/tooltip-shot.py <output.png> [dark|light]

Usually driven via the `secure-terminal-shots` wrapper (this dir).
"""

import os
import sys

# A headless grab needs no real display; force the offscreen platform before Qt
# initialises, unless the caller already chose one.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

# HiDPI: render at SHOT_SCALE x device pixels (default 2) so the published shot stays
# crisp when a browser upscales it -- the site shows it at 1x via CSS, matching the
# 2x-source convention the other shots use.
## Parse via int(): isdigit() accepts unicode digits int() then rejects.
try:
    SHOT_SCALE = int(os.environ.get('SHOT_SCALE', '2'))
except (TypeError, ValueError):
    SHOT_SCALE = 2
if SHOT_SCALE < 1:
    SHOT_SCALE = 2
## Assign, do not setdefault: Qt reads QT_SCALE_FACTOR at QApplication construction.
os.environ['QT_SCALE_FACTOR'] = str(SHOT_SCALE)

from PyQt6.QtWidgets import QApplication, QWidget            # noqa: E402
from PyQt6.QtGui import QImage, QPainter, QColor             # noqa: E402
from PyQt6.QtCore import QPoint, Qt                          # noqa: E402

from secure_terminal.main import InfoTip, _TIP_COLORS        # noqa: E402
from secure_terminal.sanitize import THEMES, OSC_FEATURES    # noqa: E402

MARGIN = 16 * SHOT_SCALE

# An authentic tip body: the OSC 52 clipboard-WRITE feature's own risk help (the text a
# user sees on that row), so the shot never invents wording. Look it up by key so a
# reword of the feature help flows into the shot on the next regen.
_FEATURES = {feature[0]: feature for feature in OSC_FEATURES}
_CLIP = _FEATURES['osc_clipboard']
TIP_TEXT = '%s  (OSC %s)\n\n%s' % (_CLIP[1], _CLIP[2], _CLIP[5])


def _render(app, theme):
    """Render the InfoTip card into an image. An offscreen grab() drops a child QLabel's
    styled background (only the text survives), but a HOST QWidget's stylesheet background
    DOES paint -- so the host is made the card (the same _TIP_COLORS bg / border / 8px radius
    _apply_palette uses), and the real InfoTip rides inside it painting only its (real,
    wrapped, zoom-aware) TEXT on a transparent background. The card is then framed by a
    terminal-background margin, so it reads as the tip floating over a tab."""
    card_bg, card_fg, card_border = _TIP_COLORS['dark' if theme == 'dark' else 'light']
    host = QWidget()
    host.setStyleSheet('QWidget{background:%s;border:1px solid %s;border-radius:8px}'
                       % (card_bg, card_border))
    tip = InfoTip(host)
    tip.setWindowFlags(Qt.WindowType.Widget)            # a child, not a top-level Tool window
    tip.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
    # only the TEXT -- transparent so the host card shows through; padding matches the tip's.
    tip.setStyleSheet('QLabel{color:%s;background:transparent;padding:8px 11px}' % card_fg)
    tip.setMaximumWidth(340)                            # the width cap that drives the wrap
    tip.setText(TIP_TEXT)
    tip.adjustSize()
    tip.resize(tip.width(), tip.heightForWidth(tip.width()))   # the app's wrapped-height fix
    tip.move(0, 0)
    host.setFixedSize(tip.width(), tip.height())
    host.show()
    app.processEvents()
    grab = host.grab().toImage().convertToFormat(QImage.Format.Format_ARGB32)
    # host.grab() bakes the HiDPI factor into the pixels AND stamps devicePixelRatio=SHOT_SCALE,
    # so drawImage would place it at its LOGICAL (1x) size and leave a big apron. Clear the
    # ratio so the full 2x pixel card composites 1:1 -- a crisp HiDPI shot, tight to the card.
    grab.setDevicePixelRatio(1.0)
    return _frame(grab, QColor(THEMES[theme][0]))


def _frame(card, bg):
    """Centre the card on a terminal-background canvas with a uniform MARGIN all round."""
    canvas = QImage(card.width() + 2 * MARGIN, card.height() + 2 * MARGIN,
                    QImage.Format.Format_ARGB32)
    canvas.fill(bg)
    painter = QPainter(canvas)
    painter.drawImage(QPoint(MARGIN, MARGIN), card)
    painter.end()
    return canvas


def main(argv):
    if not 2 <= len(argv) <= 3 or (len(argv) == 3 and argv[2] not in ('dark', 'light')):
        sys.stderr.write('usage: %s <output.png> [dark|light]\n' % argv[0])
        return 2
    out = argv[1]
    theme = argv[2] if len(argv) == 3 else 'light'   # match the other site shots (light)

    app = QApplication([argv[0], '-platform', os.environ['QT_QPA_PLATFORM']])
    image = _render(app, theme)
    if not image.save(out, 'PNG'):
        sys.stderr.write('failed to write %s\n' % out)
        return 1
    sys.stderr.write('wrote %s (%dx%d)\n' % (out, image.width(), image.height()))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
