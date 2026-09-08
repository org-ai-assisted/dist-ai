#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Show the InfoTip -- secure-terminal's selectable, theme-aware risk-explanation tooltip
-- as a real top-level on the CURRENT Wayland compositor and keep it mapped, so an
external grim capture (tooltip-capture.sh) can trim to it. This is the SHOW half; the
capture + trim + webp is the orchestrator's job.

The tip is fed an AUTHENTIC risk explanation -- the OSC 52 "System clipboard (write)"
feature help from OSC_FEATURES -- so the shot shows exactly the wording a user reads in
Global Settings / the OSC menu.

A translucent top-level does not reliably paint a STYLESHEET background under the wayland
QPA (only the QLabel text renders over a transparent surface), so the card is drawn
EXPLICITLY in a paintEvent -- a rounded rect with the real _TIP_COLORS bg + 1px border,
radius + padding matching the app's InfoTip._apply_palette -- with the real InfoTip riding
inside it painting only its real (wrapped, zoom-aware) TEXT. Rendered by the real
compositor; the leave-poll is never started (a static shot must not auto-hide).

    WAYLAND_DISPLAY=... PYTHONPATH=<secure-terminal>/usr/lib/python3/dist-packages \\
        tooltip-shot.py [dark|light] [zoom]

Usually driven via tooltip-capture.sh (this dir), itself via the `secure-terminal-shots`
wrapper. Requires WAYLAND_DISPLAY (no offscreen); runs the event loop until SIGTERM.
"""

import os
import signal
import sys

if not os.environ.get('WAYLAND_DISPLAY'):
    sys.stderr.write('tooltip-shot: WAYLAND_DISPLAY unset; run under wl-headless '
                     '(via tooltip-capture.sh)\n')
    sys.exit(2)
# A native Wayland client; the compositor sets the scale, so no per-client QT_SCALE_FACTOR.
# FORCE wayland (not setdefault): a caller that runs the offscreen gens exports
# QT_QPA_PLATFORM=offscreen, and this shot cannot render its card offscreen -- it needs the
# real compositor (WAYLAND_DISPLAY is already asserted above).
os.environ['QT_QPA_PLATFORM'] = 'wayland'

from PyQt6.QtWidgets import QApplication, QWidget      # noqa: E402
from PyQt6.QtGui import QFont, QPainter, QColor, QPen  # noqa: E402
from PyQt6.QtCore import Qt, QRectF                    # noqa: E402

from secure_terminal.main import InfoTip, _TIP_COLORS  # noqa: E402
from secure_terminal.sanitize import OSC_FEATURES      # noqa: E402

# The tip's rounded-card radius + text padding, matching InfoTip._apply_palette.
RADIUS = 4.0
PADDING = '5px 9px'

# An authentic tip body: the OSC 52 clipboard-WRITE feature's own risk help (the text a
# user sees on that row), looked up by key so a reword of the feature help flows into the
# shot on the next regen.
_FEATURES = {feature[0]: feature for feature in OSC_FEATURES}
_CLIP = _FEATURES['osc_clipboard']
TIP_TEXT = '%s  (OSC %s)\n\n%s' % (_CLIP[1], _CLIP[2], _CLIP[5])


class _Card(QWidget):
    """A frameless top-level that PAINTS the tip's card (rounded bg + 1px border). The
    InfoTip's own translucent surface does not paint its stylesheet bg under the wayland
    QPA, so the card is drawn here and the InfoTip rides inside painting only its text."""

    def __init__(self, bg, border):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool
                            | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._bg = QColor(bg)
        self._border = QColor(border)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)   # crisp 1px border inset
        pen = QPen(self._border)
        pen.setWidthF(1.0)
        painter.setPen(pen)
        painter.setBrush(self._bg)
        painter.drawRoundedRect(rect, RADIUS, RADIUS)
        painter.end()


def main(argv):
    theme = argv[1] if len(argv) >= 2 and argv[1] in ('dark', 'light') else 'dark'
    try:
        zoom = int(argv[2]) if len(argv) >= 3 else 100
    except (TypeError, ValueError):
        zoom = 100

    app = QApplication([argv[0]])
    card_bg, card_fg, card_border = _TIP_COLORS['dark' if theme == 'dark' else 'light']
    host = _Card(card_bg, card_border)

    tip = InfoTip(host)
    tip.setWindowFlags(Qt.WindowType.Widget)            # a child, not a top-level Tool window
    tip.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
    # only the TEXT -- transparent so the host card shows through; padding matches the app's.
    tip.setStyleSheet('QLabel{color:%s;background:transparent;padding:%s}' % (card_fg, PADDING))
    tip.setMaximumWidth(340)                            # the width cap that drives the wrap
    tip.setText(TIP_TEXT)
    font = QFont()
    base = font.pointSizeF() if font.pointSizeF() > 0 else 10.0
    font.setPointSizeF(base * max(50, min(400, zoom)) / 100.0)
    tip.setFont(font)
    tip.adjustSize()
    # QLabel + wordWrap UNDER-computes its height once the text wraps at maximumWidth;
    # recompute the height the wrapped text actually needs so the whole tip is visible.
    tip.resize(tip.width(), tip.heightForWidth(tip.width()))
    tip.move(0, 0)
    host.setFixedSize(tip.width(), tip.height())
    host.show()
    app.processEvents()

    signal.signal(signal.SIGTERM, lambda *_a: app.quit())
    sys.stderr.write('tooltip-shot: mapped %dx%d theme=%s\n' % (host.width(), host.height(), theme))
    return app.exec()


if __name__ == '__main__':
    sys.exit(main(sys.argv))
