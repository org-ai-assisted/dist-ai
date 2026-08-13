#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Own the X CLIPBOARD selection and hold it, for clipboard-verdict.sh.

Set the clipboard to the single text argument, then block in the Qt event loop so
this process keeps SELECTION ownership until it is killed. X selection ownership
is live -- the seeded value only survives while an owner stays alive, which is why
this holds rather than exits.

The caller exports QT_QPA_PLATFORM=xcb so Qt talks to the real X server; the
clipboard lane measures a real X selection, not an offscreen one. No xclip: PyQt6
talks to the X CLIPBOARD selection directly.

    QT_QPA_PLATFORM=xcb clipboard-verdict-seed.py <text>
"""

import sys

from PyQt6.QtWidgets import QApplication


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write('usage: clipboard-verdict-seed.py <text>\n')
        return 2
    app = QApplication(sys.argv)
    app.clipboard().setText(argv[0])
    app.exec()   # hold the selection until killed
    return 0


if __name__ == '__main__':
    sys.exit(main())
