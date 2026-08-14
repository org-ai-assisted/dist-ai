#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Read the X CLIPBOARD selection once and write it to stdout, for clipboard-verdict.sh.

One-shot: create a Qt application on the real X server (the caller exports
QT_QPA_PLATFORM=xcb), write the current clipboard text with NO trailing newline,
and exit. clipboard-verdict.sh compares the exact bytes read back against the
sentinel and the canary token, so nothing is added around the value. No xclip:
PyQt6 talks to the X CLIPBOARD selection directly.

    QT_QPA_PLATFORM=xcb clipboard-verdict-read.py
"""

import sys

from PyQt6.QtWidgets import QApplication


def main():
    app = QApplication(sys.argv)
    sys.stdout.write(app.clipboard().text())
    return 0


if __name__ == '__main__':
    sys.exit(main())
