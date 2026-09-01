#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression helper for shot_generators_smoke_test.sh: the paste/copy review shots must
## SHOW the unicode-revealing render, not the radio-first "choose a mode" hint. The review
## bar is radio-first -- with no delivery mode picked the mirror shows only the hint -- so a
## generator that forgets to pick a mode produces a shot whose mirror hides the very unicode
## detection it exists to demonstrate (the exact bug this guards). CANARY: drop the
## bar._on_radio(DELIVERY_MODE) call in build_review and this fails (the mirror shows the
## hint, and names no hidden character).
##
## Usage: paste_warning_unicode_check.py <paste-warning-shot.py path>

import importlib.util
import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


def main():
    if len(sys.argv) != 2:
        sys.stderr.write('usage: paste_warning_unicode_check.py <generator>\n')
        return 2
    spec = importlib.util.spec_from_file_location('paste_warning_shot', sys.argv[1])
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    from PyQt6.QtWidgets import QApplication, QWidget
    from secure_terminal.review import _MIRROR_HINT

    app = QApplication.instance() or QApplication(['paste-warning-check'])
    assert app is not None

    failures = 0
    for kind in ('paste', 'copy'):
        host = QWidget()
        bar = mod.build_review(host, kind, mod.COUNTDOWN_SECONDS if kind == 'paste' else 0)
        app.processEvents()
        text = bar._mirror.toPlainText()
        # the delivered "keep unicode" form still carries the look-alike, so the detail
        # render NAMES it -- the unicode the shot exists to reveal.
        if 'CYRILLIC SMALL LETTER A' not in text:
            sys.stderr.write('FAIL: %s shot mirror does not name the hidden look-alike '
                             '(shows: %r)\n' % (kind, text[:120]))
            failures += 1
        # and it must NOT be the "pick a mode" hint (the pre-fix bug).
        if _MIRROR_HINT in text:
            sys.stderr.write('FAIL: %s shot mirror shows the "choose a mode" hint, not the '
                             'delivered render\n' % kind)
            failures += 1
    if failures:
        return 1
    print('ok: paste/copy shot mirrors show the unicode render (not the hint)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
