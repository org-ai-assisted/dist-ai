#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression helper for shot_generators_smoke_test.sh: the paste/copy review shots must
## SHOW the unicode-revealing render -- the editable box, opened in the keep-printable form,
## must NAME each hidden look-alike inline (detail mode) so the shot demonstrates the very
## unicode detection it exists to show. CANARY: break the box's revealing render in
## build_review (e.g. strip the look-alikes, or a non-detail mode) and this fails (the box
## names no hidden character).
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

    app = QApplication.instance() or QApplication(['paste-warning-check'])
    assert app is not None

    failures = 0
    for kind in ('paste', 'copy'):
        host = QWidget()
        bar = mod.build_review(host, kind, mod.COUNTDOWN_SECONDS if kind == 'paste' else 0)
        app.processEvents()
        text = bar._editor.toPlainText()
        # the keep-printable box still carries the look-alike, so the detail render
        # NAMES it -- the unicode the shot exists to reveal.
        if 'CYRILLIC SMALL LETTER A' not in text:
            sys.stderr.write('FAIL: %s shot box does not name the hidden look-alike '
                             '(shows: %r)\n' % (kind, text[:120]))
            failures += 1
    if failures:
        return 1
    print('ok: paste/copy shot boxes show the unicode render')
    return 0


if __name__ == '__main__':
    sys.exit(main())
