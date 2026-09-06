#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression helper for shot_generators_smoke_test.sh: the paste/copy review shots must
## not lay the bottom decision row (Reject / Deliver) OVER the "Outcome if delivered now"
## table. The breakdown is stacked HTML tables; a plain word-wrapped QLabel under-counts
## their height (heightForWidth AND sizeHint), so under the shot's host+show+adjustSize
## sizing the host is too short and the button row overlaps the last ("Plain ASCII")
## verdict row. It reproduces ONLY under that shot sizing -- a bare ReviewBar.adjustSize()
## does not -- so this drives the generator's REAL sizing (size_host_for_shot) and asserts
## the button row clears where the table actually PAINTS (its true document height, which
## an under-allocated widget does not report via its own geometry).
##
## CANARY: revert secure_terminal.review._detail to a plain QLabel (the pre-fix widget) and
## this fails -- the decision row overlaps the table (host sized to the QLabel's under-count).
##
## Usage: review_shot_overlap_check.py <paste-warning-shot.py path>

import importlib.util
import math
import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


def _content_height(widget):
    """The true painted height of the detail widget's rich text at its own width -- an
    under-allocated widget reports a SMALLER geometry height than this."""
    from PyQt6.QtGui import QTextDocument
    doc = QTextDocument()
    doc.setDefaultFont(widget.font())
    doc.setDocumentMargin(0)
    doc.setTextWidth(float(widget.width()))
    doc.setHtml(widget.text())
    return math.ceil(doc.size().height())


def main():
    if len(sys.argv) != 2:
        sys.stderr.write('usage: review_shot_overlap_check.py <generator>\n')
        return 2
    spec = importlib.util.spec_from_file_location('paste_warning_shot', sys.argv[1])
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    from PyQt6.QtWidgets import QApplication, QWidget

    app = QApplication.instance() or QApplication(['review-overlap-check'])
    assert app is not None

    failures = 0
    for kind in ('paste', 'copy'):
        host = QWidget()
        bar = mod.build_review(host, kind, mod.COUNTDOWN_SECONDS if kind == 'paste' else 0)
        mod.size_host_for_shot(app, host, bar)

        detail = bar._detail
        reject = bar._reject
        paints_to = detail.geometry().top() + _content_height(detail)
        # the decision row must start at or below where the table finishes painting
        if reject.geometry().top() < paints_to:
            sys.stderr.write(
                'FAIL: %s shot -- decision row overlaps the Outcome table '
                '(reject.top=%d < table paints to %d)\n'
                % (kind, reject.geometry().top(), paints_to))
            failures += 1
        # and the detail widget itself must not clip its content
        elif detail.height() < _content_height(detail):
            sys.stderr.write(
                'FAIL: %s shot -- detail widget clips its table '
                '(height=%d < content %d)\n'
                % (kind, detail.height(), _content_height(detail)))
            failures += 1

    if failures:
        return 1
    print('ok: paste/copy shot decision rows clear the Outcome table')
    return 0


if __name__ == '__main__':
    sys.exit(main())
