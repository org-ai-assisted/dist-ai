#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Offscreen-Qt validator for msgcollector's SafeTextBrowser defense.

msgdispatcher_dispatch_x renders GUI messages with QTextBrowser.setHtml over
caller-constructed HTML that may carry unsanitized values. SafeTextBrowser's
defense-in-depth is loadResource() -> None: the widget must NEVER fetch a
resource, so a message can never trigger a network or filesystem access (e.g.
'<img src="http://...">' or '<img src="file:///etc/passwd">'), for ANY input.

The class lives inside an executable GUI script (importing it would launch the
dialog), so this test extracts the real class source, defines it against the
real QtWidgets.QTextBrowser base, runs it under the offscreen Qt platform, and
asserts:
  * loadResource refuses every (resource_type, url) -- returns None; and
  * setHtml never crashes on adversarial HTML.

Coverage-guided fuzzing (Atheris) does not fit here: the HTML parsing is inside
Qt (C++), which Atheris cannot instrument. This offscreen-Qt property test is
the meaningful way to exercise the Python defense. Needs python3-pyqt5 (and,
for the property case, python3-hypothesis); skipped cleanly if absent.
"""

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt5")
# pylint: disable=wrong-import-position
from PyQt5 import QtWidgets, QtCore, QtGui  # noqa: E402

import msgcollector_testlib as T  # noqa: E402

try:
    _CLASS_SRC = T.extract_python_class(T.dispatch_script(), "SafeTextBrowser")
except (LookupError, SystemExit):
    pytest.skip("SafeTextBrowser not available", allow_module_level=True)

## Define the REAL class against the real Qt base, without importing the script.
_NS = {"QtWidgets": QtWidgets}
exec(_CLASS_SRC, _NS)  # noqa: S102  (trusted first-party source)
SafeTextBrowser = _NS["SafeTextBrowser"]

## One QApplication for the whole module (offscreen; no display needed).
_APP = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
assert _APP is not None     # a QApplication must outlive every widget built below
_BROWSER = SafeTextBrowser()

_RESOURCE_TYPES = [
    QtGui.QTextDocument.ImageResource,
    QtGui.QTextDocument.StyleSheetResource,
    QtGui.QTextDocument.HtmlResource,
    999,  # an out-of-range resource type must be refused too
]

_HOSTILE_URLS = [
    "http://evil.example/x", "https://evil.example/x", "file:///etc/passwd",
    "ftp://evil/x", "data:text/html,<script>alert(1)</script>", "//evil/x",
    "qrc:/x", "about:blank", "", "javascript:alert(1)",
]


def test_defense_override_is_present() -> None:
    ## The heart of the defense: SafeTextBrowser must OVERRIDE loadResource (not
    ## inherit QTextBrowser's, which would fetch). A bare "returns None" check is
    ## not enough on its own -- the base also returns None for an unreachable
    ## resource -- so this guards against the override being removed/renamed.
    ## (PyQt wraps inherited methods in fresh objects, so an identity check
    ## against the base is unreliable; the __dict__ membership is the real guard.)
    assert "loadResource" in SafeTextBrowser.__dict__, \
        "SafeTextBrowser no longer overrides loadResource -- the resource-refusal defense is gone"


def test_loadresource_refuses_known_hostile_urls() -> None:
    for url in _HOSTILE_URLS:
        for resource_type in _RESOURCE_TYPES:
            assert _BROWSER.loadResource(resource_type, QtCore.QUrl(url)) is None, \
                f"loadResource returned non-None for {url!r}"


def test_sethtml_adversarial_no_crash() -> None:
    for html in [
        '<img src="http://evil.example/x">',
        '<a href="file:///etc/passwd">click</a>',
        '<img src=http://x><style>@import url(http://y)</style>',
        '<font color="green">OK.</font><br/>' * 50,
        "<" * 200,
        '<img src="data:image/png;base64,AAAA">',
    ]:
        _BROWSER.setHtml(html)  # must not raise
    assert True


try:
    from hypothesis import given, settings, strategies as st
except ImportError:
    pass
else:
    @settings(max_examples=200, deadline=None)
    @given(st.text(
        alphabet=st.characters(min_codepoint=1, exclude_categories=("Cs",)),
        max_size=48))
    def test_loadresource_refuses_arbitrary_url(url: str) -> None:
        assert _BROWSER.loadResource(
            QtGui.QTextDocument.ImageResource, QtCore.QUrl(url)) is None
