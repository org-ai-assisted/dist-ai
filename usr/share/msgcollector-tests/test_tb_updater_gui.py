#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Offscreen-Qt regression tests for two tb_updater_gui defects.

1. OK-button hang: setup_ui() used to run its own nested modal loop
   (self.exec_()) inside __init__, while main() ran a SECOND app.exec_(). The
   OK button is wired to the default QDialog.accept(), which returns from the
   nested loop without exiting; control then fell into the redundant outer
   app.exec_() with no window left to end it, hanging forever. The fix removes
   the nested loop (single show() + app.exec_()). Guard: the class must NOT
   call self.exec_() -- reintroducing it brings the hang back, and a behavioural
   check cannot fail cleanly (a Qt C++ loop does not yield to Python signals).

2. Rich-text version spoofing: installed_version and each online_versions entry
   are caller-supplied and rendered by widgets whose textFormat auto-detects
   markup, so an unsanitized value could spoof the version shown in the
   download-confirmation dialog. The fix runs them through sanitize_string,
   which strips markup AND control/ANSI/escape bytes (html.escape would leave
   the latter).

The class lives in an executable GUI script (importing it would run main), so
its source is extracted and defined against the real Qt classes, offscreen.
Needs python3-pyqt5; skipped cleanly if absent.
"""

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
pytest.importorskip('PyQt5')
pytest.importorskip('sanitize_string')
# pylint: disable=wrong-import-position
from PyQt5 import QtCore, QtGui, QtWidgets  # noqa: E402
from PyQt5.QtGui import QIcon, QPixmap  # noqa: E402
from sanitize_string.sanitize_string_lib import sanitize_string  # noqa: E402

import msgcollector_testlib as T  # noqa: E402


def _tb_updater_gui_script():
    return os.path.join(os.path.dirname(T.msgcollector_script()), 'tb_updater_gui.py')


try:
    _SCRIPT = _tb_updater_gui_script()
    _CLASS_SRC = T.extract_python_class(_SCRIPT, 'GuiMessage')
except (LookupError, SystemExit):
    pytest.skip('tb_updater_gui GuiMessage not available', allow_module_level=True)

## Define the REAL class against the real Qt bases, without importing the script.
_NS = {
    'QtWidgets': QtWidgets, 'QtCore': QtCore, 'QtGui': QtGui,
    'QIcon': QIcon, 'QPixmap': QPixmap, 'os': os, 'sys': sys,
    'sanitize_string': sanitize_string,
}
exec(_CLASS_SRC, _NS)  # noqa: S102  # nosec B102 -- trusted first-party class source
GuiMessage = _NS['GuiMessage']

_APP = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
assert _APP is not None


class _Args:
    def __init__(self, installed='1.0', online='1.1,1.2', button='ok'):
        self.message_type = 'info'
        self.title = 'Title'
        self.installed_version = installed
        self.online_versions = online
        self.message = 'body'
        self.question = 'Continue?'
        self.button_type = button


def test_no_nested_modal_loop():
    ## The nested self.exec_() in setup_ui is what hangs the OK path; it must be
    ## gone so the single outer app.exec_() owns the loop.
    assert 'self.exec_()' not in _CLASS_SRC, \
        'GuiMessage runs a nested modal loop -- the OK-button hang is back'


def test_construction_does_not_block():
    ## With the nested loop removed, building the dialog must return (offscreen);
    ## the old code would block here in self.exec_().
    dialog = GuiMessage(_Args())
    try:
        assert dialog is not None
    finally:
        dialog.close()


def test_version_markup_is_stripped():
    ## Use markup tags the label's own template never contains (<img>, <u>), so
    ## the assertion cannot false-positive on the template's own <b>/<p>/<code>.
    dialog = GuiMessage(_Args(installed='<img src=x>9.9', online='<u>7.0</u>,8.0'))
    try:
        labels = ' '.join(w.text() for w in dialog.findChildren(QtWidgets.QLabel))
        radios = [w.text() for w in dialog.findChildren(QtWidgets.QRadioButton)]
        ## QLabel.text() returns the source HTML; the injected tag must be gone,
        ## the numeric value kept.
        assert '<img' not in labels, 'installed_version markup not stripped'
        assert '9.9' in labels, 'installed_version value lost'
        ## radio text is the bare sanitized version -- no markup at all remains.
        assert not any('<' in r for r in radios), 'online_versions markup not stripped'
        assert '7.0' in ' '.join(radios), 'online_versions value lost'
    finally:
        dialog.close()


def test_version_control_bytes_are_stripped():
    ## The point of sanitize_string over html.escape: it also removes control
    ## and ANSI/escape bytes, which html.escape would pass through unchanged and
    ## which can spoof the version shown in the confirmation dialog.
    zwsp = chr(0x200b)  ## zero-width space (kept out of the source as ASCII)
    dialog = GuiMessage(_Args(installed='9.9\x1b[31m\x07' + zwsp,
                              online='1.0\x1b]8;;http://evil\x07,2.0'))
    try:
        widgets = dialog.findChildren((QtWidgets.QLabel, QtWidgets.QRadioButton))
        shown = ' '.join(w.text() for w in widgets)
        assert '\x1b' not in shown, 'ESC byte survived into the dialog'
        assert '\x07' not in shown, 'BEL byte survived into the dialog'
        assert zwsp not in shown, 'zero-width space survived into the dialog'
    finally:
        dialog.close()
