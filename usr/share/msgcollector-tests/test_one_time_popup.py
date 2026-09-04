#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for two one-time-popup defects.

1. notify-send option injection: show_passive_popup() passed the caller-supplied
   title/message as trailing notify-send arguments with no '--' terminator, so a
   value beginning with '-' (e.g. '-1', which argparse's negative-number
   heuristic lets through) was parsed as a notify-send option instead of text.
   The fix inserts '--' before the positionals. Verified by capturing the argv
   show_passive_popup builds.

2. GUI-helper coupling: the passive (notify-send) path needs no display, yet the
   guard 'from guimessages.display import exit_if_no_gui' was imported at module
   top, making even --passive depend on the GUI helper. The fix imports it
   lazily inside the GUI branch. Guard: no top-level guimessages import.

one-time-popup.py is a script (main() is __main__-guarded), so it is loaded by
path; importing it must NOT require guimessages. Needs python3-pyqt5; skipped
cleanly if absent.
"""

import os
import sys
import importlib.util

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
pytest.importorskip('PyQt5')

import msgcollector_testlib as T  # noqa: E402


def _one_time_popup_script():
    return os.path.join(os.path.dirname(T.msgcollector_script()), 'one-time-popup.py')


_SCRIPT = _one_time_popup_script()
if not os.path.isfile(_SCRIPT):
    pytest.skip('one-time-popup.py not available', allow_module_level=True)


def _load_module():
    ## Importing must not require guimessages -- that is exactly the decoupling
    ## under test; a top-level guimessages import would fail here if the helper
    ## were absent, and always couples the passive path to it.
    spec = importlib.util.spec_from_file_location('one_time_popup', _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guimessages_import_is_not_module_top_level():
    src = T.read(_SCRIPT)
    top_level = [ln for ln in src.splitlines() if ln.startswith('from guimessages')]
    assert not top_level, \
        'guimessages imported at module top -- the passive path must not need it'


def test_notify_send_uses_option_terminator(monkeypatch, tmp_path):
    module = _load_module()

    captured = {}

    class _Result:
        stdout = 'SUPPRESS'

    def _fake_run(argv, **_kwargs):
        captured['argv'] = argv
        return _Result()

    monkeypatch.setattr(module.subprocess, 'run', _fake_run)

    ## show_passive_popup exits after writing the status file; a title of '-1'
    ## must reach notify-send as text, guarded by a preceding '--'.
    with pytest.raises(SystemExit):
        module.show_passive_popup(tmp_path / 'status', '-1', 'body')

    argv = captured['argv']
    assert '--' in argv, 'notify-send argv lacks the "--" option terminator'
    assert argv.index('--') < argv.index('-1'), '"--" must precede the title'
    assert argv.index('-1') < argv.index('body'), 'title then message order'
