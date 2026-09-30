#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for a one-time-popup defect.

notify-send option injection: show_passive_popup() passed the caller-supplied
title/message as trailing notify-send arguments with no '--' terminator, so a
value beginning with '-' (e.g. '-1', which argparse's negative-number
heuristic lets through) was parsed as a notify-send option instead of text.
The fix inserts '--' before the positionals. Verified by capturing the argv
show_passive_popup builds.

one-time-popup.py is a script (main() is __main__-guarded), so it is loaded by
path, running only its top-level imports (guimessages + PyQt5), not main().
Needs python3-pyqt5; skipped cleanly if absent.
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
    ## one-time-popup.py is __main__-guarded, so loading it by path runs only its
    ## top-level imports (guimessages + PyQt5), not main().
    spec = importlib.util.spec_from_file_location('one_time_popup', _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
