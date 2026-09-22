#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for the two ai-review-confirmed main.py findings that need the window
/ CLI surface: _ipc_open's strict if_absent validation, and ctl dump-state --file failing
cleanly (stderr + exit 1) on an unwritable path instead of a traceback."""

from test_mainwin_common import *   # noqa: F401,F403  (shared harness: MainWindow, _ctl_main, ok, eq, finish, APP)

from secure_terminal import main as _main

win = MainWindow()
win.new_tab()
APP.processEvents()

# --- #14: _ipc_open rejects a non-boolean if_absent (matching submit/lines) -----------
_bad = win._ipc_open({'if_absent': 'false', 'tabs': []})   # a "false" STRING is truthy
ok(isinstance(_bad, dict) and _bad.get('ok') is False
   and 'if_absent' in _bad.get('error', ''),
   '#14: a non-boolean if_absent is rejected, not truthy-coerced')
_bad2 = win._ipc_open({'if_absent': 1, 'tabs': []})        # bool-as-int
ok(_bad2.get('ok') is False, '#14: an int if_absent is rejected too')
_okr = win._ipc_open({'if_absent': False, 'tabs': []})     # a real bool is accepted
ok(_okr.get('ok') is True, '#14: a boolean if_absent is accepted (sanity)')

# --- #10: ctl dump-state --file to an unwritable dir returns 1 (no traceback) ----------
_saved_send = _main.ipc.send_request
_main.ipc.send_request = lambda group, req: {'ok': True, 'text': 'STATE-DATA'}
try:
    _rc = _main._ctl_main(['--instance-group', 'g', 'dump-state', '--tab', 'id:0',
                           '--file', '/no/such/dir/definitely/missing/x'])
finally:
    _main.ipc.send_request = _saved_send
eq(_rc, 1, '#10: dump-state --file to an unwritable dir returns 1, not a traceback')
# the happy path still writes + returns 0
import tempfile as _tf
import os as _os
_dst = _os.path.join(_tf.mkdtemp(prefix='st-cf-'), 'dump.txt')
_main.ipc.send_request = lambda group, req: {'ok': True, 'text': 'STATE-DATA'}
try:
    _rc2 = _main._ctl_main(['--instance-group', 'g', 'dump-state', '--tab', 'id:0',
                            '--file', _dst])
finally:
    _main.ipc.send_request = _saved_send
ok(_rc2 == 0 and _os.path.isfile(_dst)
   and open(_dst, encoding='utf-8').read() == 'STATE-DATA',
   '#10: a writable --file path still writes the dump and returns 0 (sanity)')

finish('core-fixes-win')
