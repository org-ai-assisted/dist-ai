#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: msgdispatcher_dispatch_x.py reads the GUI message body from stdin
and must decode it losslessly. The body is caller-constructed HTML that may
carry invalid UTF-8 (a raw journal line). Under a full UTF-8 locale (e.g.
en_US.UTF-8) Python's sys.stdin uses the STRICT error handler, so a plain
sys.stdin.read() raises UnicodeDecodeError on such bytes and silently drops the
dialog. The script decodes sys.stdin.buffer with 'surrogateescape' instead
(matching the former argv path, PEP 383), which never raises.

Drives the REAL script as a subprocess under offscreen Qt, feeding invalid
UTF-8 on stdin with PYTHONIOENCODING=utf-8:strict to force the strict stdin
codec deterministically (independent of which locales the host generated). A
successful decode enters the Qt event loop (killed by the timeout); a
strict-read regression exits early with a UnicodeDecodeError traceback. Needs
python3-pyqt5; skipped if absent.
"""

import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

pytest.importorskip('PyQt5')

import msgcollector_testlib as T  # noqa: E402

try:
    DISPATCH = T.dispatch_script()
except (LookupError, SystemExit):
    pytest.skip('msgdispatcher_dispatch_x not available', allow_module_level=True)


def _run_with_stdin(body: bytes) -> subprocess.CompletedProcess:
    ## Offscreen Qt so no display is needed. PYTHONIOENCODING=utf-8:strict forces
    ## the strict stdin codec that a full UTF-8 locale gives -- the environment a
    ## strict read dies in and the surrogateescape decode must survive. A clean
    ## decode enters app.exec_() and blocks, so bound it with a timeout: being
    ## killed (returncode 124) means the decode succeeded and the dialog is up.
    env = dict(os.environ)
    env['QT_QPA_PLATFORM'] = 'offscreen'
    env['PYTHONIOENCODING'] = 'utf-8:strict'
    try:
        return subprocess.run(
            [DISPATCH, 'info', 'title', '0'],
            input=body, env=env, capture_output=True, timeout=6)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            exc.args, returncode=124, stdout=exc.stdout or b'',
            stderr=exc.stderr or b'')


def test_invalid_utf8_stdin_does_not_crash_decoding() -> None:
    ## A lone 0xff is invalid UTF-8; a strict read raises on it.
    proc = _run_with_stdin(b'<p>bad \xff byte</p>')
    stderr = proc.stderr.decode('utf-8', 'replace')
    assert 'UnicodeDecodeError' not in stderr, \
        f"strict stdin decode regressed: {stderr}"
    assert 'Traceback' not in stderr, \
        f"dispatch crashed on invalid-utf8 stdin: {stderr}"


def test_truncated_multibyte_stdin_does_not_crash() -> None:
    ## A lone UTF-8 lead byte (truncated multibyte sequence) also breaks a strict
    ## read; a raw journal slice can end mid-character.
    proc = _run_with_stdin(b'<p>truncated \xe2\x80</p>')
    stderr = proc.stderr.decode('utf-8', 'replace')
    assert 'UnicodeDecodeError' not in stderr, \
        f"strict stdin decode regressed on truncated multibyte: {stderr}"


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
