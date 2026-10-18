#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for remote_times.run_command -- runs url_to_unixtime against one
remote with a 120s wait and a 2s read, classifying the outcome:
  * normal exit            -> status "done"
  * wait() TimeoutExpired  -> kill + status "timeout"
  * other wait() exception -> kill + status "error"
  * communicate() timeout  -> status "error"
  * non-UTF8 stdout/stderr -> decode guard returns "" (never crashes)

subprocess.Popen and time.time are stubbed with a fake process; the subject is
imported for real via sdwdate_testlib (SDWDATE_REPO).
"""

import unittest

import sdwdate_testlib


class FakeProcess:
    """
    Stand-in for the url_to_unixtime child. Models exactly what run_command
    touches: wait(timeout)/wait(), kill(), communicate(timeout), returncode.
    """

    def __init__(self, *, first_wait_raises=None, communicate_result=(b'', b''),
                 communicate_raises=None, returncode=0) -> None:
        self._first_wait_raises = first_wait_raises
        self._communicate_result = communicate_result
        self._communicate_raises = communicate_raises
        self.returncode = returncode
        self.killed = False

    def wait(self, timeout=None):
        ## The first call passes the 120s timeout; the reap call passes none.
        if timeout is not None and self._first_wait_raises is not None:
            raise self._first_wait_raises
        return self.returncode

    def kill(self) -> None:
        self.killed = True

    def communicate(self, timeout=None):
        if self._communicate_raises is not None:
            raise self._communicate_raises
        return self._communicate_result


class RunCommandTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = sdwdate_testlib.import_sdwdate_submodule('remote_times')

    def setUp(self) -> None:
        self._saved: list[tuple] = []
        ## Deterministic took_time; value is not asserted.
        self._stub(self.mod.time, 'time', lambda: 1000.0)

    _MISSING = object()

    def tearDown(self) -> None:
        for owner, name, value in reversed(self._saved):
            if value is self._MISSING:
                delattr(owner, name)
            else:
                setattr(owner, name, value)

    def _stub(self, owner, name, value) -> None:
        self._saved.append((owner, name, getattr(owner, name, self._MISSING)))
        setattr(owner, name, value)

    def _run(self, process):
        self._stub(
            self.mod.subprocess, 'Popen',
            lambda argv, stdout=None, stderr=None: process)
        return self.mod.run_command(
            0, 'url_to_unixtime 127.0.0.1 9050 http://x.onion true', 'x.onion')

    def test_normal_exit_is_done(self) -> None:
        proc = FakeProcess(communicate_result=(b'1700000000', b''))
        returned_proc, status, _end, _took, stdout, stderr = self._run(proc)
        self.assertEqual(status, 'done')
        self.assertIs(returned_proc, proc)
        self.assertEqual(stdout, '1700000000')
        self.assertEqual(stderr, '')
        self.assertFalse(proc.killed)

    def test_wait_timeout_is_timeout_and_kills(self) -> None:
        proc = FakeProcess(
            first_wait_raises=self.mod.subprocess.TimeoutExpired('cmd', 120))
        _p, status, _end, _took, _out, _err = self._run(proc)
        self.assertEqual(status, 'timeout')
        self.assertTrue(proc.killed, 'timed-out process was not killed')

    def test_wait_other_exception_is_error_and_kills(self) -> None:
        proc = FakeProcess(first_wait_raises=RuntimeError('boom'))
        _p, status, _end, _took, _out, _err = self._run(proc)
        self.assertEqual(status, 'error')
        self.assertTrue(proc.killed)

    def test_communicate_timeout_is_error(self) -> None:
        proc = FakeProcess(
            communicate_raises=self.mod.subprocess.TimeoutExpired('cmd', 2))
        _p, status, _end, _took, _out, _err = self._run(proc)
        self.assertEqual(status, 'error')

    def test_non_utf8_output_hits_decode_guard(self) -> None:
        ## Invalid UTF-8 must be caught, not crash the daemon; stdout/stderr
        ## fall back to "".
        proc = FakeProcess(communicate_result=(b'\xff\xfe', b'\xff'))
        _p, status, _end, _took, stdout, stderr = self._run(proc)
        self.assertEqual(status, 'done')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')


if __name__ == '__main__':
    unittest.main()
