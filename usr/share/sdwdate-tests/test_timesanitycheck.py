#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for sdwdate.timesanitycheck -- the two gates that classify a fetched
time as slow / sane / fast / error before sdwdate will act on it.

Both functions reach an external edge: static_time_sanity_check shells out to
/usr/bin/minimum-unixtime-show, and time_consensus_sanity_check opens a Tor
control connection (stem). Those edges are stubbed; the REAL decision logic is
driven, so a boundary or sign regression is caught.

The subject is imported for real via sdwdate_testlib (SDWDATE_REPO).
"""

import unittest

import sdwdate_testlib


class TimeSanityCheckBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = sdwdate_testlib.import_sdwdate_submodule('timesanitycheck')

    def setUp(self) -> None:
        self._saved: list[tuple] = []

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


class _StubPopen:
    """subprocess.Popen stand-in: communicate() returns the scripted bytes."""

    def __init__(self, stdout_bytes: bytes, stderr_bytes: bytes = b'') -> None:
        self._stdout = stdout_bytes
        self._stderr = stderr_bytes

    def communicate(self):
        return (self._stdout, self._stderr)


class StaticTimeSanityCheckTest(TimeSanityCheckBase):
    """static_time_sanity_check: minimum (from the helper) < x <= expiration."""

    ## Hardcoded in the subject: Tue, 17 May 2033 10:00:00 GMT.
    EXPIRATION = 1999936800
    MINIMUM = 1600000000

    def _run(self, unixtime_to_validate):
        def fake_popen(path, stdout=None, stderr=None):
            return _StubPopen(str(self.MINIMUM).encode('UTF-8'))

        self._stub(self.mod.subprocess, 'Popen', fake_popen)
        return self.mod.static_time_sanity_check(unixtime_to_validate)

    def test_below_minimum_is_slow(self) -> None:
        status, error = self._run(self.MINIMUM - 1)
        self.assertEqual(status, 'slow')
        self.assertEqual(error, 'none')

    def test_in_range_is_sane(self) -> None:
        status, _error = self._run(self.MINIMUM + 1000)
        self.assertEqual(status, 'sane')

    def test_at_minimum_is_sane_strict_less_than(self) -> None:
        ## The compare is strict '<', so exactly minimum is NOT slow.
        status, _error = self._run(self.MINIMUM)
        self.assertEqual(status, 'sane')

    def test_above_expiration_is_fast(self) -> None:
        status, _error = self._run(self.EXPIRATION + 1)
        self.assertEqual(status, 'fast')

    def test_at_expiration_is_sane_strict_greater_than(self) -> None:
        ## The compare is strict '>', so exactly expiration is NOT fast.
        status, _error = self._run(self.EXPIRATION)
        self.assertEqual(status, 'sane')

    def test_non_integer_helper_output_is_error(self) -> None:
        ## int(stdout) raises -> the BaseException path -> 'error', never a
        ## vacuous 'sane'.
        def fake_popen(path, stdout=None, stderr=None):
            return _StubPopen(b'not-a-number')

        self._stub(self.mod.subprocess, 'Popen', fake_popen)
        status, error = self.mod.static_time_sanity_check(self.MINIMUM + 1)
        self.assertEqual(status, 'error')
        self.assertNotEqual(error, 'none')

    def test_helper_failure_is_error(self) -> None:
        def fake_popen(path, stdout=None, stderr=None):
            raise OSError('minimum-unixtime-show missing')

        self._stub(self.mod.subprocess, 'Popen', fake_popen)
        status, _error = self.mod.static_time_sanity_check(self.MINIMUM + 1)
        self.assertEqual(status, 'error')


class _FakeController:
    """stem controller stand-in for time_consensus_sanity_check."""

    def __init__(self, valid_after: str, valid_until: str) -> None:
        self._info = {
            'consensus/valid-after': valid_after,
            'consensus/valid-until': valid_until,
        }
        self.closed = False

    def get_info(self, key: str) -> str:
        return self._info[key]

    def close(self) -> None:
        self.closed = True


class TimeConsensusSanityCheckTest(TimeSanityCheckBase):
    """time_consensus_sanity_check: slow <= valid-after < ok <= valid-until."""

    ## TZ is forced to UTC at module import, so strftime('%s') on these naive
    ## datetimes yields the UTC epoch deterministically.
    VALID_AFTER = '2020-01-01 00:00:00'   # epoch 1577836800
    VALID_UNTIL = '2020-01-01 01:00:00'   # epoch 1577840400
    AFTER_EPOCH = 1577836800
    UNTIL_EPOCH = 1577840400

    def _connect_ok(self):
        controller = _FakeController(self.VALID_AFTER, self.VALID_UNTIL)
        self._stub(self.mod, 'connect', lambda: controller)
        return controller

    def test_before_valid_after_is_slow(self) -> None:
        self._connect_ok()
        status, error, _a, _u = self.mod.time_consensus_sanity_check(
            self.AFTER_EPOCH - 10)
        self.assertEqual(status, 'slow')
        self.assertEqual(error, '')

    def test_at_valid_after_is_slow(self) -> None:
        ## The compare is 'unixtime > valid-after else slow', so equality is
        ## slow (not ok).
        self._connect_ok()
        status, _error, _a, _u = self.mod.time_consensus_sanity_check(
            self.AFTER_EPOCH)
        self.assertEqual(status, 'slow')

    def test_in_range_is_ok(self) -> None:
        self._connect_ok()
        status, _error, _a, _u = self.mod.time_consensus_sanity_check(
            self.AFTER_EPOCH + 10)
        self.assertEqual(status, 'ok')

    def test_after_valid_until_is_fast(self) -> None:
        self._connect_ok()
        status, _error, _a, _u = self.mod.time_consensus_sanity_check(
            self.UNTIL_EPOCH + 10)
        self.assertEqual(status, 'fast')

    def test_connect_failure_is_error(self) -> None:
        def boom():
            raise OSError('control socket down')

        self._stub(self.mod, 'connect', boom)
        status, error, _a, _u = self.mod.time_consensus_sanity_check(
            self.AFTER_EPOCH + 10)
        self.assertEqual(status, 'error')
        self.assertIn('control connection', error)

    def test_get_info_failure_is_error(self) -> None:
        class Broken:
            def get_info(self, _key):
                raise OSError('getinfo failed')

            def close(self):
                pass

        self._stub(self.mod, 'connect', lambda: Broken())
        status, _error, _a, _u = self.mod.time_consensus_sanity_check(
            self.AFTER_EPOCH + 10)
        self.assertEqual(status, 'error')


if __name__ == '__main__':
    unittest.main()
