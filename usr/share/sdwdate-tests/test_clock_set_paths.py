#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Synthetic tests for sdwdate's two clock-change paths, against an EMULATED clock.

sdwdate changes the system clock two ways:
  * set_time_using_date  -> '/bin/date --set @<unixtime>'   (instant jump)
  * run_sclockadj        -> '/usr/libexec/sdwdate/sclockadj <nanoseconds>'
                            (gradual slew), followed in both by
                            'leaprun sdwdate-sync-hwclock'.

No root, no real clock: /bin/date and sclockadj are stubbed by a recorder that
applies the requested change to an emulated clock, and the test asserts the
emulated clock ACTUALLY CHANGED by the right amount (not merely that a command
was issued). threading.Thread is stubbed synchronous so run_sclockadj is
deterministic.

The subject module is imported for real via sdwdate_testlib (SDWDATE_REPO).
"""

import logging
import types
import unittest

import sdwdate_testlib


class EmulatedClock:
    """A nanosecond clock that /bin/date sets and sclockadj slews."""

    def __init__(self, ns: int) -> None:
        self.ns = ns

    def set_unixtime(self, unixtime_str: str) -> None:
        self.ns = int(round(float(unixtime_str) * 1_000_000_000))

    def slew(self, delta_ns_str: str) -> None:
        self.ns += int(delta_ns_str)


class RecorderPopen:
    """Stub for subprocess.Popen: records argv and applies the clock change."""

    def __init__(self, argv, clock, calls, stdout=None, stderr=None) -> None:
        self.argv = list(argv)
        calls.append(self.argv)
        self.returncode = 0
        self.pid = 4242
        if self.argv[:1] == ['/bin/date']:
            ## argv is ['/bin/date','--utc','+...','--set','@<unixtime>']
            target = self.argv[-1].lstrip('@')
            clock.set_unixtime(target)
        elif self.argv[:1] == ['/usr/libexec/sdwdate/sclockadj']:
            clock.slew(self.argv[1])

    def communicate(self):
        return (b'', b'')

    def kill(self) -> None:
        pass

    def wait(self) -> int:
        return 0


class SyncThread:
    """Run the target inline on start(), so run_sclockadj is deterministic."""

    def __init__(self, target=None, args=(), **_kwargs) -> None:
        self._target = target
        self._args = args

    def start(self) -> None:
        if self._target is not None:
            self._target(*self._args)

    def join(self, *_a, **_k) -> None:
        pass


class ClockSetPathBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sdwdate = sdwdate_testlib.import_sdwdate()

    def setUp(self) -> None:
        module = self.sdwdate
        self.clock = EmulatedClock(1_000_000_000_000_000_000)  # arbitrary start
        self.popen_calls: list[list[str]] = []
        self.run_calls: list[list[str]] = []
        self._saved: list[tuple] = []

        self._stub(module, 'LOGGER', logging.getLogger('sdwdate-clock-tests'))
        module.LOGGER.addHandler(logging.NullHandler())
        module.LOGGER.propagate = False

        def fake_popen(argv, stdout=None, stderr=None):
            return RecorderPopen(argv, self.clock, self.popen_calls)

        def fake_run(argv, *a, **k):
            self.run_calls.append(list(argv))
            return types.SimpleNamespace(returncode=0)

        self._stub(module.subprocess, 'Popen', fake_popen)
        self._stub(module.subprocess, 'run', fake_run)
        self._stub(module.threading, 'Thread', SyncThread)
        ## set_time_using_date calls exit_handler on a non-zero /bin/date exit;
        ## our stub returns 0, but guard against a real sys.exit either way.
        self._stub(module, 'exit_handler',
                   lambda code, reason: self.fail(
                       'exit_handler(%r, %r)' % (code, reason)))

    _MISSING = object()

    def tearDown(self) -> None:
        ## LOGGER does not exist on a bare import (main() creates it); restore to
        ## absent rather than leaving the stub behind.
        for owner, name, value in reversed(self._saved):
            if value is self._MISSING:
                delattr(owner, name)
            else:
                setattr(owner, name, value)

    def _stub(self, owner, name, value) -> None:
        self._saved.append((owner, name, getattr(owner, name, self._MISSING)))
        setattr(owner, name, value)

    def _fake_self(self, diff_seconds: float):
        ## run_sclockadj reaches self.run_sclockadj_and_hwclock (a staticmethod);
        ## give the fake-self the real one so the thread target resolves.
        return types.SimpleNamespace(
            new_diff_in_seconds=diff_seconds,
            new_diff_in_nanoseconds=int(diff_seconds * 1_000_000_000),
            run_sclockadj_and_hwclock=(
                self.sdwdate.SdwdateClass.run_sclockadj_and_hwclock))


class SetTimeUsingDateTest(ClockSetPathBase):
    def test_date_jump_changes_the_clock(self) -> None:
        fake = self._fake_self(123.0)
        target_unixtime = '1700000000'
        self.sdwdate.SdwdateClass.set_time_using_date(fake, target_unixtime)

        self.assertEqual(
            self.popen_calls,
            [['/bin/date', '--utc', '+%Y-%m-%d %H:%M:%S', '--set',
              '@' + target_unixtime]],
            'set_time_using_date did not run /bin/date with the fetched time')
        self.assertEqual(
            self.clock.ns, 1700000000 * 1_000_000_000,
            'emulated clock was not set to the target unixtime')
        self.assertIn(
            ['/usr/bin/leaprun', 'sdwdate-sync-hwclock'], self.run_calls,
            'hardware clock was not synced via leaprun after /bin/date')

    def test_zero_diff_does_not_touch_the_clock(self) -> None:
        before = self.clock.ns
        self.sdwdate.SdwdateClass.set_time_using_date(
            self._fake_self(0), '1700000000')
        self.assertEqual(self.popen_calls, [],
                         'set_time_using_date ran /bin/date for a zero diff')
        self.assertEqual(self.clock.ns, before, 'clock changed on a zero diff')


class RunSclockadjTest(ClockSetPathBase):
    def test_sclockadj_slews_the_clock(self) -> None:
        delta_ns = 50_000_000  # 0.05s -> gradual, well under a date jump
        fake = self._fake_self(delta_ns / 1_000_000_000)
        before = self.clock.ns

        self.sdwdate.SdwdateClass.run_sclockadj(fake)

        self.assertEqual(
            self.popen_calls,
            [['/usr/libexec/sdwdate/sclockadj', str(delta_ns)]],
            'run_sclockadj did not exec sclockadj with the nanosecond delta')
        self.assertEqual(
            self.clock.ns, before + delta_ns,
            'emulated clock was not slewed by sclockadj by the delta')
        self.assertIn(
            ['/usr/bin/leaprun', 'sdwdate-sync-hwclock'], self.run_calls,
            'hardware clock was not synced via leaprun after sclockadj')

    def test_zero_diff_does_not_run_sclockadj(self) -> None:
        before = self.clock.ns
        self.sdwdate.SdwdateClass.run_sclockadj(self._fake_self(0))
        self.assertEqual(self.popen_calls, [],
                         'run_sclockadj ran sclockadj for a zero diff')
        self.assertEqual(self.clock.ns, before, 'clock changed on a zero diff')


if __name__ == '__main__':
    unittest.main()
