#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for SdwdateClass.set_new_time -- the gate + dispatch that decides
whether and HOW to apply a fetched time. test_clock_set_paths.py covers the two
leaf setters (set_time_using_date / run_sclockadj) against an emulated clock;
set_new_time itself (the replay gate and the 3-way first-run / clock-jump /
slew decision) is driven here.

The two leaf setters are stubbed to RECORD which one fired (the emulated-clock
behaviour is already proven elsewhere), the replay-protection read and time
source are stubbed, and the three flag files are real temp files so the
create/unlink side effects are asserted on disk.

The subject is imported for real via sdwdate_testlib (SDWDATE_REPO).
"""

import os
import tempfile
import types
import unittest

import sdwdate_testlib

## time.time() is pinned here; new_unixtime_int = round(NOW + new_diff).
NOW = 1_700_000_000.0
NOW_INT = 1_700_000_000


class SetNewTimeBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sdwdate = sdwdate_testlib.import_sdwdate()

    def setUp(self) -> None:
        module = self.sdwdate
        self._saved: list[tuple] = []
        self.date_calls: list[str] = []
        self.sclockadj_calls: list[bool] = []
        self.status_writes: list[tuple] = []

        self._stub(module, 'LOGGER', sdwdate_testlib.RecordingLogger())
        self._stub(module.time, 'time', lambda: NOW)
        self._stub(
            module, 'write_status',
            lambda icon, msg: self.status_writes.append((icon, msg)))

        self.workdir = tempfile.mkdtemp(prefix='sdwdate-set-new-time.')
        self.addCleanup(self._rmtree, self.workdir)
        self.first_success = os.path.join(self.workdir, 'first_success')
        self.success = os.path.join(self.workdir, 'success')
        self.clock_jump = os.path.join(self.workdir, 'clock_jump_do_once')
        self._stub(module, 'status_first_success_path', self.first_success)
        self._stub(module, 'status_success_path', self.success)
        self._stub(module, 'clock_jump_do_once_file', self.clock_jump)

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

    @staticmethod
    def _rmtree(path: str) -> None:
        for root, _dirs, files in os.walk(path, topdown=False):
            for name in files:
                os.unlink(os.path.join(root, name))
        os.rmdir(path)

    def _touch(self, path: str) -> None:
        with open(path, 'w', encoding='utf-8'):
            pass

    def _fake_self(self, new_diff_in_seconds: float):
        return types.SimpleNamespace(
            new_diff_in_seconds=new_diff_in_seconds,
            set_time_using_date=(
                lambda arg: self.date_calls.append(arg)),
            run_sclockadj=(
                lambda: self.sclockadj_calls.append(True)))

    def _set_replay_minimum(self, minimum_int: int) -> None:
        self._stub(
            self.sdwdate, 'time_replay_protection_file_read',
            lambda: (minimum_int, 'human readable'))

    def _run(self, new_diff_in_seconds: float):
        return self.sdwdate.SdwdateClass.set_new_time(
            self._fake_self(new_diff_in_seconds))


class ReplayGateTest(SetNewTimeBase):
    def test_candidate_below_minimum_aborts_without_setting_clock(self) -> None:
        ## new_unixtime_int (NOW_INT) is below the replay minimum -> abort.
        self._set_replay_minimum(NOW_INT + 100)
        result = self._run(0.0)
        self.assertFalse(result, 'set_new_time did not abort on a replay')
        self.assertEqual(
            self.date_calls, [], '/bin/date path ran despite replay gate')
        self.assertEqual(
            self.sclockadj_calls, [], 'sclockadj ran despite replay gate')
        self.assertTrue(
            any(icon == 'error' for icon, _msg in self.status_writes),
            'no error status written on replay-gate abort')
        self.assertFalse(
            os.path.exists(self.success),
            'success marker written despite replay-gate abort')

    def test_candidate_equal_to_minimum_passes(self) -> None:
        ## The gate is strict '<', so candidate == minimum is NOT a replay.
        self._set_replay_minimum(NOW_INT)
        result = self._run(0.0)
        self.assertTrue(result, 'set_new_time wrongly rejected candidate==min')


class ThreeWayDecisionTest(SetNewTimeBase):
    def setUp(self) -> None:
        super().setUp()
        ## Gate always passes for these: minimum far below the candidate.
        self._set_replay_minimum(NOW_INT - 1000)

    def test_first_run_uses_date_and_creates_first_success(self) -> None:
        ## No first_success marker, no clock-jump flag -> instant /bin/date jump.
        result = self._run(5.0)
        self.assertTrue(result)
        self.assertEqual(
            len(self.date_calls), 1, 'first run did not use /bin/date')
        self.assertEqual(
            self.sclockadj_calls, [], 'first run used the slew path')
        self.assertTrue(
            os.path.exists(self.first_success),
            'first_success marker not created on first run')
        self.assertTrue(
            os.path.exists(self.success), 'success marker not created')

    def test_clock_jump_flag_uses_date_and_unlinks_flag(self) -> None:
        ## first_success present AND clock-jump flag present -> instant jump,
        ## then the one-shot flag is consumed.
        self._touch(self.first_success)
        self._touch(self.clock_jump)
        result = self._run(5.0)
        self.assertTrue(result)
        self.assertEqual(
            len(self.date_calls), 1, 'clock-jump did not use /bin/date')
        self.assertEqual(
            self.sclockadj_calls, [], 'clock-jump used the slew path')
        self.assertFalseExists(self.clock_jump)

    def test_steady_state_uses_sclockadj(self) -> None:
        ## first_success present, no clock-jump flag -> gradual slew.
        self._touch(self.first_success)
        result = self._run(5.0)
        self.assertTrue(result)
        self.assertEqual(
            len(self.sclockadj_calls), 1, 'steady state did not slew')
        self.assertEqual(
            self.date_calls, [], 'steady state used the instant-jump path')

    def assertFalseExists(self, path: str) -> None:
        self.assertFalse(
            os.path.exists(path),
            'clock-jump one-shot flag %s not unlinked after use' % path)


if __name__ == '__main__':
    unittest.main()
