#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for SdwdateClass's pure time-math helpers:
  * build_median              -- median = sorted[len//2] (upper-median on even).
  * add_or_subtract_nanoseconds -- optional sub-second randomization applied to
    the raw median; new_diff_in_nanoseconds == int(new_diff_in_seconds * 1e9).
  * check_clock_skew          -- warn when the slept wall time differs from the
    requested sleep by more than +-2s, info otherwise.

Each is driven on a fake-self holding the exact instance attributes the method
reads; the only module edges stubbed are LOGGER, secrets.choice (determinism),
time.time, and randomize_time_config.

The subject is imported for real via sdwdate_testlib (SDWDATE_REPO).
"""

import types
import unittest

import sdwdate_testlib


class TimeMathBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sdwdate = sdwdate_testlib.import_sdwdate()

    def setUp(self) -> None:
        self._saved: list[tuple] = []
        self.logger = sdwdate_testlib.RecordingLogger()
        self._stub(self.sdwdate, 'LOGGER', self.logger)

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


class BuildMedianTest(TimeMathBase):
    def _run(self, raw_diffs, lag_cleaned_diffs):
        ## request_took_times / half_took_time_float are logged only, but must be
        ## non-empty and numeric (the subject indexes sorted[len//2] and formats
        ## with %+.2f).
        fake = types.SimpleNamespace(
            request_took_times={'a': 1.0, 'b': 2.0, 'c': 3.0},
            half_took_time_float={'a': 0.5, 'b': 1.0, 'c': 1.5},
            list_of_pools_raw_diff=list(raw_diffs),
            pools_lag_cleaned_diff=list(lag_cleaned_diffs),
            median_diff_raw_in_seconds=None,
            median_diff_lag_cleaned_in_seconds=None)
        self.sdwdate.SdwdateClass.build_median(fake)
        return fake

    def test_odd_length_picks_the_middle(self) -> None:
        ## odd length -> the single middle element after sorting.
        fake = self._run([5, 1, 3], [10, 20, 30])
        self.assertEqual(fake.median_diff_raw_in_seconds, 3)
        self.assertEqual(fake.median_diff_lag_cleaned_in_seconds, 20)

    def test_even_length_picks_the_upper_middle(self) -> None:
        ## even length -> the UPPER of the two middles, never an average.
        fake = self._run([1, 2, 3, 4], [10, 20])
        self.assertEqual(fake.median_diff_raw_in_seconds, 3)
        self.assertEqual(fake.median_diff_lag_cleaned_in_seconds, 20)

    def test_raw_and_lag_cleaned_use_distinct_source_lists(self) -> None:
        ## Guard against the two medians reading the same list: give them
        ## disjoint value ranges and assert each tracks its own source.
        fake = self._run([100, 200, 300], [1, 2, 3])
        self.assertEqual(fake.median_diff_raw_in_seconds, 200)
        self.assertEqual(fake.median_diff_lag_cleaned_in_seconds, 2)


class AddOrSubtractNanosecondsTest(TimeMathBase):
    def _fake_self(self, median_raw):
        return types.SimpleNamespace(
            median_diff_raw_in_seconds=median_raw,
            median_diff_lag_cleaned_in_seconds=median_raw + 777,
            range_nanoseconds=range(0, 999999999),
            new_diff_in_seconds=None,
            new_diff_in_nanoseconds=None)

    def _run_randomized(self, median_raw, nanoseconds, sign):
        self._stub(self.sdwdate, 'randomize_time_config', lambda: True)
        choices = [nanoseconds, sign]
        self._stub(
            self.sdwdate.secrets, 'choice',
            lambda seq: choices.pop(0))
        fake = self._fake_self(median_raw)
        self.sdwdate.SdwdateClass.add_or_subtract_nanoseconds(fake)
        self.assertEqual(choices, [], 'secrets.choice call count unexpected')
        return fake

    def test_randomize_off_applies_zero_offset(self) -> None:
        self._stub(self.sdwdate, 'randomize_time_config', lambda: False)
        fake = self._fake_self(10.0)
        self.sdwdate.SdwdateClass.add_or_subtract_nanoseconds(fake)
        self.assertEqual(fake.new_diff_in_seconds, 10.0)
        self.assertEqual(fake.new_diff_in_nanoseconds, 10_000_000_000)

    def test_randomize_adds_subsecond_offset_positive_sign(self) -> None:
        ## sign == 0 -> positive offset; 0.5s added to the raw median.
        fake = self._run_randomized(10.0, 500_000_000, 0)
        self.assertAlmostEqual(fake.new_diff_in_seconds, 10.5, places=9)

    def test_randomize_subtracts_offset_when_sign_is_one(self) -> None:
        ## sign == 1 -> negative offset.
        fake = self._run_randomized(10.0, 500_000_000, 1)
        self.assertAlmostEqual(fake.new_diff_in_seconds, 9.5, places=9)

    def test_offset_is_always_sub_second(self) -> None:
        ## nanoseconds come from range(0, 999999999) -> |offset| < 1s always.
        fake = self._run_randomized(0.0, 999_999_998, 0)
        self.assertLess(abs(fake.new_diff_in_seconds), 1.0)

    def test_nanoseconds_track_seconds_exactly(self) -> None:
        fake = self._run_randomized(3.0, 250_000_000, 0)
        self.assertEqual(
            fake.new_diff_in_nanoseconds,
            int(fake.new_diff_in_seconds * 1_000_000_000))

    def test_uses_raw_median_not_lag_cleaned(self) -> None:
        ## The lag-cleaned line is commented out in the subject; the raw median
        ## (not raw+777) must be the base.
        fake = self._run_randomized(42.0, 0, 0)
        self.assertEqual(fake.new_diff_in_seconds, 42.0)


class CheckClockSkewTest(TimeMathBase):
    def _run(self, before, sleep_seconds, after):
        self._stub(self.sdwdate.time, 'time', lambda: after)
        fake = types.SimpleNamespace(
            unixtime_before_sleep=before,
            sleep_time_seconds=sleep_seconds)
        self.sdwdate.SdwdateClass.check_clock_skew(fake)
        return fake

    def test_expected_sleep_logs_info_not_warning(self) -> None:
        ## time_passed == 0 -> no unexpected change.
        self._run(1000, 100, 1100)
        self.assertTrue(self.logger.infos)
        self.assertEqual(self.logger.warnings, [])

    def test_clock_jumped_forward_warns(self) -> None:
        ## slept only 50 of 100 requested -> time_passed == 50 -> warn.
        self._run(1000, 100, 1050)
        self.assertTrue(self.logger.warnings)

    def test_clock_jumped_backward_warns(self) -> None:
        ## wall time advanced 150 for a 100 sleep -> time_passed == -50 -> warn.
        self._run(1000, 100, 1150)
        self.assertTrue(self.logger.warnings)

    def test_positive_two_boundary_is_not_a_warning(self) -> None:
        ## time_passed == +2 is within tolerance (strict '> 2').
        self._run(1000, 100, 1098)
        self.assertEqual(self.logger.warnings, [])

    def test_negative_two_boundary_is_not_a_warning(self) -> None:
        ## time_passed == -2 is within tolerance (strict '< -2').
        self._run(1000, 100, 1102)
        self.assertEqual(self.logger.warnings, [])


if __name__ == '__main__':
    unittest.main()
