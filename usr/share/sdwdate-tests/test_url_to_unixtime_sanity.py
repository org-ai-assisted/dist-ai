#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Deterministic boundary tests for url_to_unixtime's two gating parsers, which a
hostile time server's response flows through. The fuzz suites prove these never
crash; these assert they gate CORRECTLY at the exact boundaries:

  * data_to_http_time   -- the Date-header length window [29, 100].
  * unixtime_sanity_check -- numeric, strictly-positive, <= 10 digits.

unixtime_sanity_check had no deterministic unit test before (only fuzz). Loader
reused from fuzz_sdwdate so the subject is resolved one way.
"""

import unittest

import fuzz_sdwdate


class DataToHttpTimeLengthGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.u2u = fuzz_sdwdate._load_url_to_unixtime()

    def _date(self, value: str):
        return fuzz_sdwdate._FakeResponse(value)

    def test_too_short_rejected(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            self.u2u.data_to_http_time(self._date('x' * 28))
        self.assertEqual(ctx.exception.code, 2)

    def test_minimum_length_accepted(self) -> None:
        value = 'x' * 29
        self.assertEqual(self.u2u.data_to_http_time(self._date(value)), value)

    def test_maximum_length_accepted(self) -> None:
        value = 'x' * 100
        self.assertEqual(self.u2u.data_to_http_time(self._date(value)), value)

    def test_too_long_rejected(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            self.u2u.data_to_http_time(self._date('x' * 101))
        self.assertEqual(ctx.exception.code, 2)


class UnixtimeSanityCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.u2u = fuzz_sdwdate._load_url_to_unixtime()

    def _check(self, parsed_unixtime: str):
        data = fuzz_sdwdate._FakeResponse('Wed, 21 Oct 2015 07:28:00 GMT')
        return self.u2u.unixtime_sanity_check(
            data, 'Wed, 21 Oct 2015 07:28:00 GMT', parsed_unixtime)

    def test_valid_ten_digit_passes(self) -> None:
        self.assertEqual(self._check('1445412480'), '1445412480')

    def test_non_numeric_rejected(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            self._check('not-a-number')
        self.assertEqual(ctx.exception.code, 3)

    def test_zero_rejected(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            self._check('0')
        self.assertEqual(ctx.exception.code, 3)

    def test_negative_rejected(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            self._check('-5')
        self.assertEqual(ctx.exception.code, 3)

    def test_excessive_length_rejected(self) -> None:
        ## 11 digits: numeric and positive, but past the 10-digit cap -> exit 4.
        with self.assertRaises(SystemExit) as ctx:
            self._check('12345678901')
        self.assertEqual(ctx.exception.code, 4)


if __name__ == '__main__':
    unittest.main()
