#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: url_to_unixtime must reject a hostile server's HTTP Date header
without crashing.

dateutil.parser.parse raises OverflowError (not ValueError) on an
out-of-C-int-range year, so http_time_to_parsed_unixtime must reject such a
Date header via sys.exit(6) (SystemExit) rather than let the exception escape
and crash the daemon. Found by fuzz_sdwdate.py.

The loaders are reused from fuzz_sdwdate so there is one source for resolving
the subject.
"""

import unittest

import fuzz_sdwdate


class DateParseRejection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.u2u = fuzz_sdwdate._load_url_to_unixtime()

    def test_overflow_year_is_rejected_not_crash(self):
        ## 35 chars: passes data_to_http_time's 29..100 length gate, and the
        ## year is large enough that dateutil raises OverflowError.
        http_time = 'Mon, 01 Jan 9999999999 00:00:00 GMT'
        data = fuzz_sdwdate._FakeResponse(http_time)
        self.assertEqual(
            len(http_time), 35, 'fixture must stay within the length gate')
        with self.assertRaises(SystemExit) as ctx:
            self.u2u.http_time_to_parsed_unixtime(data, http_time)
        self.assertEqual(ctx.exception.code, 6)

    def test_end_to_end_overflow_date_rejected(self):
        ## The same value entering through data_to_http_time (as a real server
        ## response would) must be rejected cleanly, never raise.
        http_time = 'Mon, 01 Jan 9999999999 00:00:00 GMT'
        data = fuzz_sdwdate._FakeResponse(http_time)
        returned = self.u2u.data_to_http_time(data)
        self.assertEqual(returned, http_time)
        with self.assertRaises(SystemExit) as ctx:
            self.u2u.http_time_to_parsed_unixtime(data, returned)
        self.assertEqual(ctx.exception.code, 6)

    def test_valid_rfc_date_still_parses(self):
        ## The fix must not break a well-formed Date header.
        http_time = 'Wed, 21 Oct 2015 07:28:00 GMT'
        data = fuzz_sdwdate._FakeResponse(http_time)
        parsed = self.u2u.http_time_to_parsed_unixtime(data, http_time)
        self.assertEqual(parsed, '1445412480')


if __name__ == '__main__':
    unittest.main()
