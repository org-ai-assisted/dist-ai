#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: config.sort_pool must not crash on a malformed pool file.

Two production-mode inputs the fuzzer flags, both required to parse cleanly:
  * an empty multi-line "[" .. "]" block -- the picker must not sample from an
    empty population.
  * a line matching the url regex but not the comment regex -- the url and
    comment lists must stay in lockstep so the paired index stays valid.

The loader is reused from fuzz_sdwdate.
"""

import unittest

import fuzz_sdwdate


class SortPoolRobustness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = fuzz_sdwdate._load_config()

    def _assert_pair_of_lists(self, result):
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        urls, comments = result
        self.assertIsInstance(urls, list)
        self.assertIsInstance(comments, list)
        ## The two lists must stay in lockstep; get_comment pairs them by index.
        self.assertEqual(len(urls), len(comments))
        return urls, comments

    def test_empty_multiline_pool_no_crash(self):
        result = self.config.sort_pool(['[', ']'], 'production')
        urls, comments = self._assert_pair_of_lists(result)
        self.assertEqual(urls, [])
        self.assertEqual(comments, [])

    def test_desynced_url_only_line_no_indexerror(self):
        ## '"abc#def' matches the url regex ("(.*)#) but not the comment regex
        ## (#(.*)"): sort_pool must keep the url and comment lists in lockstep so
        ## the production picker cannot index past the shorter list.
        result = self.config.sort_pool(['[', '"abc#def', ']'], 'production')
        self._assert_pair_of_lists(result)

    def test_wellformed_multiline_pool_picks_one(self):
        ## A valid multi-line block still yields exactly one picked member.
        pool = ['[', '"a.onion # A"', '"b.onion # B"', ']']
        urls, comments = self._assert_pair_of_lists(
            self.config.sort_pool(pool, 'production'))
        self.assertEqual(len(urls), 1)
        self.assertIn(urls[0], ('a.onion', 'b.onion'))

    def test_test_mode_flattens_all_members(self):
        pool = ['[', '"a.onion # A"', '"b.onion # B"', ']']
        urls, comments = self._assert_pair_of_lists(
            self.config.sort_pool(pool, 'test'))
        self.assertEqual(urls, ['a.onion', 'b.onion'])
        self.assertEqual(comments, ['A', 'B'])


if __name__ == '__main__':
    unittest.main()
