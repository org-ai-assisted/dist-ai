#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for sdwdate.config parsers other than sort_pool (which has its own
suite):
  * read_pools              -- the SDWDATE_POOL_ZERO/ONE/TWO section state
    machine feeding sort_pool, '##'-comment skipping, no-dir / empty branches.
  * randomize_time_config   -- RANDOMIZE_TIME last-wins across sorted conf files.
  * time_replay_protection_file_read -- subtracts the 100s replay slack.
  * time_human_readable     -- UTC regardless of the process timezone.
  * get_comment / get_comment_pool_single -- url<->comment index pairing.

The on-disk /etc/sdwdate.d scan is redirected to real temp files (os.path.exists
and glob are stubbed); config.subprocess.Popen is stubbed for the replay read.
config has stdlib-only imports, so the lighter fuzz_sdwdate._load_config loader
is reused (matching test_config_sort_pool.py).
"""

import os
import subprocess
import tempfile
import time
import types
import unittest
from typing import Any

import fuzz_sdwdate

SDWDATE_D = '/etc/sdwdate.d/'


class ConfigBase(unittest.TestCase):
    config: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = fuzz_sdwdate._load_config()

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

    def _write_confs(self, files) -> None:
        """
        files: list of (basename, content). Redirect the hardcoded /etc/sdwdate.d
        scan at them -- os.path.exists(dir) True, glob returns the temp paths.
        """
        workdir = tempfile.mkdtemp(prefix='sdwdate-conf.')
        self.addCleanup(self._rmtree, workdir)
        paths = []
        for basename, content in files:
            path = os.path.join(workdir, basename)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(content)
            paths.append(path)
        real_exists = os.path.exists
        self._stub(
            self.config.os.path, 'exists',
            lambda p: True if p == SDWDATE_D else real_exists(p))
        self._stub(
            self.config.glob, 'glob', lambda pattern: sorted(paths))

    def _no_dir(self) -> None:
        real_exists = os.path.exists
        self._stub(
            self.config.os.path, 'exists',
            lambda p: False if p == SDWDATE_D else real_exists(p))

    def _empty_dir(self) -> None:
        real_exists = os.path.exists
        self._stub(
            self.config.os.path, 'exists',
            lambda p: True if p == SDWDATE_D else real_exists(p))
        self._stub(self.config.glob, 'glob', lambda pattern: [])

    @staticmethod
    def _rmtree(path: str) -> None:
        for root, _dirs, files in os.walk(path, topdown=False):
            for name in files:
                os.unlink(os.path.join(root, name))
        os.rmdir(path)


class ReadPoolsTest(ConfigBase):
    SECTIONS = (
        'SDWDATE_POOL_ZERO\n'
        '## a comment that must be skipped\n'
        '"a.onion # A"\n'
        'SDWDATE_POOL_ONE\n'
        '"b.onion # B"\n'
        'SDWDATE_POOL_TWO\n'
        '"c.onion # C"\n'
    )

    def test_sections_route_to_the_right_pool(self) -> None:
        self._write_confs([('30_pool.conf', self.SECTIONS)])
        self.assertEqual(
            self.config.read_pools(0, 'test'), (['a.onion'], ['A']))
        self.assertEqual(
            self.config.read_pools(1, 'test'), (['b.onion'], ['B']))
        self.assertEqual(
            self.config.read_pools(2, 'test'), (['c.onion'], ['C']))

    def test_no_directory_yields_empty_pools(self) -> None:
        self._no_dir()
        self.assertEqual(self.config.read_pools(0, 'test'), ([], []))

    def test_empty_directory_yields_empty_pools(self) -> None:
        self._empty_dir()
        self.assertEqual(self.config.read_pools(1, 'production'), ([], []))

    def test_production_picks_one_test_flattens_multiline(self) -> None:
        multiline = (
            'SDWDATE_POOL_ZERO\n'
            '[\n'
            '"a.onion # A"\n'
            '"b.onion # B"\n'
            ']\n'
        )
        self._write_confs([('30_pool.conf', multiline)])
        test_urls, _c = self.config.read_pools(0, 'test')
        self.assertEqual(sorted(test_urls), ['a.onion', 'b.onion'])
        ## production samples exactly one member of the block.
        self._stub(self.config.random, 'sample', lambda population, k: [0])
        prod_urls, _c2 = self.config.read_pools(0, 'production')
        self.assertEqual(prod_urls, ['a.onion'])


class RandomizeTimeConfigTest(ConfigBase):
    def test_true(self) -> None:
        self._write_confs([('30.conf', 'RANDOMIZE_TIME=true\n')])
        self.assertTrue(self.config.randomize_time_config())

    def test_false(self) -> None:
        self._write_confs([('30.conf', 'RANDOMIZE_TIME=false\n')])
        self.assertFalse(self.config.randomize_time_config())

    def test_last_file_in_sorted_order_wins(self) -> None:
        ## 00 sets true, 01 sets false -> processed in that order -> False.
        self._write_confs([
            ('00_a.conf', 'RANDOMIZE_TIME=true\n'),
            ('01_b.conf', 'RANDOMIZE_TIME=false\n'),
        ])
        self.assertFalse(self.config.randomize_time_config())

    def test_no_directory_is_false(self) -> None:
        self._no_dir()
        self.assertFalse(self.config.randomize_time_config())


class TimeReplayProtectionReadTest(ConfigBase):
    def test_subtracts_the_hundred_second_slack(self) -> None:
        def fake_popen(path, stdout=None, stderr=None):
            return types.SimpleNamespace(
                communicate=lambda: (b'1700000100', b'human readable\n'))

        self._stub(subprocess, 'Popen', fake_popen)
        unixtime, human = self.config.time_replay_protection_file_read()
        self.assertEqual(unixtime, 1700000000)   # 1700000100 - 100
        self.assertEqual(human, 'human readable')


class TimeHumanReadableTest(ConfigBase):
    def test_epoch_zero_is_utc_regardless_of_process_tz(self) -> None:
        ## Force a non-UTC process TZ; the subject passes tz=timezone.utc so the
        ## output must still be the UTC rendering of the epoch.
        saved_tz = os.environ.get('TZ')
        os.environ['TZ'] = 'America/New_York'
        time.tzset()
        try:
            self.assertEqual(
                self.config.time_human_readable(0), '1970-01-01 00:00:00')
        finally:
            if saved_tz is None:
                del os.environ['TZ']
            else:
                os.environ['TZ'] = saved_tz
            time.tzset()


class GetCommentTest(ConfigBase):
    def _pool(self, urls, comments):
        return types.SimpleNamespace(url=list(urls), comment=list(comments))

    def test_get_comment_returns_paired_comment(self) -> None:
        pools = [
            self._pool(['a.onion'], ['A']),
            self._pool(['b.onion', 'c.onion'], ['B', 'C']),
        ]
        self.assertEqual(self.config.get_comment(pools, 'c.onion'), 'C')

    def test_get_comment_unknown_url_sentinel(self) -> None:
        pools = [self._pool(['a.onion'], ['A'])]
        self.assertEqual(
            self.config.get_comment(pools, 'absent.onion'), 'unknown-comment')

    def test_get_comment_pool_single_paired(self) -> None:
        pool = self._pool(['a.onion', 'b.onion'], ['A', 'B'])
        self.assertEqual(
            self.config.get_comment_pool_single(pool, 'b.onion'), 'B')

    def test_get_comment_pool_single_unknown_sentinel(self) -> None:
        pool = self._pool(['a.onion'], ['A'])
        self.assertEqual(
            self.config.get_comment_pool_single(pool, 'absent.onion'),
            'unknown-comment')


if __name__ == '__main__':
    unittest.main()
