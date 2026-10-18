#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for SdwdateClass.sdwdate_fetch_loop -- the multi-iteration state
machine that picks a URL per pool, fetches times, and decides error vs success.

Driven on a fake-self holding the real instance attributes; get_time_from_servers
is stubbed to return scripted per-URL results, and secrets.choice is scripted so
URL selection is deterministic. The exercised terminal paths:
  * pool exhaustion     -- every URL in a pool tried, none valid -> "error".
  * failure quorum      -- failed URLs exceed allowed_failures -> "error".
  * general timeout      -- 3 "timeout" statuses from iteration 2 -> "error".
  * multi-iteration recovery -- a pool that succeeded is not re-fetched; the run
    reaches success across two iterations.
Plus the pure general_timeout_error staticmethod.

The subject is imported for real via sdwdate_testlib (SDWDATE_REPO).
"""

import os
import tempfile
import types
import unittest
from typing import Any

import sdwdate_testlib

NOW = 1_700_000_500.0


def _pool(urls):
    return types.SimpleNamespace(
        url=list(urls), already_picked_index=[], url_random_pool=[],
        done=False)


class FetchLoopBase(unittest.TestCase):
    sdwdate: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.sdwdate = sdwdate_testlib.import_sdwdate()

    def setUp(self) -> None:
        module = self.sdwdate
        self._saved: list[tuple] = []
        self.status_writes: list[tuple] = []
        self.get_time_calls: list[list] = []
        self.url_status: dict[str, str] = {}
        self._choices: list[int] = []

        self._stub(module, 'LOGGER', sdwdate_testlib.RecordingLogger())
        self._stub(module, 'translate_object', lambda key: key)
        self._stub(
            module, 'write_status',
            lambda icon, msg: self.status_writes.append((icon, msg)))
        self._stub(module, 'get_time_from_servers', self._fake_get_time)
        self._stub(module.secrets, 'choice', self._scripted_choice)
        self._stub(module.time, 'time', lambda: NOW)
        self._stub(module, 'proxy_ip', '127.0.0.1')
        self._stub(module, 'proxy_port', '9050')

        ## status_first_success_path is only os.path.exists'd for the icon; point
        ## it at a guaranteed-absent path.
        workdir = tempfile.mkdtemp(prefix='sdwdate-fetch.')
        self.addCleanup(os.rmdir, workdir)
        self._stub(
            module, 'status_first_success_path',
            os.path.join(workdir, 'absent_first_success'))

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

    def _scripted_choice(self, seq):
        self.assertTrue(
            self._choices, 'secrets.choice called more times than scripted')
        return self._choices.pop(0)

    def _fake_get_time(self, pools, requested, proxy_ip, proxy_port):
        self.get_time_calls.append(list(requested))
        urls, statuses, unixtimes, tooks, halfs, raws, lags = \
            [], [], [], [], [], [], []
        for url in requested:
            urls.append(url)
            statuses.append(self.url_status[url])
            ## Valid-time payload (only read for an "ok" url).
            unixtimes.append(1700000000)
            tooks.append(1.0)
            halfs.append(0.5)
            raws.append(0)
            lags.append(0.0)
        return urls, statuses, unixtimes, tooks, halfs, raws, lags

    def _make_self(self, pools, allowed_failures):
        return types.SimpleNamespace(
            iteration=0,
            pools=pools,
            number_of_pools=len(pools),
            allowed_failures=allowed_failures,
            list_of_urls_returned=[],
            list_of_url_random_requested=[],
            list_of_status=[],
            list_of_unixtimes=[],
            list_of_took_time=[],
            list_of_half_took_time=[],
            list_off_time_diff_raw_int=[],
            list_off_time_diff_lag_cleaned_float=[],
            request_unixtimes={},
            request_took_times={},
            valid_urls=[],
            unixtimes=[],
            half_took_time_float={},
            time_diff_raw_int={},
            time_diff_lag_cleaned_float={},
            list_of_pools_raw_diff=[],
            pools_lag_cleaned_diff=[],
            failed_urls=[],
            general_timeout_error=self.sdwdate.SdwdateClass.general_timeout_error)

    def _run(self, fake):
        return self.sdwdate.SdwdateClass.sdwdate_fetch_loop(fake)


class GeneralTimeoutErrorStaticTest(FetchLoopBase):
    def test_all_three_timeout_is_true(self) -> None:
        self.assertTrue(
            self.sdwdate.SdwdateClass.general_timeout_error(
                ['timeout', 'timeout', 'timeout']))

    def test_mixed_is_false(self) -> None:
        self.assertFalse(
            self.sdwdate.SdwdateClass.general_timeout_error(
                ['timeout', 'ok', 'timeout']))


class FetchLoopTerminalTest(FetchLoopBase):
    def test_pool_exhaustion_returns_error(self) -> None:
        ## 3 single-URL pools, all fetches fail -> no pool goes done; iteration 2
        ## re-picks the only index and exhausts the pool.
        pools = [_pool(['p0u0']), _pool(['p1u0']), _pool(['p2u0'])]
        for url in ('p0u0', 'p1u0', 'p2u0'):
            self.url_status[url] = 'error'
        self._choices = [0, 0, 0, 0]
        status = self._run(self._make_self(pools, allowed_failures=99))
        self.assertEqual(status, 'error')
        self.assertTrue(
            any(icon == 'error' for icon, _msg in self.status_writes))

    def test_failure_quorum_gives_up(self) -> None:
        ## failed URLs (3) exceed allowed_failures (2) -> giving up in iteration 1.
        pools = [_pool(['p0u0']), _pool(['p1u0']), _pool(['p2u0'])]
        for url in ('p0u0', 'p1u0', 'p2u0'):
            self.url_status[url] = 'error'
        self._choices = [0, 0, 0]
        status = self._run(self._make_self(pools, allowed_failures=2))
        self.assertEqual(status, 'error')
        self.assertTrue(
            any('Giving up' in msg for _icon, msg in self.status_writes),
            'failure-quorum message not written')

    def test_general_timeout_from_second_iteration(self) -> None:
        ## 3 two-URL pools; every fetch times out. Iteration 1 cannot trip the
        ## general-timeout gate (it only arms at iteration >= 2); iteration 2 does.
        pools = [_pool(['p0u0', 'p0u1']),
                 _pool(['p1u0', 'p1u1']),
                 _pool(['p2u0', 'p2u1'])]
        for url in ('p0u0', 'p0u1', 'p1u0', 'p1u1', 'p2u0', 'p2u1'):
            self.url_status[url] = 'timeout'
        self._choices = [0, 0, 0, 1, 1, 1]
        status = self._run(self._make_self(pools, allowed_failures=99))
        self.assertEqual(status, 'error')
        self.assertTrue(
            any(msg == 'general_timeout_error'
                for _icon, msg in self.status_writes),
            'general_timeout_error status not written')

    def test_multi_iteration_recovery_does_not_refetch_done_pool(self) -> None:
        ## Pool 0 succeeds in iteration 1; pools 1 and 2 recover on iteration 2.
        ## The run reaches success and pool 0's URL is NOT requested again.
        pools = [_pool(['p0u0']),
                 _pool(['p1u0', 'p1u1']),
                 _pool(['p2u0', 'p2u1'])]
        self.url_status = {
            'p0u0': 'ok',
            'p1u0': 'error', 'p2u0': 'error',
            'p1u1': 'ok', 'p2u1': 'ok',
        }
        self._choices = [0, 0, 0, 1, 1]
        status = self._run(self._make_self(pools, allowed_failures=99))
        self.assertEqual(status, 'success')
        self.assertEqual(len(self.get_time_calls), 2)
        self.assertNotIn(
            'p0u0', self.get_time_calls[1],
            'a done pool was re-fetched on the second iteration')


if __name__ == '__main__':
    unittest.main()
