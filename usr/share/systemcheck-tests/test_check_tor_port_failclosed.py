#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Fail-closed scenario tests for check_tor_socks_or_trans_port (systemcheck).

This check is a POSITIVE CONTROL: dm-whonix-pair runs its per-port wrappers
(check_tor_socks_port / check_tor_trans_port) to confirm live Tor egress before
trusting a leak-test result. A connection FAILURE on a Whonix-Workstation (a dead
or half-broken Tor link) must make the check exit NONZERO -- a red error that
exits 0 is a false green that would mask the dead link the control exists to catch.

The curl-failure branch classifies the result (info for an EXPECTED-unreachable
port -- Whonix-Gateway's absent TransPort, a Qubes TemplateVM -- else error) and
must set EXIT_CODE=1 for ANY error-typed failure. These scenarios drive the real
extracted function with a stubbed curl that fails to connect:

  * TransPort on a Whonix-Workstation  -> error, EXIT_CODE 1  (the regression;
    pre-fix the branch pre-set type=error but EXIT_CODE stayed 0 -> false green,
    so assertEqual(exit_code, '1') FAILS on old code = canary).
  * SocksPort on a Whonix-Workstation  -> error, EXIT_CODE 1  (guards the path
    that was already fail-closed).
  * TransPort on a Whonix-Gateway      -> info, EXIT_CODE 0   (the expected-
    unreachable case must stay non-failing).

The failure branch calls /usr/libexec/helper-scripts/curl_exit_codes by absolute
path, so each scenario runs in a bubblewrap mount namespace with a stub bound
there; SkipTest when bubblewrap / user namespaces are unavailable.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario_isolated,
)

## curl stub: exit 7 (could not connect) so the check takes its curl-failure
## branch -- the dead-link condition a positive control must fail on.
CURL_FAIL = 'curl() { return 7; }'
## SocksPort builds a stream-isolation user name via this helper-scripts function
## (not in this fragment); a stub keeps the SocksPort scenario off a bare
## command-not-found that assertCleanRun would flag.
RANDOM_USER = 'random_alpha_numeric() { printf aaaa; }'
## The curl-failure branch translates the exit code via this ABSOLUTE path; bind a
## stub there so the branch does not hit command-not-found inside the namespace.
CURL_EXIT_CODES = (
    '/usr/libexec/helper-scripts/curl_exit_codes',
    '#!/bin/bash\nprintf "curl exit %s" "${1:-?}"\n',
    True,
)

## Globals the orchestrator would set before the check runs (the scenario preamble
## already provides EXIT_CODE / status_ok / verbose / silent / output_*).
BASE_ENV = (
    'leak_tests=true\n'
    'silent=0\n'
    'NOT_USING_TOR=0\n'
    'GATEWAY_IP=10.152.152.10\n'
    'CURL=curl\n'
    'CURL_VERBOSE=\n'
    'CURL_TPO_PIN_CERT=\n'
    'TEMP_DIR=/tmp\n'  # nosec B108 -- unused on the curl-failure branch; never written
)


class TestTorPortFailClosed(ScenarioTestBase):
    FILE = 'check_tor_socks_or_trans_port.bsh'

    def _env(self, vm: str) -> str:
        return BASE_ENV + f'VM={vm}\n'

    def test_transport_connection_failure_fails_closed(self) -> None:
        ## TransPort unreachable on a Whonix-Workstation -> error + EXIT_CODE 1.
        ## Pre-fix the branch pre-set type=error yet left EXIT_CODE 0, so this
        ## assertEqual FAILS on old code (canary with teeth).
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_tor_trans_port',
            env_setup=self._env('Whonix-Workstation'),
            stubs=CURL_FAIL + '\n' + RANDOM_USER,
            bind_files=[CURL_EXIT_CODES])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('error'))
        self.assertEqual(r.exit_code, '1')

    def test_socks_connection_failure_fails_closed(self) -> None:
        ## SocksPort unreachable on a Whonix-Workstation -> error + EXIT_CODE 1
        ## (already fail-closed; this guards it does not regress).
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_tor_socks_port',
            env_setup=self._env('Whonix-Workstation'),
            stubs=CURL_FAIL + '\n' + RANDOM_USER,
            bind_files=[CURL_EXIT_CODES])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('error'))
        self.assertEqual(r.exit_code, '1')

    def test_transport_on_gateway_stays_info(self) -> None:
        ## A Whonix-Gateway has no TransPort by default, so an unreachable
        ## TransPort there is EXPECTED -> info, EXIT_CODE stays 0. Guards the fix
        ## against over-failing the legitimately-informational case.
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_tor_trans_port',
            env_setup=self._env('Whonix-Gateway'),
            stubs=CURL_FAIL + '\n' + RANDOM_USER,
            bind_files=[CURL_EXIT_CODES])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('error'))
        self.assertEqual(r.exit_code, '0')


if __name__ == '__main__':
    unittest.main()
