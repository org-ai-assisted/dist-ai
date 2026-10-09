#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for the systemcheck Tor bootstrap privleap guard
(check_tor_bootstrap_require_leaprun). They need no absolute-path fixture.
check_tor_config / check_tor_running / check_tor_enabled are gated on
absolute-path markers: systemcheck-tests-bwrap
test_check_scenarios_tor_isolated.py.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    extract_bash_function,
    run_bash_function,
    run_check_scenario,
)


class TestTorBootstrapLeaprunGuard(ScenarioTestBase):
    """check_tor_bootstrap_require_leaprun: the #100 fail-fast guard.

    systemcheck reads Tor's bootstrap percentage and circuit status via privleap
    (leaprun). When privleapd is unreachable for the account running systemcheck
    (e.g. a session with no /run/privleapd/comm/<user> socket), those reads fail
    and, without this guard, are indistinguishable from "Tor not established
    yet": the check_tor_bootstrap loop then waits out the whole budget and
    systemcheck is SIGTERMed with an ambiguous CI_EXIT=124 that hides the real
    cause (exactly the mis-diagnosis #100 chased for multiple sessions). The
    guard must instead FAIL FAST with the specific privleapd-unavailable message.

    These drive the RESOLVED `use_leaprun` global directly -- the same variable
    the real use_leaprun.sh sets -- so no bubblewrap/absolute-path fixture is
    needed (the guard only sources use_leaprun.sh when the global is unset).
    """

    FILE = 'check_tor_bootstrap.bsh'
    ## cleanup() (-> ex_funct -> exit) is a bare-name call; a no-op stub lets the
    ## function return so the scenario can record EXIT_CODE instead of exiting.
    CLEANUP = 'cleanup() { :; }'
    ## The guard RE-PROBES via leaprun_useable_test every call (never trusting a
    ## stale use_leaprun global), so drive that function -- the same seam the real
    ## use_leaprun.sh defines -- rather than presetting the variable.
    PROBE_NO = (
        'leaprun_useable_test() { use_leaprun=no; '
        "leaprun_useable_result=\"WARNING: Cannot communicate with privleapd. "
        "File '/run/privleapd/comm/1001' does not exist. Cannot use privleap.\"; }")
    PROBE_YES = 'leaprun_useable_test() { use_leaprun=yes; }'

    def test_privleap_unusable_fails_fast_with_diagnosis(self) -> None:
        ## privleap unusable -> error emitted, the specific privleapd diagnosis is
        ## surfaced (not swallowed), EXIT_CODE 1. On pre-fix code the guard is
        ## absent, so assertCleanRun catches the "command not found" (canary).
        r = run_check_scenario(
            self.check(self.FILE), 'check_tor_bootstrap_require_leaprun',
            stubs=self.CLEANUP + '\n' + self.PROBE_NO)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('error'))
        self.assertFalse(r.has_severity('info'))
        self.assertIn('Cannot query', r.joined())
        self.assertIn('privleap', r.joined())
        self.assertIn('/run/privleapd/comm/1001', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_privleap_usable_is_noop(self) -> None:
        ## privleap usable -> guard returns 0, emits nothing, EXIT_CODE stays 0
        ## (the normal-session path: the real Tor bootstrap/circuit checks then
        ## run exactly as before).
        r = run_check_scenario(
            self.check(self.FILE), 'check_tor_bootstrap_require_leaprun',
            stubs=self.CLEANUP + '\n' + self.PROBE_YES)
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, '0')

    def test_reprobes_not_trusting_stale_use_leaprun(self) -> None:
        ## Regression for the stale-global bug: even if use_leaprun is already
        ## 'yes' in the environment (as it is at systemcheck runtime, set once at
        ## startup), a fresh probe reporting privleap now unusable must still fail
        ## fast. A guard that trusted the cached 'yes' would wrongly return 0 here.
        r = run_check_scenario(
            self.check(self.FILE), 'check_tor_bootstrap_require_leaprun',
            env_setup='use_leaprun=yes', stubs=self.CLEANUP + '\n' + self.PROBE_NO)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('error'))
        self.assertEqual(r.exit_code, '1')

    def test_guard_is_wired_before_tor_query(self) -> None:
        ## A correct guard that is never CALLED would still pass the two tests
        ## above while the runtime re-enters the wait->timeout. Assert the public
        ## check_tor_bootstrap loop invokes check_tor_bootstrap_require_leaprun,
        ## and does so BEFORE check_tor_bootstrap_init (which sources the leaprun
        ## helper and begins the Tor-query/wait path) -- so a privleap-unusable
        ## session fails fast rather than looping. Pre-fix, the guard name is
        ## absent from the loop body and assertIn fails (canary).
        body = extract_bash_function(self.check(self.FILE), 'check_tor_bootstrap')
        self.assertIn('check_tor_bootstrap_require_leaprun', body)
        self.assertLess(
            body.index('check_tor_bootstrap_require_leaprun'),
            body.index('check_tor_bootstrap_init'),
            'the leaprun guard must run before check_tor_bootstrap_init')

    def test_privleap_usable_guard_returns_zero(self) -> None:
        ## run_check_scenario discards the guard's own $? (it runs under `set +e`),
        ## so test_privleap_usable_is_noop cannot see it. Source the extracted guard
        ## and call it: a `return 1` usable-branch -- which would make
        ## `check_tor_bootstrap_require_leaprun || break` wrongly skip the whole Tor
        ## check -- is caught here. The usable path returns before any emit/cleanup,
        ## so only the probe stub is needed. The `if` suspends errexit for the guard
        ## body so a non-zero return is captured rather than aborting the run.
        guard = extract_bash_function(
            self.check(self.FILE), 'check_tor_bootstrap_require_leaprun')
        status = run_bash_function(
            self.PROBE_YES + '\n' + guard,
            'if check_tor_bootstrap_require_leaprun; then echo "RET:0";'
            ' else echo "RET:nonzero"; fi')
        self.assertEqual(status, 'RET:0')

    def test_privleap_unusable_guard_returns_nonzero(self) -> None:
        ## The fail-fast guarantee needs the guard to RETURN non-zero so the loop's
        ## `|| break` fires; the wiring test proves it is CALLED before init but not
        ## that it breaks. An unusable branch that set EXIT_CODE=1 yet `return 0`
        ## would pass test_privleap_unusable_fails_fast_with_diagnosis (which checks
        ## the EXIT_CODE global) while the loop kept waiting -- the exact #100 hang.
        ## emit_message is the REAL preparation.bsh helper; only its output channel
        ## is redirected via the production output_x/output_cli command-name seam.
        guard = extract_bash_function(
            self.check(self.FILE), 'check_tor_bootstrap_require_leaprun')
        emit = extract_bash_function(self.preparation, 'emit_message')
        status = run_bash_function(
            self.CLEANUP + '\n' + self.PROBE_NO + '\n' + emit + '\n' + guard,
            'if check_tor_bootstrap_require_leaprun; then echo "RET:0";'
            ' else echo "RET:nonzero"; fi',
            env_setup='output_x=true\noutput_cli=true\noutput_opts=()')
        self.assertEqual(status, 'RET:nonzero')


if __name__ == '__main__':
    unittest.main()
