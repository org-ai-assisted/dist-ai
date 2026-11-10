#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: check_privilege_escalation_tool.bsh must SKIP its sudo/pkexec
self-checks under no_new_privs, without false-failing.

systemcheck.service runs W^X-hardened with NoNewPrivileges, and any
`systemd --user` unit's W^X seccomp forces PR_SET_NO_NEW_PRIVS=1 regardless.
Under NoNewPrivs=1 the kernel refuses to honor the setuid bit, so `sudo` and
`pkexec` ABORT by design -- not from misconfiguration. Before the fix
(no_new_privs_active + the gate), check_privilege_escalation_tools ran those
setuid self-checks unconditionally, so every hardened autostart run hit the
worker's "any non-zero exit OR any output is a failure" rule and raised a
spurious `error` with EXIT_CODE=1 on a perfectly configured system.

The detector reads /proc/self/status's NoNewPrivs field, so the two regimes are
exercised against the REAL kernel bit: NoNewPrivs=1 via `setpriv --no-new-privs`
(run_check_scenario(no_new_privs=True)), NoNewPrivs=0 plain. No /proc mock.

Locked here:
  * NoNewPrivs=1 -> the sudo/pkexec checks are skipped with a benign N/A line,
    NO error, EXIT_CODE stays 0, and the 4 mandatory privleapd/leaprun checks
    STILL run (they use a non-setuid socket client, unaffected by no_new_privs).
    This is the exact case that false-failed before the fix (canary: on the
    pre-fix fragment the sudo check runs and raises error + EXIT_CODE=1).
  * NoNewPrivs=0 -> the detector does NOT blanket-skip: the setuid checks run,
    a clean sudo/pkexec passes, and a failing one still surfaces as error.
  * no_new_privs_active() itself is true under NoNewPrivs=1, false otherwise.

The subject is resolved by systemcheck_testlib (SYSTEMCHECK_REPO).
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)

## The 4 privleapd/leaprun checks that must run in BOTH regimes (they use the
## non-setuid privleapd socket client, so no_new_privs never gates them).
LEAPRUN_CHECKS = (
    'privleapd --check-config',
    'leaprun check-privleap',
    'leaprun check-privleap-environment-variables',
    'leaprun check-sudo',
)

## leaprun/privleapd succeed silently: the worker treats ANY output as a failure,
## so a passing stub must emit nothing and exit 0.
LEAPRUN_OK_STUBS = (
    'privleapd() { return 0; }\n'
    'leaprun() { return 0; }\n'
)

## sudo/pkexec as they behave under no_new_privs: the setuid exec cannot elevate,
## so the tool aborts non-zero with a diagnostic. The worker must treat this as a
## failure -- which is exactly why the pre-fix code false-failed, and why the fix
## skips these under no_new_privs instead.
SUDO_PKEXEC_ABORT_STUBS = (
    'sudo() { printf "%s\\n" "sudo: a password is required" >&2; return 1; }\n'
    'pkexec() { printf "%s\\n" "pkexec: operation not permitted" >&2; return 1; }\n'
)

## sudo/pkexec on a correctly configured interactive host (no_new_privs unset):
## the check is meaningful and passes (exit 0, no output).
SUDO_PKEXEC_OK_STUBS = (
    'sudo() { return 0; }\n'
    'pkexec() { return 0; }\n'
)

## use_sudo/use_pkexec are set by the sourced use_*.sh from system state; force
## both on so the setuid checks are reached whenever the gate allows them.
USE_BOTH = 'use_sudo=yes\nuse_pkexec=yes\nverbose=1'


class NoNewPrivsPrivescGating(ScenarioTestBase):
    FILE = 'check_privilege_escalation_tool.bsh'
    CALL = 'check_privilege_escalation_tools'

    def _assert_leaprun_checks_ran(self, result) -> None:
        joined = result.joined()
        for check in LEAPRUN_CHECKS:
            self.assertIn(
                check, joined,
                'mandatory privleapd/leaprun check %r did not run -- the '
                'no_new_privs gate must only skip sudo/pkexec, never the '
                'socket-client checks' % check)

    def test_nnp1_skips_sudo_pkexec_without_false_fail(self) -> None:
        ## The regression: under NoNewPrivs=1 the sudo/pkexec checks must be
        ## skipped with a benign N/A line, no error, EXIT_CODE unchanged. On the
        ## pre-fix fragment the sudo check runs, hits the abort stub, and raises
        ## error + EXIT_CODE=1 -- so this case is the canary (RED on old code).
        r = run_check_scenario(
            self.check(self.FILE), self.CALL,
            env_setup=USE_BOTH,
            stubs=LEAPRUN_OK_STUBS + SUDO_PKEXEC_ABORT_STUBS,
            no_new_privs=True)
        self.assertCleanRun(r)
        self.assertFalse(
            r.has_severity('error'),
            'under no_new_privs the sudo/pkexec abort must NOT be reported as a '
            'misconfiguration error: %r' % r.joined())
        self.assertEqual(r.exit_code, '0')
        self.assertIn(
            'no_new_privs', r.joined(),
            'the skip must emit the benign N/A (no_new_privs) status line')
        self._assert_leaprun_checks_ran(r)

    def test_nnp0_runs_sudo_pkexec_clean_no_skip(self) -> None:
        ## NoNewPrivs=0: the detector must NOT blanket-skip. A clean sudo/pkexec
        ## passes, no N/A line is emitted, and the setuid checks really ran.
        r = run_check_scenario(
            self.check(self.FILE), self.CALL,
            env_setup=USE_BOTH,
            stubs=LEAPRUN_OK_STUBS + SUDO_PKEXEC_OK_STUBS,
            no_new_privs=False)
        self.assertCleanRun(r)
        self.assertFalse(r.has_severity('error'))
        self.assertEqual(r.exit_code, '0')
        self.assertNotIn(
            'no_new_privs', r.joined(),
            'the N/A (no_new_privs) skip must NOT fire when NoNewPrivs=0')
        self.assertIn('Check \'<code>sudo</code>', r.joined(),
                      'the sudo self-check must run when NoNewPrivs=0')
        self.assertIn('pkexec-test', r.joined(),
                      'the pkexec self-check must run when NoNewPrivs=0')
        self._assert_leaprun_checks_ran(r)

    def test_nnp0_failing_sudo_still_errors(self) -> None:
        ## Proves the fix did not over-skip: with no_new_privs unset, a genuinely
        ## broken sudo must still surface as error + EXIT_CODE=1.
        r = run_check_scenario(
            self.check(self.FILE), self.CALL,
            env_setup=USE_BOTH,
            stubs=LEAPRUN_OK_STUBS + SUDO_PKEXEC_ABORT_STUBS,
            no_new_privs=False)
        self.assertCleanRun(r)
        self.assertTrue(
            r.has_severity('error'),
            'a failing sudo check with NoNewPrivs=0 must still be reported')
        self.assertEqual(r.exit_code, '1')

    def test_leaprun_checks_unconditional_under_nnp1(self) -> None:
        ## The 4 socket-client checks must run even when the sudo/pkexec checks
        ## are gated off -- they are mandatory and unaffected by no_new_privs.
        r = run_check_scenario(
            self.check(self.FILE), self.CALL,
            env_setup=USE_BOTH,
            stubs=LEAPRUN_OK_STUBS + SUDO_PKEXEC_ABORT_STUBS,
            no_new_privs=True)
        self.assertCleanRun(r)
        self._assert_leaprun_checks_ran(r)

    def test_detector_true_under_nnp1_false_otherwise(self) -> None:
        ## Direct unit test of no_new_privs_active() against the real kernel bit.
        call = ('if no_new_privs_active; then printf "DET\\tactive\\n"; '
                'else printf "DET\\tinactive\\n"; fi')
        active = run_check_scenario(
            self.check(self.FILE), call, no_new_privs=True)
        self.assertIn('DET\tactive', active.stdout)
        self.assertNotIn('DET\tinactive', active.stdout)
        inactive = run_check_scenario(
            self.check(self.FILE), call, no_new_privs=False)
        self.assertIn('DET\tinactive', inactive.stdout)
        self.assertNotIn('DET\tactive', inactive.stdout)


if __name__ == '__main__':
    unittest.main()
