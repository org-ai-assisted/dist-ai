#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
onion-time-pre-script output stability.

sdwdate's preparation loop lengthens its retry interval only for as long as
this script's output stays byte-identical between runs (sdwdate.py,
SdwdateClass.preparation). Tor's bootstrap line carries COUNT=, a retry counter
incremented on every failed connection attempt, so printing it verbatim
makes an offline Gateway emit a never-repeating message and hold the loop at
its minimum interval, re-spawning six Tor control port helpers per interval.

These tests pin BOTH directions: a pure counter tick must not change the
output, and a real status transition must still change it.
"""

import subprocess
import unittest

from onion_time_pre_script_testlib import PreScriptTestBase

## A Tor bootstrap warning as documented in tor_bootstrap_check.py, emitted
## while the network is unreachable. COUNT= increments per failed attempt.
WARN_COUNT_26 = (
    'WARN BOOTSTRAP PROGRESS=80 TAG=conn_or '
    'SUMMARY="Connecting to the Tor network" WARNING="No route to host" '
    'REASON=NOROUTE COUNT=26 RECOMMENDATION=warn'
)
WARN_COUNT_27 = WARN_COUNT_26.replace('COUNT=26', 'COUNT=27')
WARN_PROGRESS_85 = WARN_COUNT_26.replace('PROGRESS=80', 'PROGRESS=85')
WARN_REASON_TIMEOUT = WARN_COUNT_26.replace('REASON=NOROUTE', 'REASON=TIMEOUT')
DONE_LINE = 'NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"'


## Sourced subject, control port stubbed: check_tor_bootstrap_status publishes
## the canned status, so no Tor control port, privleap or root is involved.
BOOTSTRAP_BODY = '\n'.join(
    [
        'set -o pipefail',
        'check_tor_bootstrap_status() {',
        '   tor_bootstrap_status="$STUB_STATUS"',
        '}',
        'VM="$STUB_VM"',
        'tor_circuit_established_word="not established."',
        'tor_bootstrap_check',
    ]
)


class TestBootstrapOutputStability(PreScriptTestBase):
    """Drive the real tor_bootstrap_check with a stubbed control port."""

    def bootstrap_output(self, status: str, vm: str = 'Gateway') -> str:
        """Run tor_bootstrap_check against `status` and return its stdout."""
        result = self.run_sourced(BOOTSTRAP_BODY, STUB_STATUS=status, STUB_VM=vm)
        self.assertEqual(
            result.returncode,
            0,
            'tor_bootstrap_check failed: %s' % result.stderr,
        )
        ## Not a vacuous pass: the branch under test must actually have run.
        self.assertIn('Tor reports:', result.stdout, 'no bootstrap line emitted')
        return result.stdout

    def test_retry_counter_tick_does_not_change_output(self) -> None:
        """
        The regression. Two runs differing ONLY in Tor's retry counter must be
        byte-identical, otherwise sdwdate's backoff never advances.
        """
        self.assertEqual(
            self.bootstrap_output(WARN_COUNT_26),
            self.bootstrap_output(WARN_COUNT_27),
        )

    def test_counter_is_not_present_in_output(self) -> None:
        self.assertNotIn('COUNT=', self.bootstrap_output(WARN_COUNT_26))

    def test_progress_change_still_changes_output(self) -> None:
        """Over-redaction guard: a real transition must stay visible."""
        self.assertNotEqual(
            self.bootstrap_output(WARN_COUNT_26),
            self.bootstrap_output(WARN_PROGRESS_85),
        )

    def test_reason_change_still_changes_output(self) -> None:
        """Over-redaction guard: a changed failure mode must stay visible."""
        self.assertNotEqual(
            self.bootstrap_output(WARN_COUNT_26),
            self.bootstrap_output(WARN_REASON_TIMEOUT),
        )

    def test_neighbouring_fields_survive_redaction(self) -> None:
        out = self.bootstrap_output(WARN_COUNT_26)
        self.assertIn('REASON=NOROUTE', out)
        self.assertIn('RECOMMENDATION=warn', out)
        ## The counter is removed with its separator, leaving no double space.
        self.assertIn('REASON=NOROUTE RECOMMENDATION=warn', out)

    def test_counterless_line_passes_through_verbatim(self) -> None:
        self.assertIn(DONE_LINE, self.bootstrap_output(DONE_LINE))

    def test_timeout_reason_still_flagged(self) -> None:
        """Redaction must not break the REASON=TIMEOUT match at the call site."""
        self.assertIn(
            'Tor reports: REASON=TIMEOUT',
            self.bootstrap_output(WARN_REASON_TIMEOUT),
        )

    def test_workstation_does_not_emit_bootstrap_line(self) -> None:
        """
        A Workstation has no access to the Gateway's control port, so the
        volatile line never reaches its output at all.
        """
        result = self.run_sourced(
            BOOTSTRAP_BODY, STUB_STATUS=WARN_COUNT_26, STUB_VM='Workstation'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Tor reports:', result.stdout)
        self.assertIn('Tor circuit:', result.stdout)


class TestExitHandler(PreScriptTestBase):
    """
    The EXIT trap is the only thing that turns an unset exit_code into the
    documented 'wait, retry and error icon' contract sdwdate reads.
    """

    def run_exit_handler(
        self, preset: str = ''
    ) -> 'subprocess.CompletedProcess[str]':
        return self.run_sourced(
            '\n'.join(['set -o pipefail', preset, 'exit_handler'])
        )

    def test_unset_exit_code_becomes_one(self) -> None:
        """
        With no exit_code set, the handler must announce and actually apply 1.
        Leaving it empty makes the script 'exit ""', which bash rejects and
        turns into an exit status sdwdate then misreads.
        """
        result = self.run_exit_handler()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("exit_code '1'", result.stdout)
        self.assertIn('wait, show error icon and retry.', result.stdout)

    def test_explicit_exit_code_preserved(self) -> None:
        result = self.run_exit_handler(preset='exit_code=2')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("exit_code '2'", result.stdout)
        self.assertIn('wait, show busy icon and retry.', result.stdout)

    def test_success_exit_code_preserved(self) -> None:
        result = self.run_exit_handler(preset='exit_code=0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("indicating 'success'", result.stdout)


if __name__ == '__main__':
    unittest.main()
