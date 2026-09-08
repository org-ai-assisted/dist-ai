#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
onion-time-pre-script exit-code contract.

sdwdate interprets this script's exit code (documented at its top):
    0 = success
    1 = wait, show error icon and retry
    2 = wait, show busy icon and retry

These tests pin that contract across the Tor / system states the script
branches on, so enabling full strict mode (set -o nounset) cannot silently
change which code a state produces. The whole real script is sourced (its
was_executed guard keeps it from auto-running) and driven through its real
entry point te_pe_tb_check; only the I/O boundary (VM-type marker files, the
/run state folder, timesanitycheck) and the Tor-control collaborators (the
sourced .bsh functions) are stubbed to select a state -- the exit-code decision
logic under test is the script's own.

The harness runs under the SAME strict options the script sets when executed,
INCLUDING nounset, so an unset-prone reference that the refactor must guard
shows up here as a failing case (not a silent pass).
"""

import os
import time
import unittest

from onion_time_pre_script_testlib import (
    PreScriptTestBase,
    run_bash,
    stub_env,
)


def _helper_scripts_path() -> str:
    """
    Root of a helper-scripts checkout, so the sourced script can load its .bsh
    siblings (check_runtime.bsh, tor_bootstrap_check.bsh, ...). Prefer an
    explicit HELPER_SCRIPTS_PATH, else the repo the subject came from
    (ONION_TIME_PRE_SCRIPT_REPO, wired by dist-ai-tests-all).
    """
    explicit = os.environ.get('HELPER_SCRIPTS_PATH', '').strip()
    if explicit:
        return explicit
    return os.environ.get('ONION_TIME_PRE_SCRIPT_REPO', '').strip()


## Default state: Gateway, Tor enabled, not dormant, control port reachable,
## no circuit, bootstrap mid-way, consensus "ok", not rate limited. Each
## scenario overrides only the keys that select its state.
_DEFAULTS = {
    'vm': 'Gateway',
    'boot': 'false',
    'static_failed': '',
    'tor_enabled': '1',
    'dormant': '0',
    ## exit code of check_tor_circuit_established (0 = reached the control port)
    'cc_exit': '0',
    'bootstrap': '50',
    'circuit_est': '0',
    ## exit code of check_tor_circuit_built (0 = a fresh circuit was built)
    'built_exit': '1',
    ## consensus verdict selector: 'ok' | 'slow' | 'fast' | 'noneyet' | 'error'
    'consensus': 'ok',
    ## return code of anondate_request_rate_limited (0 = rate limited)
    'rate_limited_rc': '1',
    ## keep the real anondate_folder (exercises the USER path) when True
    'real_anondate_folder': False,
    'user': 'sdwdate',
}


class TestExitCodeContract(PreScriptTestBase):
    """Drive the real te_pe_tb_check across states; assert the sdwdate code."""

    helper_scripts_path: str

    def _consensus_stub(self, kind: str, now: int) -> str:
        """
        Bodies for tor_consensus_valid-after / -until that make the REAL
        tor_consensus_time_sanity_check reach the wanted verdict. 'now' anchors
        the fixture times a full hour off the wall clock so the run's own
        `date +%s` still lands on the intended side.
        """
        after: "int | str" = now - 3600
        until: "int | str" = now + 3600
        aec = '0'
        uec = '0'
        if kind == 'ok':
            pass
        elif kind == 'slow':
            after = now + 3600
            until = now + 7200
        elif kind == 'fast':
            after = now - 7200
            until = now - 3600
        elif kind == 'noneyet':
            after = until = ''
            aec = uec = '277'
        elif kind == 'error':
            after = until = ''
            aec = uec = '9'
        else:
            raise ValueError('unknown consensus kind %r' % kind)
        after_s = '' if after == '' else str(after)
        until_s = '' if until == '' else str(until)
        return '\n'.join(
            [
                'tor_consensus_valid-after() {',
                '   tor_consensus_valid_after_unixtime="%s"' % after_s,
                '   tor_consensus_valid_after_output="stub"',
                '   tor_consensus_valid_after_exit_code="%s"' % aec,
                '}',
                'tor_consensus_valid-until() {',
                '   tor_consensus_valid_until_unixtime="%s"' % until_s,
                '   tor_consensus_valid_until_output="stub"',
                '   tor_consensus_valid_until_exit_code="%s"' % uec,
                '}',
            ]
        )

    def run_scenario(self, **overrides: object) -> 'tuple[int, str, str]':
        """
        Source the real script, override the I/O + Tor-control boundary to
        select the state, then run te_pe_tb_check under full strict mode
        (nounset included). Returns (returncode, stdout, stderr).
        """
        cfg = dict(_DEFAULTS)
        cfg.update(overrides)
        now = int(time.time())
        state_dir = self.state_dir

        stubs = []
        if not cfg['real_anondate_folder']:
            stubs.append(
                'anondate_folder() { anondate_state_folder="%s"; }' % state_dir
            )
        stubs += [
            'onion_time_script_status() { onion_time_script_status_boot="%s"; }'
            % cfg['boot'],
            'timesanitycheck_static() {'
            ' timesanitycheck_static_timestamp_based_failed="%s"; }'
            % cfg['static_failed'],
            'detect_vm_type() { VM="%s"; }' % cfg['vm'],
            'check_tor_enabled_do() { TOR_ENABLED="%s"; }' % cfg['tor_enabled'],
            'check_tor_dormant_status() {'
            ' tor_dormant_status="%s"; tor_dormant_type="stub"; }'
            % cfg['dormant'],
            'run_signal_newnym() { :; }',
            ## Stubs set EXACTLY the variables their real tor_bootstrap_check.bsh
            ## counterparts set -- no more -- so a reference the real code leaves
            ## unset (e.g. tor_bootstrap_timeout_type on the circuit-established
            ## path, tor_bootstrap_percent on a workstation) stays unset here and
            ## the nounset run surfaces it instead of a stub masking it.
            ##
            ## check_tor_circuit_established sets the circuit flag + word (and on
            ## a workstation this is their only source, since tor_bootstrap_check
            ## skips check_tor_bootstrap_status there).
            'check_tor_circuit_established() {'
            ' check_bootstrap_privleap_action="stub";'
            ' tor_circuit_established_check_exit_code="%s";'
            ' tor_circuit_established="%s";'
            ' tor_circuit_established_word="stub"; }'
            % (cfg['cc_exit'], cfg['circuit_est']),
            'check_tor_bootstrap_status() {'
            ' check_bootstrap_privleap_action="stub";'
            ' tor_bootstrap_percent="%s"; tor_bootstrap_status="stub";'
            ' tor_bootstrap_timeout_type="none"; }' % cfg['bootstrap'],
            'check_tor_circuit_built() {'
            ' check_bootstrap_privleap_action="stub";'
            ' tor_circuit_built_check_exit_code="%s"; }' % cfg['built_exit'],
            self._consensus_stub(str(cfg['consensus']), now),
            'anondate_request_rate_limited() { return %s; }'
            % cfg['rate_limited_rc'],
        ]

        script = '\n'.join(
            [
                'source "%s"' % self.path,
                '\n'.join(stubs),
                'set -o errexit',
                'set -o nounset',
                'set -o errtrace',
                'set -o pipefail',
                'shopt -s inherit_errexit',
                'shopt -s shift_verbose',
                'te_pe_tb_check',
            ]
        )
        env = stub_env(
            HELPER_SCRIPTS_PATH=self.helper_scripts_path,
            USER=str(cfg['user']),
        )
        result = run_bash(script, env)
        return result.returncode, result.stdout, result.stderr

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.helper_scripts_path = _helper_scripts_path()
        if not cls.helper_scripts_path:
            raise unittest.SkipTest(
                'set HELPER_SCRIPTS_PATH or ONION_TIME_PRE_SCRIPT_REPO'
            )

    def setUp(self) -> None:
        ## A writable stand-in for /run/sdwdate so anondate_use's touch works.
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.state_dir = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def assert_exit(self, expected: int, needle: str, **overrides: object) -> None:
        code, stdout, stderr = self.run_scenario(**overrides)
        combined = stdout + stderr
        self.assertEqual(
            expected,
            code,
            'expected exit %d, got %d\nstdout:\n%s\nstderr:\n%s'
            % (expected, code, stdout, stderr),
        )
        ## Not a vacuous pass: the intended branch must have produced its output,
        ## and 'unbound variable' must never be how we got the code.
        self.assertNotIn(
            'unbound variable',
            combined,
            'nounset tripped an unguarded reference:\n%s' % combined,
        )
        self.assertIn(
            needle,
            combined,
            'expected output %r not found in:\n%s' % (needle, combined),
        )

    ## --- exit 1: wait + error icon ---

    def test_tor_disabled(self) -> None:
        self.assert_exit(1, 'Tor is disabled', tor_enabled='0')

    def test_circuit_check_timeout(self) -> None:
        self.assert_exit(1, 'Tor Bootstrap Result', cc_exit='124')

    def test_circuit_check_killed(self) -> None:
        self.assert_exit(1, 'Tor Bootstrap Result', cc_exit='137')

    def test_control_port_unreachable_gateway(self) -> None:
        self.assert_exit(
            1, 'Control Port could not be reached', cc_exit='255', vm='Gateway'
        )

    def test_unimplemented_user(self) -> None:
        self.assert_exit(
            1, 'is not yet implemented', real_anondate_folder=True, user='nobody'
        )

    ## --- exit 0: success ---

    def test_circuit_confirmed_gateway(self) -> None:
        self.assert_exit(0, 'circuit confirmed', built_exit='0')

    def test_workstation_circuit_established(self) -> None:
        self.assert_exit(
            0, 'circuit confirmed', vm='Workstation', circuit_est='1'
        )

    def test_bootstrap_100_no_circuit(self) -> None:
        self.assert_exit(
            0,
            'tor_bootstrap_percent) is 100',
            bootstrap='100',
            circuit_est='0',
            built_exit='1',
            consensus='ok',
        )

    ## --- exit 2: wait + busy icon ---

    def test_nothing_conclusive(self) -> None:
        self.assert_exit(2, 'END', bootstrap='50', circuit_est='0', built_exit='1')

    def test_clock_slow_gateway(self) -> None:
        self.assert_exit(2, "Running 'anondate-set'", consensus='slow')

    def test_clock_fast_first_run_after_boot(self) -> None:
        ## Exercises the onion_time_script_status_boot=true branch.
        self.assert_exit(
            2, "Running 'anondate-set'", consensus='fast', boot='true'
        )

    def test_consensus_none_yet(self) -> None:
        self.assert_exit(2, "Running 'anondate-set'", consensus='noneyet')

    def test_consensus_error(self) -> None:
        self.assert_exit(2, "Running 'anondate-set'", consensus='error')

    def test_static_sanity_failed_gateway(self) -> None:
        self.assert_exit(2, "Running 'anondate-set'", static_failed='true')

    def test_static_sanity_failed_workstation(self) -> None:
        ## Workstation + static-failed leaves clock_tor_consensus_check_result
        ## unset (the consensus check returns early) and tor_bootstrap_percent
        ## unset (workstation skips the bootstrap read) -- both are references
        ## the strict-mode refactor must guard. Falls through to the busy-wait.
        self.assert_exit(
            2, 'END', vm='Workstation', static_failed='true', circuit_est='0'
        )

    def test_workstation_no_circuit_clock_ok(self) -> None:
        ## Workstation with Tor up but no circuit and an ok clock reaches
        ## exit_success_if_tor_circuit_already_established, which reads
        ## tor_bootstrap_percent -- unset on a workstation (bootstrap status is
        ## skipped there), another reference the refactor must guard. Falls
        ## through to the busy-wait.
        self.assert_exit(
            2,
            'END',
            vm='Workstation',
            circuit_est='0',
            consensus='ok',
            static_failed='',
        )

    def test_anondate_rate_limited(self) -> None:
        self.assert_exit(
            2,
            'less than',
            consensus='slow',
            rate_limited_rc='0',
        )

    def test_dormant_then_bootstrap_100(self) -> None:
        ## Dormant Tor is woken (SIGNAL newnym); a 100% bootstrap still exits 0.
        self.assert_exit(
            0, 'tor_bootstrap_percent) is 100', dormant='1', bootstrap='100'
        )


if __name__ == '__main__':
    unittest.main()
