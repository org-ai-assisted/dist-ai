#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for check_tirdad_module (check_tirdad_module.bsh).

The check reports whether the 'tirdad' kernel module (TCP ISN CPU information
leak protection) is loaded. Loaded state is read from `lsmod`; the branch that
classifies an UNLOADED module reads the Qubes marker file and the
`intel_amd_64_detected` / `secure_boot_status_enabled` globals.

The scenarios steer:
  * lsmod            -- a function stub, so process substitution `< <(lsmod)`
                        sees exactly the module table we want.
  * the Qubes marker -- hidden via hide_dirs so the non-Qubes branch runs.
  * the globals      -- via env_setup.

Focus: the green "Enabled" success line is gated behind verbose (reassuring but
noise to a layman running without --verbose), while a genuine "Disabled"
security gap must still surface non-verbose.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario_isolated,
)

FILE = 'check_tirdad_module.bsh'
FUNC = 'check_tirdad_module'

## lsmod output WITH / WITHOUT tirdad. A header line plus one module row,
## matching real `lsmod` so the check's fixed-string grep behaves as in
## production.
LSMOD_LOADED = (
    "lsmod() { printf '%s\\n' 'Module Size Used by' "
    "'tirdad 16384 0'; }")
LSMOD_UNLOADED = (
    "lsmod() { printf '%s\\n' 'Module Size Used by' "
    "'nf_tables 274432 0'; }")

## live-status-detected is only reached on the Secure Boot branch; stub it to
## "not live" so it never blocks if a scenario does reach it.
STUB_LIVE = 'live-status-detected() { return 1; }\n'


class TestTirdadModuleScenarios(ScenarioTestBase):
    HIDE = ['/usr/share/qubes']

    def _run(self, lsmod_stub: str, verbose: int = 1,
             intel_amd: str = 'true', secure_boot: str = 'false'):
        env = (f'verbose={verbose}\n'
               f'intel_amd_64_detected={intel_amd}\n'
               f'secure_boot_status_enabled={secure_boot}\n')
        return run_check_scenario_isolated(
            self.check(FILE), FUNC,
            env_setup=env,
            stubs=lsmod_stub + '\n' + STUB_LIVE,
            hide_dirs=self.HIDE)

    ## -- loaded: green "Enabled" is gated behind verbose -------------------
    def test_enabled_hidden_when_not_verbose(self) -> None:
        r = self._run(LSMOD_LOADED, verbose=0)
        self.assertCleanRun(r)
        self.assertNotIn('>Enabled<', r.joined())
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    def test_enabled_shown_when_verbose(self) -> None:
        r = self._run(LSMOD_LOADED, verbose=1)
        self.assertCleanRun(r)
        self.assertIn('>Enabled<', r.joined())
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    ## -- unloaded (critical, non-Qubes, Intel/AMD64, Secure Boot off): the
    ## -- "Disabled" warning is NOT gated and fails the run, verbose or not --
    def test_disabled_critical_reported_when_not_verbose(self) -> None:
        r = self._run(LSMOD_UNLOADED, verbose=0)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('>Disabled<', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_disabled_critical_reported_when_verbose(self) -> None:
        r = self._run(LSMOD_UNLOADED, verbose=1)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('>Disabled<', r.joined())
        self.assertEqual(r.exit_code, '1')


if __name__ == '__main__':
    unittest.main()
