#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for systemcheck's --ci mode.

--ci exists so a CI / automated-test run does not fail merely because package
upgrades are available. It suppresses ONLY that one finding: check_operating_system
does not set a non-zero EXIT_CODE for the "packages can be updated" result when
ci=true. Every other warning and error still exits non-zero (unchanged), so --ci
cannot mask a real problem.

These tests drive the REAL check_operating_system fragment down to the relevant
branch (apt-get-update succeeds; the simulate reports an upgrade count) and assert
the resulting EXIT_CODE.
"""

import unittest

from systemcheck_testlib import ScenarioTestBase, run_check_scenario


## Steer the globals that select the plain (non-Qubes, non-sysmaint) update branch.
_ENV_COMMON = (
    'systemcheck_external_network_found=true\n'
    'silent=0\n'
    'verbose=0\n'
    'qubes_detected=false\n'
    'booted_in_sysmaint_session=false\n'
    'user_sysmaint_split_installed=false\n'
)

## leaprun drives the apt interaction; sanitize-string / br_add are output-format
## shims (their result does not reach the exit decision -- pure isolation stubs).
_STUBS_UPDATES_AVAILABLE = r"""
leaprun() {
  case "${1:-}" in
    apt-get-update) return 0 ;;
    apt-get-update-simulate)
      printf '%s\n' '5 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.' ;;
    *) return 0 ;;
  esac
}
sanitize-string() { printf '%s' "${3:-}"; }
br_add() { printf '%s' "${1:-}"; }
"""

## Same, but the simulate FAILS -> check_operating_system emits an ERROR.
_STUBS_SIMULATE_ERROR = r"""
leaprun() {
  case "${1:-}" in
    apt-get-update) return 0 ;;
    apt-get-update-simulate) printf '%s\n' 'E: dpkg was interrupted'; return 100 ;;
    *) return 0 ;;
  esac
}
sanitize-string() { printf '%s' "${3:-}"; }
br_add() { printf '%s' "${1:-}"; }
"""

## apt-get-update ITSELF fails -> "Could not check for software updates!". A
## failure to check is a real finding (not the tolerated updates-available one),
## so it must exit non-zero even under --ci.
_STUBS_UPDATE_CHECK_FAILS = r"""
leaprun() {
  case "${1:-}" in
    apt-get-update) return 1 ;;
    *) return 0 ;;
  esac
}
sanitize-string() { printf '%s' "${3:-}"; }
br_add() { printf '%s' "${1:-}"; }
"""


class TestCiUpdatesAvailable(ScenarioTestBase):
    def _run(self, ci: str, stubs: str):
        return run_check_scenario(
            self.check('check_operating_system.bsh'),
            'check_operating_system',
            env_setup=_ENV_COMMON + f'ci={ci}\n',
            stubs=stubs)

    def test_reaches_updates_available_branch(self) -> None:
        ## Precondition for the exit-code tests: the run actually hit the
        ## "packages can be updated" warning (otherwise they would be vacuous).
        res = self._run('false', _STUBS_UPDATES_AVAILABLE)
        self.assertCleanRun(res)
        self.assertTrue(res.has_severity('warning'),
                        f'expected updates-available warning; got {res.records!r}')
        self.assertIn('can be updated', res.joined())

    def test_without_ci_exits_nonzero(self) -> None:
        ## Default behaviour unchanged: updates available -> non-zero exit.
        res = self._run('false', _STUBS_UPDATES_AVAILABLE)
        self.assertCleanRun(res)
        self.assertEqual(res.exit_code, '1')

    def test_ci_suppresses_updates_available_exit(self) -> None:
        ## The whole point: under --ci the updates-available finding is non-fatal...
        res = self._run('true', _STUBS_UPDATES_AVAILABLE)
        self.assertCleanRun(res)
        self.assertEqual(res.exit_code, '0')
        ## ...but the warning is still emitted (informative, just not fatal).
        self.assertTrue(res.has_severity('warning'))

    def test_ci_does_not_mask_error(self) -> None:
        ## --ci tolerates ONLY updates-available. A real ERROR (here: the upgrade
        ## simulation failing) must still exit non-zero even with ci=true.
        res = self._run('true', _STUBS_SIMULATE_ERROR)
        self.assertCleanRun(res)
        self.assertTrue(res.has_severity('error'),
                        f'expected an error-severity emit; got {res.records!r}')
        self.assertEqual(res.exit_code, '1')

    def test_ci_does_not_mask_update_check_failure(self) -> None:
        ## apt-get-update failing (could not check at all) is a real finding, not
        ## the tolerated "updates available" one: non-zero exit even with ci=true.
        res = self._run('true', _STUBS_UPDATE_CHECK_FAILS)
        self.assertCleanRun(res)
        self.assertTrue(res.has_severity('warning'),
                        f'expected could-not-check warning; got {res.records!r}')
        self.assertIn('Could not check', res.joined())
        self.assertEqual(res.exit_code, '1')


if __name__ == '__main__':
    unittest.main()
