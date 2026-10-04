#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the warrant-canary subsystem.

  * json-field-get   - pure stdin/argv JSON field extractor (used by the Tor
                       check); exercised directly.
  * canary           - the fetch/verify script; it is source-able (functions at
                       top level, canary_main guarded by was_executed), so the
                       source-able contract is asserted here.
  * check_warrant_canary.bsh - the systemcheck check fragment; its gating
                       branches (disabled / workstation / live mode) are driven
                       through the dist-ai run_check_scenario harness.

The network / signify / root-path parts of canary and canary-download are not
headless-runnable and are out of scope here (the AppArmor profile is covered by
test_canary_apparmor_profile.py).
"""

import os
import subprocess
import unittest

from systemcheck_testlib import ScenarioTestBase, run_check_scenario, systemcheck_dir


def _libexec(name: str, required: bool = False) -> str:
    path = os.path.join(systemcheck_dir(), name)
    if not os.path.isfile(path):
        ## A configured checkout (SYSTEMCHECK_REPO) that lacks a REQUIRED script is a
        ## regression to FAIL on, not silently skip -- a skip would green the whole class.
        if required and os.environ.get('SYSTEMCHECK_REPO', '').strip():
            raise AssertionError(f"{name} missing from configured checkout at {path!r}")
        raise unittest.SkipTest(f"{name} not found at {path!r}")
    return path


def _helper_scripts_root() -> str:
    return os.environ.get('HELPER_SCRIPTS_PATH', '').strip()


class TestJsonFieldGet(unittest.TestCase):
    """json-field-get prints the top-level field named in argv[1] from the JSON
    on stdin, and exits non-zero on a missing key or malformed JSON."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = _libexec('json-field-get')

    def _run(self, stdin: str, *args: str):
        return subprocess.run(['python3', self.script, *args],
                              input=stdin, capture_output=True, text=True, timeout=30)

    def test_extracts_string_field(self) -> None:
        res = self._run('{"IsTor": true, "IP": "1.2.3.4"}', 'IP')
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout.strip(), '1.2.3.4')

    def test_extracts_bool_field(self) -> None:
        res = self._run('{"IsTor": true, "IP": "1.2.3.4"}', 'IsTor')
        self.assertEqual(res.returncode, 0)
        ## json.load -> Python True -> printed 'True', matching the old inline parser.
        self.assertEqual(res.stdout.strip(), 'True')

    def test_missing_key_exits_nonzero(self) -> None:
        res = self._run('{"IsTor": true}', 'IP')
        self.assertNotEqual(res.returncode, 0)

    def test_malformed_json_exits_nonzero(self) -> None:
        res = self._run('not json at all', 'IP')
        self.assertNotEqual(res.returncode, 0)

    def test_missing_argv_exits_nonzero(self) -> None:
        res = self._run('{"IsTor": true}')
        self.assertNotEqual(res.returncode, 0)


class TestCanarySourceable(unittest.TestCase):
    """canary is written source-able: sourcing it defines its functions without
    running canary_main (which fetches over Tor and writes /var/lib/canary) and
    without leaking strict-mode into the caller."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = _libexec('canary', required=True)
        cls.hs_root = _helper_scripts_root()

    def _source(self, body: str, strict_off: bool = False):
        prefix = '' if strict_off else 'set -o errexit\nset -o pipefail\n'
        return subprocess.run(
            ['bash', '-c',
             f'{prefix}export HELPER_SCRIPTS_PATH={self.hs_root!r}\n'
             f'source {self.script!r}\n{body}'],
            capture_output=True, text=True, timeout=30)

    def test_sourcing_defines_functions_without_running_main(self) -> None:
        res = self._source('echo "main=$(type -t canary_main) '
                           'count=$(type -t canary_count_or_not)"')
        self.assertEqual(res.returncode, 0)
        self.assertIn('main=function', res.stdout)
        self.assertIn('count=function', res.stdout)
        ## canary_main emits nothing we can see here; assert no fetch side-effect
        ## markers leaked from an accidental auto-run.
        self.assertNotIn('Attempting to download', res.stdout)

    def test_no_strict_mode_leak(self) -> None:
        ## Fresh bash -c starts errexit/nounset/pipefail OFF; sourcing must not turn
        ## ANY of them on in the caller. Check all three named by the sourceable
        ## contract, not only errexit (a 'false;true' probe misses nounset/pipefail).
        res = self._source(
            'lk=""\n'
            'case "$-" in *e*) lk="${lk} errexit";; esac\n'
            'case "$-" in *u*) lk="${lk} nounset";; esac\n'
            'set -o | grep --quiet "^pipefail[[:space:]]*on" && lk="${lk} pipefail"\n'
            'printf "LEAK:%s:END\\n" "${lk}"',
            strict_off=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn('LEAK::END', res.stdout)

    def test_count_or_not_skips_in_live_mode(self) -> None:
        ## live_status_detected=true -> canary_count_or_not exits 0 early with the
        ## live-mode skip message (a pure, global-driven branch).
        res = self._source('live_status_detected=true\ncanary_count_or_not',
                           strict_off=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn('Skip in live mode', res.stdout)


class TestCheckWarrantCanaryScenarios(ScenarioTestBase):
    """check_warrant_canary gating branches via the scenario harness.

    The fragment sources canary-run-or-not (which only ever sets canary_run=false
    on a disable marker), so the value set in env_setup steers the disabled vs
    enabled branch deterministically on a host with no disable marker."""

    def _run(self, env_setup: str, stubs: str = ''):
        ## leaprun must succeed by default so the enabled branches reach the
        ## later checks rather than the "unit not running" info.
        base_stubs = 'leaprun() { return 0; }\n' + stubs
        return run_check_scenario(
            self.check('check_warrant_canary.bsh'), 'check_warrant_canary',
            env_setup=env_setup, stubs=base_stubs)

    def test_disabled_in_settings(self) -> None:
        res = self._run('canary_run=false\nverbose=1\n')
        self.assertCleanRun(res)
        self.assertTrue(res.has_severity('info'))
        self.assertIn('Disabled in settings', res.joined())
        self.assertEqual(res.exit_code, '0')

    def test_skips_on_workstation(self) -> None:
        res = self._run('canary_run=true\nvm_lower_case_short=workstation\n'
                        'VM=Whonix-Workstation\nverbose=1\n')
        self.assertCleanRun(res)
        self.assertIn('Skipping on', res.joined())
        self.assertEqual(res.exit_code, '0')

    def test_skips_in_live_mode(self) -> None:
        res = self._run('canary_run=true\nvm_lower_case_short=gateway\n'
                        'live_status_detected=true\nverbose=1\n')
        self.assertCleanRun(res)
        self.assertIn('Skipping in live mode', res.joined())
        self.assertEqual(res.exit_code, '0')

    def test_unit_not_running_is_info_not_error(self) -> None:
        ## leaprun failing -> info "systemd unit canary not running", not a
        ## run-failing error (EXIT_CODE stays 0).
        res = self._run('canary_run=true\nvm_lower_case_short=gateway\n'
                        'live_status_detected=false\nverbose=1\n',
                        stubs='leaprun() { return 1; }\n')
        self.assertCleanRun(res)
        self.assertIn('not running', res.joined())
        ## The "not running" record must be INFO severity: an error-severity emit at
        ## exit 0 would still pass the exit_code check, so assert the severity too.
        self.assertTrue(res.has_severity('info'))
        self.assertEqual(res.exit_code, '0')


if __name__ == '__main__':
    unittest.main()
