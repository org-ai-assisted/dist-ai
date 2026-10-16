#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the systemcheck orchestrator (usr/libexec/systemcheck/systemcheck).

The orchestrator sources its ~40 check fragments and the msgcollector helpers
at MODULE TOP LEVEL (upstream design: a library must be functional when
sourced), via the HARDCODED /usr/libexec/{systemcheck,msgcollector} paths. Its
progress helpers and systemcheck_main are defined at top level too, while the
strict/errexit toggle and the ERR trap live INSIDE systemcheck_main (run only
when executed, behind the was_executed source-guard).

So these tests SOURCE the orchestrator -- which defines the functions without
running the system check or installing the ERR trap -- and exercise the progress
helpers directly. Because the fragment/msgcollector sources are hardcoded to
/usr/libexec and the installed copy lags the checkout, the source needs the
checkout staged THERE: source_orchestrator binds it with bubblewrap. That is why
this suite is bwrap-only (the non-bwrap suite cannot stage /usr/libexec without
root). systemcheck_run_function / output_x are stubbed for isolation; the real
strings.bsh is sourced for is_whole_number.
"""

import re
import unittest

from systemcheck_testlib import source_orchestrator


class OrchestratorTestBase(unittest.TestCase):

    def run_sourced(self, body: str, stubs: str = '', strings: bool = False,
                    strict: bool = True, timeout: int = 45):
        return source_orchestrator(body, stubs=stubs, strings=strings,
                                   strict=strict, timeout=timeout)


class TestSourceableContract(OrchestratorTestBase):
    """Sourcing defines the orchestrator functions WITHOUT running the system
    check: no ERR trap is installed, no strict leak."""

    def test_defines_functions_without_running(self) -> None:
        res = self.run_sourced(
            'echo "main=$(type -t systemcheck_main) '
            'inc=$(type -t systemcheck_progress_main_increment)"')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('main=function', res.stdout)
        self.assertIn('inc=function', res.stdout)

    def test_no_err_trap_installed_on_source(self) -> None:
        res = self.run_sourced('trap -p ERR')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), '')

    def test_no_strict_mode_leak(self) -> None:
        ## Check all three strict options named by the sourceable contract, not only
        ## errexit -- a 'false;true' probe misses a leaked nounset/pipefail.
        res = self.run_sourced(
            'lk=""\n'
            'case "$-" in *e*) lk="${lk} errexit";; esac\n'
            'case "$-" in *u*) lk="${lk} nounset";; esac\n'
            'set -o | grep --quiet "^pipefail[[:space:]]*on" && lk="${lk} pipefail"\n'
            'printf "LEAK:%s:END\\n" "${lk}"',
            strict=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('LEAK::END', res.stdout)


class TestProgressMainIncrement(OrchestratorTestBase):
    """systemcheck_progress_main_increment accumulates PROGRESS_MAIN by a
    whole-number increment and forwards the new total to the progress bar;
    a non-whole increment aborts (exit 1)."""

    _STUBS = 'systemcheck_run_function() { echo "RUN: $*"; }\n'

    def test_accumulates_and_forwards_total(self) -> None:
        res = self.run_sourced(
            'PROGRESS_MAIN=5\nsystemcheck_progress_main_increment 3',
            stubs=self._STUBS, strings=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('RUN: systemcheck_move_progress_bar_to_percent 8', res.stdout)

    def test_non_numeric_progress_resets_to_zero(self) -> None:
        res = self.run_sourced(
            'PROGRESS_MAIN=garbage\nsystemcheck_progress_main_increment 2',
            stubs=self._STUBS, strings=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        ## reset to 0, then + 2.
        self.assertIn('RUN: systemcheck_move_progress_bar_to_percent 2', res.stdout)

    def test_non_numeric_increment_exits(self) -> None:
        ## A non-whole increment calls 'exit 1' (not return), terminating the
        ## shell, so assert the process exit code and that it never forwarded.
        ## strict=False so errexit does not mask the distinction: a real 'exit 1'
        ## still terminates (rc 1, 'reached' absent), but a regression to 'return 1'
        ## would let 'echo reached' run (rc 0) and fail this test. Under errexit both
        ## look identical, so the test could not catch the regression.
        res = self.run_sourced(
            'PROGRESS_MAIN=0\nsystemcheck_progress_main_increment abc\necho reached',
            stubs=self._STUBS, strings=True, strict=False)
        self.assertEqual(res.returncode, 1)
        self.assertNotIn('reached', res.stdout)
        self.assertNotIn('RUN:', res.stdout)


class TestMoveProgressBar(OrchestratorTestBase):
    """systemcheck_move_progress_bar_to_percent skips entirely at silent>=3,
    otherwise drives output_x with the percent."""

    ## output_x is a VARIABLE holding a command name (the code runs ${output_x});
    ## point it at a recorder, the way the real msgcollector dispatch is wired.
    _STUBS = ('__rec() { echo "OUT: $*"; }\noutput_x=__rec\n'
              'output_opts=()\nprogressbaridx=idx\n')

    def test_skips_when_silent(self) -> None:
        res = self.run_sourced('silent=3\nsystemcheck_move_progress_bar_to_percent 50',
                               stubs=self._STUBS)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn('OUT:', res.stdout)

    def test_drives_output_when_not_silent(self) -> None:
        res = self.run_sourced('silent=0\nsystemcheck_move_progress_bar_to_percent 50',
                               stubs=self._STUBS)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('OUT:', res.stdout)
        self.assertIn('--progressx 50', res.stdout)


class TestOrchestratorInvariants(OrchestratorTestBase):
    """Invariants over systemcheck_main's real (bash-parsed) body."""

    def test_all_main_check_calls_use_run_function(self) -> None:
        """Every check_* invocation inside systemcheck_main() must go through
        systemcheck_run_function -- that wrapper implements --skip and the
        --autostart allow-list (preparation.bsh). A bare `check_packages` call
        (found by ai-review during the check_kernel_hardening_cmdline PR)
        bypassed both: `--skip check_packages` silently ran it anyway.

        Uses `declare -f` on the sourced function: bash parses the real body, so
        the function boundary (and any heredoc) is handled correctly and comments
        are dropped -- no column-0-`}` heuristic, no `## check_x` false positive."""
        res = self.run_sourced('declare -f systemcheck_main')
        self.assertEqual(res.returncode, 0, res.stderr)
        bad = []
        for line in res.stdout.split('\n'):
            stripped = line.strip()
            match = re.match(r'^(check_[A-Za-z0-9_]+)\b', stripped)
            if match and not stripped.startswith('systemcheck_run_function'):
                bad.append(stripped)
        self.assertEqual(
            bad, [],
            f"check_* called directly in systemcheck_main, bypassing "
            f"--skip/--autostart: {bad}")


if __name__ == '__main__':
    unittest.main()
