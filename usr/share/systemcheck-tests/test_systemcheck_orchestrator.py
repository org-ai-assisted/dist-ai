#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the systemcheck orchestrator (usr/libexec/systemcheck/systemcheck).

The orchestrator is source-able: its progress helpers and systemcheck_main are
defined at top level, while the strict/errexit toggle, the ERR trap, and the ~40
fragment sources live inside systemcheck_main (run only when executed, guarded
by was_executed). So these tests SOURCE it -- defining the functions without
running the whole system check or installing the ERR trap -- and exercise the
progress helpers directly. systemcheck_run_function / output_x are stubbed for
isolation; the real strings.bsh is sourced for is_whole_number.
"""

import os
import subprocess
import unittest

from systemcheck_testlib import systemcheck_dir


def _orchestrator() -> str:
    path = os.path.join(systemcheck_dir(), 'systemcheck')
    if not os.path.isfile(path):
        ## A configured checkout (SYSTEMCHECK_REPO) missing its orchestrator is a
        ## regression to FAIL on, not silently skip.
        if os.environ.get('SYSTEMCHECK_REPO', '').strip():
            raise AssertionError(f"orchestrator missing from configured checkout at {path!r}")
        raise unittest.SkipTest(f"orchestrator not found at {path!r}")
    return path


class OrchestratorTestBase(unittest.TestCase):
    script: str
    hs_root: str
    strings: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = _orchestrator()
        cls.hs_root = os.environ.get('HELPER_SCRIPTS_PATH', '').strip()
        cls.strings = (os.path.join(cls.hs_root, 'usr/libexec/helper-scripts/strings.bsh')
                       if cls.hs_root else '/usr/libexec/helper-scripts/strings.bsh')
        ## strings.bsh is required ONLY by the subclasses that pass strings=True; its
        ## absence is enforced in run_sourced (below), not here -- gating it in the
        ## shared base silently dropped TestSourceableContract and TestMoveProgressBar,
        ## which never source it.

    def run_sourced(self, body: str, stubs: str = '', strings: bool = False,
                    strict: bool = True, timeout: int = 30):
        lines = []
        if strict:
            lines += ['set -o errexit', 'set -o pipefail']
        lines.append(f'export HELPER_SCRIPTS_PATH={self.hs_root!r}')
        lines.append(f'source {self.script!r}')
        if strings:
            if not os.path.isfile(self.strings):
                if os.environ.get('SYSTEMCHECK_REPO', '').strip():
                    raise AssertionError(f"strings.bsh missing at {self.strings!r}")
                raise unittest.SkipTest('helper-scripts strings.bsh not found')
            lines.append(f'source {self.strings!r}')
        lines.append(stubs)
        lines.append(body)
        return subprocess.run(['bash', '-c', '\n'.join(lines)],
                              capture_output=True, text=True, timeout=timeout)


class TestSourceableContract(OrchestratorTestBase):
    """Sourcing defines the orchestrator functions WITHOUT running the system
    check: no fragment is sourced, no ERR trap is installed, no strict leak."""

    def test_defines_functions_without_running(self) -> None:
        res = self.run_sourced(
            'echo "main=$(type -t systemcheck_main) '
            'inc=$(type -t systemcheck_progress_main_increment)"')
        self.assertEqual(res.returncode, 0)
        self.assertIn('main=function', res.stdout)
        self.assertIn('inc=function', res.stdout)

    def test_fragments_not_sourced_on_source(self) -> None:
        ## The ~40 check fragments are sourced inside systemcheck_main, so a plain
        ## source must NOT define their check functions.
        res = self.run_sourced('echo "dpkg=$(type -t check_dpkg) '
                               'qubes=$(type -t check_qubes_settings)"')
        self.assertIn('dpkg=', res.stdout)
        self.assertNotIn('dpkg=function', res.stdout)
        self.assertNotIn('qubes=function', res.stdout)

    def test_no_err_trap_installed_on_source(self) -> None:
        res = self.run_sourced('trap -p ERR')
        self.assertEqual(res.returncode, 0)
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
        self.assertEqual(res.returncode, 0)
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
        self.assertEqual(res.returncode, 0)
        self.assertIn('RUN: systemcheck_move_progress_bar_to_percent 8', res.stdout)

    def test_non_numeric_progress_resets_to_zero(self) -> None:
        res = self.run_sourced(
            'PROGRESS_MAIN=garbage\nsystemcheck_progress_main_increment 2',
            stubs=self._STUBS, strings=True)
        self.assertEqual(res.returncode, 0)
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
        self.assertEqual(res.returncode, 0)
        self.assertNotIn('OUT:', res.stdout)

    def test_drives_output_when_not_silent(self) -> None:
        res = self.run_sourced('silent=0\nsystemcheck_move_progress_bar_to_percent 50',
                               stubs=self._STUBS)
        self.assertEqual(res.returncode, 0)
        self.assertIn('OUT:', res.stdout)
        self.assertIn('--progressx 50', res.stdout)


if __name__ == '__main__':
    unittest.main()
