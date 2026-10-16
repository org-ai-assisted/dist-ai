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


## Detect a check_* fragment invoked DIRECTLY (in command position), i.e. NOT routed
## through systemcheck_run_function. Extracted + testable so a fixture can prove it
## catches the command-position call a line-start-only match missed.
_CHECK_SEP_RE = re.compile(r'&&|\|\||[;&|]')
## Shell keywords/openers/command-wrappers that may PRECEDE a command on the same
## segment; skipped so the command token after them is examined (`if check_x`,
## `{ check_x`, `! check_x`, `command check_x`, `eval check_x`, `time check_x`).
_CHECK_LEAD = frozenset(
    {'if', 'elif', 'while', 'until', 'then', 'else', 'do', 'not', '!', '{', '(',
     'command', 'builtin', 'eval', 'time'})
## A leading env-assignment (FOO=bar check_x) also precedes the command token.
_CHECK_ENV_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=')
_CHECK_NAME_RE = re.compile(r'check_[A-Za-z0-9_]+')


def direct_check_calls(func_body: str) -> list:
    """check_* fragments called directly (in command position) in a function body.

    Operates on the bash-parsed `declare -f` output (comments already dropped).
    Each line is split on command separators (`;` `&&` `||` `|` `&`) and leading
    shell keywords/command-wrappers/env-assignments are stripped, so a call at line
    start AND one in command position after a separator, keyword, or wrapper
    (`if check_x; then`, `foo && check_x`, `command check_x`, `FOO=bar check_x`) are
    all caught. A check_* that is an ARGUMENT (e.g. `systemcheck_run_function
    check_x`) is never in command position, so it is correctly ignored.

    SCOPE: this is a text scan of the dispatcher's `declare -f` body, not a full
    bash parser. It does not model here-doc bodies (data that merely looks like a
    command); systemcheck_main is a flat dispatcher with no here-docs, so this is
    not a concern in practice -- do not grow it into a here-doc parser to chase a
    hypothetical."""
    bad = []
    for raw_line in func_body.split('\n'):
        for segment in _CHECK_SEP_RE.split(raw_line):
            tokens = segment.split()
            idx = 0
            while idx < len(tokens) and (tokens[idx] in _CHECK_LEAD
                                         or _CHECK_ENV_RE.match(tokens[idx])):
                idx += 1
            if idx < len(tokens) and _CHECK_NAME_RE.fullmatch(tokens[idx]):
                bad.append(tokens[idx])
    return bad


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
        bad = direct_check_calls(res.stdout)
        self.assertEqual(
            bad, [],
            f"check_* called directly in systemcheck_main, bypassing "
            f"--skip/--autostart: {bad}")


class TestDirectCheckScan(unittest.TestCase):
    """direct_check_calls must catch a check_* call in ANY command position, not
    only at line start -- the gap ai-review found in the line-anchored scan
    (`if check_x; then` and `foo && check_x` slipped past)."""

    def test_flags_line_start_call(self) -> None:
        self.assertEqual(direct_check_calls('    check_packages'), ['check_packages'])

    def test_flags_if_condition_call(self) -> None:
        ## The exact missed shape: a line-start '^check_' never matches 'if check_'.
        body = ('systemcheck_main () \n{\n    if check_packages; then\n'
                '        :\n    fi\n}')
        self.assertEqual(direct_check_calls(body), ['check_packages'])

    def test_flags_call_after_separator(self) -> None:
        self.assertEqual(direct_check_calls('    foo && check_bar'), ['check_bar'])
        self.assertEqual(direct_check_calls('    check_a; check_b'),
                         ['check_a', 'check_b'])
        self.assertEqual(direct_check_calls('    something | check_piped'),
                         ['check_piped'])

    def test_ignores_run_function_wrapped(self) -> None:
        ## check_x is an ARGUMENT here, never a command -> not a direct call. Also
        ## guards the 'systemcheck_run_function' substring 'check' false positive.
        self.assertEqual(
            direct_check_calls('    systemcheck_run_function check_packages\n'
                               '    systemcheck_run_function check_dpkg'), [])

    def test_flags_call_behind_wrapper_or_env(self) -> None:
        ## A check reached via a command-wrapper or an env-assignment prefix is
        ## still a direct call bypassing systemcheck_run_function.
        self.assertEqual(direct_check_calls('    command check_packages'),
                         ['check_packages'])
        self.assertEqual(direct_check_calls('    eval check_tor'), ['check_tor'])
        self.assertEqual(direct_check_calls('    time check_clock'), ['check_clock'])
        self.assertEqual(direct_check_calls('    FOO=bar check_network'),
                         ['check_network'])
        self.assertEqual(direct_check_calls('    if command check_hidden; then'),
                         ['check_hidden'])


if __name__ == '__main__':
    unittest.main()
