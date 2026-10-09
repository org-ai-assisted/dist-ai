#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for log-checker config hardening:

  * check_service_logs with an EMPTY journal_ignore_fixed_list: a 'grep
    --fixed-strings' built with no '-e' pattern treats the file path as the
    pattern (no file operand) and blocks on stdin -> must skip the grep and
    filter nothing.
  * check_service_logs with an EMPTY journal_ignore_patterns_list: an empty
    extended-regexp matches every line, so 'grep --invert-match' drops ALL
    lines and the check reports clean having inspected nothing -> must skip the
    grep and filter nothing.
  * source_config keeps 'shopt -s nullglob' so an empty /etc/systemcheck.d is a
    clean no-op (an unmatched literal glob would otherwise crash under errexit).

log-checker is source-able (was_executed guard), so the tests SOURCE the real
script -- defining its functions (and the real strings.bsh helpers) without
running it or inheriting strict-mode -- then call the function under test. Only
genuine external / root actions (leaprun, safe-rm) and the GUI-format sinks
(sanitize-string / br_add_to_file / stcatn) are stubbed, for deterministic,
offline assertions. Absolute-path state (the Qubes marker-vm, the /etc config
dirs) is neutralized with a bubblewrap tmpfs only where it EXISTS on the host,
so on a non-Qubes CI container these run plain -- and still gate there, since a
real failure is exit 1 even when the sub-suite's skip is authorized. They live
in this sub-suite because on a Qubes host or one with systemcheck installed
they do need bubblewrap. The prep_temp_dir TOCTOU cases:
test_log_checker_temp_dir_isolated.py.
"""

import unittest

from systemcheck_testlib import LogCheckerHardeningBase

## A journal line matching log-checker's positive journal_search_pattern_list
## ("error"), so it survives the first match grep and reaches the ignore filters.
MATCH_LINE = 'testhost app[1]: this is an error sample'


class TestLogCheckerEmptyIgnoreLists(LogCheckerHardeningBase):
    """An empty ignore list means 'ignore nothing' -> matched journal lines must
    SURVIVE, not be silently dropped (the pre-fix degenerate grep dropped them)."""

    def test_both_empty_lists_keep_matches(self) -> None:
        proc = self._run_check_service_logs(MATCH_LINE, [], [])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('error sample', proc.stdout,
                      'empty ignore lists must filter NOTHING, not drop everything')

    def test_empty_patterns_keep_matches(self) -> None:
        ## Isolates the patterns-list bug: a non-matching fixed entry keeps the
        ## fixed grep well-formed, so only the empty-patterns path is exercised.
        proc = self._run_check_service_logs(MATCH_LINE, ['no-such-fixed'], [])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('error sample', proc.stdout,
                      'empty journal_ignore_patterns_list must not drop all lines')

    def test_empty_fixed_keep_matches(self) -> None:
        ## Isolates the fixed-list bug: a non-matching pattern keeps the invert
        ## grep well-formed, so only the empty-fixed path is exercised. A pre-fix
        ## hang here would trip the subprocess timeout and fail the test.
        proc = self._run_check_service_logs(MATCH_LINE, [], ['no-such-pattern'])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('error sample', proc.stdout,
                      'empty journal_ignore_fixed_list must not hang or drop all lines')

    def test_nonempty_patterns_still_filter(self) -> None:
        ## The empty-case guard must NOT neuter real filtering.
        proc = self._run_check_service_logs(MATCH_LINE, [], ['error sample'])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn('error sample', proc.stdout,
                         'a matching ignore pattern must still drop the line')

    def test_nonempty_fixed_still_filter(self) -> None:
        proc = self._run_check_service_logs(MATCH_LINE, ['error sample'], [])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn('error sample', proc.stdout,
                         'a matching fixed ignore string must still drop the line')


class TestLogCheckerSourceConfigNullglob(LogCheckerHardeningBase):
    """source_config must keep nullglob so an empty config dir is a clean no-op."""

    def test_nullglob_set_in_source_config(self) -> None:
        with open(self._log_checker(), encoding='utf-8') as handle:
            text = handle.read()
        self.assertIn('shopt -s nullglob', text,
                      'source_config must set nullglob (empty *.conf glob -> no-op, '
                      'not a literal unmatched path sourced under errexit)')

    def test_empty_config_dirs_are_a_noop(self) -> None:
        body = 'source_config\necho SOURCE_CONFIG_OK\n'
        ## Empty the config dirs so the globs match nothing.
        proc = self._run(body, ['/etc/systemcheck.d',
                                '/usr/local/etc/systemcheck.d'])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('SOURCE_CONFIG_OK', proc.stdout,
                      'an empty config dir must be a clean no-op')


if __name__ == '__main__':
    unittest.main()
