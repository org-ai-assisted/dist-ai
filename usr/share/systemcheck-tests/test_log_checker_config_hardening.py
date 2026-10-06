#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for log-checker config / temp-dir hardening:

  * prep_temp_dir TOCTOU: 'mkdir --mode' sets the mode only on CREATE, so an
    already-existing (pre-created) temp dir keeps its own mode/owner. The dir
    must therefore be validated (non-symlink, owned by us, 0700) and refused
    otherwise, or the full journal could be written into an attacker-shaped
    world-readable dir.
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
offline assertions. Absolute-path state (the Qubes marker-vm, the fixed
/var/cache temp dir, the /etc config dirs) is neutralized with a bubblewrap
tmpfs so the tests are deterministic on a Qubes host as well as a non-Qubes CI
container; SkipTest when bubblewrap is unavailable, matching the testlib.
"""

import os
import shlex
import subprocess
import tempfile
import unittest

from systemcheck_testlib import SystemcheckTestBase, bwrap_available

## A journal line matching log-checker's positive journal_search_pattern_list
## ("error"), so it survives the first match grep and reaches the ignore filters.
MATCH_LINE = 'testhost app[1]: this is an error sample'


class LogCheckerHardeningBase(SystemcheckTestBase):
    """Shared harness: SOURCE the real log-checker (source-able, so this defines
    its functions without auto-running or leaking strict-mode), then call the
    function under test, overlaying the absolute paths it reads with a bubblewrap
    tmpfs so the case under test is deterministic on any host (Qubes or CI)."""

    def _log_checker(self) -> str:
        return os.path.join(self.dir, 'log-checker')

    def _wrap(self, cmd: list, tmpfs_dirs: list) -> list:
        """Prefix cmd with a bubblewrap tmpfs overlay for each EXISTING tmpfs_dir.
        A dir absent on the host already yields the 'empty' state, so no overlay
        (and no bwrap) is needed there -- this is what lets the check_service_logs
        tests run plain on a non-Qubes CI container with no /usr/share/qubes."""
        dirs = [d for d in tmpfs_dirs if os.path.isdir(d)]
        if not dirs:
            return cmd
        if not bwrap_available():
            raise unittest.SkipTest(
                'bubblewrap unavailable; cannot isolate ' + ' '.join(dirs))
        prefix = ['bwrap', '--bind', '/', '/', '--dev', '/dev', '--proc', '/proc']
        for directory in dirs:
            prefix += ['--tmpfs', directory]
        return prefix + cmd

    def _run(self, body: str, tmpfs_dirs: list) -> subprocess.CompletedProcess:
        ## Source the source-able script (was_executed is false here -> no
        ## auto-run, no strict leak), then run the caller-supplied body under the
        ## same options the executed script sets, so the functions behave as in
        ## production.
        script = (
            f'source {shlex.quote(self._log_checker())}\n'
            ## Match the executed script's own options so the function runs as in
            ## production (pipefail on -> the grep brace-masks are genuinely
            ## exercised); the source itself did not enable strict (was_executed
            ## is false when sourced).
            'set -o errexit\n'
            'set -o nounset\n'
            'set -o pipefail\n'
            f'{body}'
        )
        cmd = self._wrap(['bash', '-c', script], tmpfs_dirs)
        ## stdin=DEVNULL so nothing can block on a terminal; timeout fails a hang
        ## loudly instead of wedging CI.
        return subprocess.run(cmd, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=30)

    ## Stubs for the externals/sinks the functions call as bare names. Defined
    ## AFTER the source so they shadow the real definitions; kept to the identity
    ## transform so assertions are deterministic and offline.
    @staticmethod
    def _stubs(journal_line: str) -> str:
        return (
            'leaprun() { case "$1" in'
            f" read-journalctl-logs-this-boot) printf '%s\\n' {shlex.quote(journal_line)} ;;"
            ' *) : ;; esac ; }\n'
            'sanitize-string() { cat ; }\n'
            'br_add_to_file() { cp -- "$1" "$1_br" ; }\n'
            'stcatn() { cat -- "$@" ; }\n'
            'safe-rm() { : ; }\n'
        )

    def _run_check_service_logs(self, journal_line: str, fixed: list,
                                patterns: list) -> subprocess.CompletedProcess:
        tmp = tempfile.mkdtemp()
        fixed_arr = ' '.join(shlex.quote(item) for item in fixed)
        patterns_arr = ' '.join(shlex.quote(item) for item in patterns)
        body = (
            self._stubs(journal_line)
            + f'TMPDIR={shlex.quote(tmp)}\n'
            + f'journal_ignore_fixed_list=( {fixed_arr} )\n'
            + f'journal_ignore_patterns_list=( {patterns_arr} )\n'
            + 'check_service_logs this_boot\n'
        )
        ## Hide the Qubes marker so the 'virtualbox' auto-append does not make
        ## journal_ignore_patterns_list non-empty on a Qubes host.
        return self._run(body, ['/usr/share/qubes'])

    def _run_prep_temp_dir(self, setup: str = '') -> subprocess.CompletedProcess:
        ## prep_temp_dir hardcodes TMPDIR=/var/cache/systemcheck-log-checker, so
        ## isolate /var/cache with a tmpfs: a clean per-run dir, writable by us.
        body = (
            'safe-rm() { command rm --recursive --force -- "${@:3}" ; }\n'
            f'{setup}'
            'if prep_temp_dir ; then echo PREP_OK ; else echo "PREP_FAIL rc=$?" ; fi\n'
        )
        return self._run(body, ['/var/cache'])


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


class TestLogCheckerTempDirTocToU(LogCheckerHardeningBase):
    """prep_temp_dir must fail closed when the fixed temp dir already exists with
    unsafe type/owner/permissions (mkdir --mode does not re-apply to it)."""

    def test_clean_dir_created_and_accepted(self) -> None:
        proc = self._run_prep_temp_dir()
        self.assertIn('PREP_OK', proc.stdout,
                      'a freshly-created 0700 dir must be accepted')
        self.assertNotIn('PREP_FAIL', proc.stdout)

    def test_pre_created_world_writable_dir_refused(self) -> None:
        setup = ('mkdir --parents --mode=777 -- '
                 '/var/cache/systemcheck-log-checker\n')
        proc = self._run_prep_temp_dir(setup)
        self.assertIn('PREP_FAIL', proc.stdout,
                      'a pre-created mode-0777 temp dir must be refused, not written into')

    def test_symlink_temp_dir_refused(self) -> None:
        ## A symlink in place of the dir (mkdir -p is a no-op on it) must be
        ## refused so the journal is not written through it to another location.
        setup = ('ln --symbolic -- /tmp /var/cache/systemcheck-log-checker\n')
        proc = self._run_prep_temp_dir(setup)
        self.assertIn('PREP_FAIL', proc.stdout,
                      'a symlinked temp dir must be refused')


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
