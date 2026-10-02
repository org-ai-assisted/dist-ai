#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for usr/bin/updatecheck.

updatecheck is a STANDALONE script run on a timer: it probes privleap / network
/ sdwdate readiness with retries, counts available apt upgrades, and raises a
desktop notification. It is written in the source-able style (pure functions at
top level; strict-mode + the run logic in main(); auto-run guarded by
was_executed), so these tests SOURCE the real script -- defining its functions
without running main() -- and call them directly. External commands (leaprun,
notify-send, light_sleep) are stubbed for isolation only; the real helper-scripts
strings.bsh is sourced for is_whole_number, never reimplemented (dist-ai/CLAUDE.md).
"""

import os
import subprocess
import unittest

from systemcheck_testlib import read, systemcheck_dir


def _updatecheck_path() -> str:
    usr = os.path.dirname(os.path.dirname(systemcheck_dir()))
    path = os.path.join(usr, 'bin', 'updatecheck')
    if not os.path.isfile(path):
        raise unittest.SkipTest(f"updatecheck not found at {path!r}")
    return path


def _helper_scripts_root() -> str:
    """Repo root that resolves ${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/*.

    updatecheck's pre-guard 'source check_runtime.bsh' (and the test's own
    strings.bsh source) read it; without a checkout they fall back to the
    installed /usr tree."""
    hs = os.environ.get('HELPER_SCRIPTS_PATH', '').strip()
    if hs:
        return hs
    ## Installed layout: the source form '${HELPER_SCRIPTS_PATH:-}/usr/...'
    ## becomes '/usr/...' when the variable is empty.
    return ''


class UpdatecheckTestBase(unittest.TestCase):
    script: str
    text: str
    hs_root: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = _updatecheck_path()
        cls.text = read(cls.script)
        cls.hs_root = _helper_scripts_root()
        strings = os.path.join(cls.hs_root or '',
                               'usr/libexec/helper-scripts/strings.bsh')
        if not os.path.isfile(strings if cls.hs_root else '/' + strings.lstrip('/')):
            raise unittest.SkipTest(
                'helper-scripts strings.bsh not found (set HELPER_SCRIPTS_PATH)')
        cls.strings = strings if cls.hs_root else '/usr/libexec/helper-scripts/strings.bsh'

    def run_sourced(self, body: str, stubs: str = '', nounset: bool = False,
                    strings: bool = False, timeout: int = 30):
        """Source updatecheck (defining its functions, NOT running main), then
        run `body`. `stubs` are defined AFTER the source so they shadow any
        command the functions call; `strings` additionally sources the real
        strings.bsh (is_whole_number). errexit/pipefail match the script; nounset
        is opt-in for the cases that assert nounset-safety."""
        lines = ['set -o errexit', 'set -o pipefail', 'set -o errtrace']
        if nounset:
            lines.append('set -o nounset')
        lines.append(f'export HELPER_SCRIPTS_PATH={self.hs_root!r}')
        lines.append(f'source {self.script!r}')
        if strings:
            lines.append(f'source {self.strings!r}')
        lines.append(stubs)
        lines.append(body)
        return subprocess.run(['bash', '-c', '\n'.join(lines)],
                              capture_output=True, text=True, timeout=timeout)


class TestSourceableContract(UpdatecheckTestBase):
    """updatecheck must be source-able: sourcing defines main() without running
    it and without leaking strict-mode into the caller."""

    def test_sourcing_defines_main_but_does_not_run_it(self) -> None:
        res = self.run_sourced('echo "main=$(type -t main)"')
        self.assertEqual(res.returncode, 0)
        self.assertIn('main=function', res.stdout)
        ## main() prints "$0: START" and raises notifications; none of that
        ## should appear merely from sourcing.
        self.assertNotIn('START', res.stdout)
        self.assertNotIn('updates available', res.stdout)

    def test_no_strict_mode_leak(self) -> None:
        ## A fresh 'bash -c' starts errexit OFF; if sourcing leaked 'set -e',
        ## the following 'false' would abort before 'true'. (Run withOUT the
        ## harness's own strict so the leak, not the harness, is what is tested.)
        res = subprocess.run(
            ['bash', '-c',
             f'export HELPER_SCRIPTS_PATH={self.hs_root!r}\n'
             f'source {self.script!r}\nfalse\ntrue'],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(res.returncode, 0)


class TestRunWithAttempts(UpdatecheckTestBase):
    """run_with_attempts <attempts> <sleep> <label> <command...>: retry up to
    <attempts> times, succeed on first success, give up after the last failure,
    reject a non-numeric <attempts>."""

    _STUBS = 'light_sleep() { :; }\n'

    def test_rejects_non_numeric_attempts(self) -> None:
        ## '|| rc=$?' keeps errexit from aborting on the non-zero return, as
        ## production's 'if ! run_with_attempts ...' call site does.
        res = self.run_sourced(
            'rc=0\nrun_with_attempts abc 0 label true || rc=$?\necho "rc=${rc}"',
            stubs=self._STUBS, strings=True)
        self.assertIn('rc=1', res.stdout)

    def test_succeeds_first_attempt(self) -> None:
        res = self.run_sourced(
            'n=0\nprobe() { n=$((n+1)); return 0; }\n'
            'rc=0\nrun_with_attempts 3 0 label probe || rc=$?\necho "rc=${rc} n=${n}"',
            stubs=self._STUBS, strings=True)
        self.assertIn('rc=0 n=1', res.stdout)

    def test_gives_up_after_all_attempts(self) -> None:
        res = self.run_sourced(
            'n=0\nprobe() { n=$((n+1)); return 1; }\n'
            'rc=0\nrun_with_attempts 3 0 label probe || rc=$?\necho "rc=${rc} n=${n}"',
            stubs=self._STUBS, strings=True)
        self.assertIn('rc=1 n=3', res.stdout)

    def test_succeeds_on_later_attempt(self) -> None:
        res = self.run_sourced(
            'n=0\nprobe() { n=$((n+1)); [ "${n}" -ge 3 ]; }\n'
            'rc=0\nrun_with_attempts 5 0 label probe || rc=$?\necho "rc=${rc} n=${n}"',
            stubs=self._STUBS, strings=True)
        self.assertIn('rc=0 n=3', res.stdout)


class TestLeaprunCheckFunction(UpdatecheckTestBase):
    """leaprun_check_function runs 'leaprun --check -- apt-get-update',
    propagates its exit code, and discards its output."""

    def test_returns_zero_when_leaprun_succeeds(self) -> None:
        res = self.run_sourced('rc=0\nleaprun_check_function || rc=$?\necho "rc=${rc}"',
                               stubs='leaprun() { return 0; }\n')
        self.assertIn('rc=0', res.stdout)

    def test_propagates_nonzero_exit(self) -> None:
        res = self.run_sourced('rc=0\nleaprun_check_function || rc=$?\necho "rc=${rc}"',
                               stubs='leaprun() { return 7; }\n')
        self.assertIn('rc=7', res.stdout)

    def test_discards_output(self) -> None:
        res = self.run_sourced(
            'rc=0\nleaprun_check_function || rc=$?\necho "rc=${rc}"',
            stubs='leaprun() { printf "%s\\n" noise-on-stdout; '
                  'printf "%s\\n" noise-on-stderr >&2; return 0; }\n')
        self.assertNotIn('noise-on-stdout', res.stdout)
        self.assertNotIn('noise-on-stderr', res.stdout)
        self.assertIn('rc=0', res.stdout)


class TestOutputCapturingProbes(UpdatecheckTestBase):
    """system_ready_check_function and onion_time_pre_script_run capture a
    leaprun command's combined output into a global and propagate its exit code
    (now directly callable since the script is source-able)."""

    def test_system_ready_check_captures_output_and_rc(self) -> None:
        res = self.run_sourced(
            'rc=0\nsystem_ready_check_function || rc=$?\n'
            'echo "rc=${rc} out=${system_ready_check_output}"',
            stubs='leaprun() { printf "%s\\n" ready-output; return 0; }\n')
        self.assertIn('rc=0 out=ready-output', res.stdout)

    def test_system_ready_check_propagates_failure(self) -> None:
        res = self.run_sourced(
            'rc=0\nsystem_ready_check_function || rc=$?\necho "rc=${rc}"',
            stubs='leaprun() { printf "%s\\n" boom >&2; return 5; }\n')
        self.assertIn('rc=5', res.stdout)

    def test_onion_time_pre_script_captures_output(self) -> None:
        res = self.run_sourced(
            'rc=0\nonion_time_pre_script_run || rc=$?\n'
            'echo "rc=${rc} out=${onion_time_pre_script_output}"',
            stubs='leaprun() { printf "%s\\n" onion-output; return 0; }\n')
        self.assertIn('rc=0 out=onion-output', res.stdout)


class TestUpdateOutputCheck(UpdatecheckTestBase):
    """update_output_check raises a failure notification ONLY when
    ${update_output} carries an apt error line (Error:/E:/Err:)."""

    def _run(self, update_output: str):
        ## Stub the notifier to record whether it fired, without exiting.
        return self.run_sourced(
            f'update_output={update_output!r}\nupdate_output_check\n',
            stubs='send_notification_wait_exit() { printf "%s\\n" "NOTIFY:$1"; }\n')

    def test_fires_on_e_prefix(self) -> None:
        self.assertIn('NOTIFY:', self._run('E: The list of sources could not be read.').stdout)

    def test_fires_on_err_prefix(self) -> None:
        self.assertIn('NOTIFY:', self._run('Err:4 http://example InRelease').stdout)

    def test_silent_on_clean_output(self) -> None:
        self.assertNotIn(
            'NOTIFY:',
            self._run('Hit:1 http://example InRelease\nReading package lists... Done').stdout)


class TestSendNotificationWaitExit(UpdatecheckTestBase):
    """send_notification_wait_exit assembles the notification text, drives
    notify-send through a coprocess, closes the coproc fds, and exits 0."""

    _STUBS = (
        ## stdbuf strips its own options up to '--', then runs the rest.
        'stdbuf() { while [ "$1" != "--" ]; do shift; done; shift; "$@"; }\n'
        ## notify-send prints a notification id on stdout (the coproc reads it).
        'notify-send() { printf "%s\\n" 4242; }\n'
        'sleep_seconds=1\n')

    def test_appends_run_systemcheck_when_not_suppressed(self) -> None:
        res = self.run_sourced('send_notification_wait_exit "A title" "A body"',
                               stubs=self._STUBS, nounset=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn('Please run systemcheck.', res.stdout)

    def test_suppresses_run_systemcheck_when_yes(self) -> None:
        res = self.run_sourced('send_notification_wait_exit "A title" "A body" yes',
                               stubs=self._STUBS, nounset=True)
        self.assertEqual(res.returncode, 0)
        self.assertNotIn('Please run systemcheck.', res.stdout)

    def test_exits_zero_after_closing_coproc_fds(self) -> None:
        ## Exercises the fd-close assertions (test -e /proc/$$/fd/N && exit 1):
        ## both fds are closed, so neither aborts and the function exits 0.
        res = self.run_sourced('send_notification_wait_exit "T" "M"; echo unreachable',
                               stubs=self._STUBS, nounset=True)
        self.assertEqual(res.returncode, 0)
        self.assertNotIn('unreachable', res.stdout)


class TestUpdatecheckRegressions(UpdatecheckTestBase):
    """Static regressions locked by this change."""

    def test_no_undefined_leaprun_useable_result(self) -> None:
        ## The leaprun-availability-failure diagnostic once referenced an
        ## unassigned ${leaprun_useable_result}; under 'set -o nounset' that
        ## aborts the failure path with an unbound-variable error. Removed.
        self.assertNotIn('leaprun_useable_result', self.text)

    def test_leaprun_check_function_has_no_dead_capture(self) -> None:
        ## The old body captured output into an unused leaprun_check_output
        ## variable; the fix redirects output instead.
        self.assertNotIn('leaprun_check_output', self.text)


if __name__ == '__main__':
    unittest.main()
