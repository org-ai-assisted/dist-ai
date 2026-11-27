#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Scenario tests for check_mount_options -- systemcheck's presenter over
security-misc's `remount-secure --check` mount-options audit.

check_mount_options first surfaces the configured level via
`remount-secure --get-level`: level 3 (most restrictive) is a verbose-gated
green line; a level below 3 is an orange INFO notice, a hard failure (EXIT_CODE)
ONLY under --ci (interactively a lowered level is a deliberate admin choice);
an unreadable level is an orange "Indeterminate" notice.

It then runs `remount-secure --check` (no explicit level, so the audit targets
the configured drop-in level) and translates its verdict into a systemcheck
result: exit 0 -> green info (verbose-gated); a deviation exit -> an orange
"Not hardened" warning listing the DEVIATION lines; a failed run (no deviation
lines) -> an orange "Indeterminate" warning. All set EXIT_CODE.

remount-secure is stubbed as the branch sink; its own set-based audit logic is
covered in the security-misc-tests suite (test_remount_secure_check_audit.py).
The stub ASSERTS it was invoked with `--check`: a regression that dropped it and
called `remount-secure 3` would, as root, enter mutating remount mode -- so the
stub must make that fail the test, not pass silently.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
)

## Answers both subcommands the check calls. `--get-level` returns
## ${STUB_LEVEL:-3} (3 = most restrictive, so the level line stays silent for
## the audit-focused scenarios); STUB_LEVEL=fail simulates an older
## remount-secure without the query. `--check` is asserted to be passed and to
## run with NEWROOT cleared; otherwise it emits an error and a sentinel exit so
## the caller's assertions (info / DEVIATION) cannot be met -- a regression that
## called `remount-secure 3` instead would, as root, enter mutating remount mode.
_REQUIRE_CHECK = (
    "remount-secure() {\n"
    "   case \" $* \" in\n"
    "      *\" --get-level \"*)\n"
    "         if [ \"${STUB_LEVEL:-3}\" = \"fail\" ]; then\n"
    "            printf '%s\\n' \"STUB: --get-level unsupported\" >&2\n"
    "            return 2\n"
    "         fi\n"
    "         printf '%s\\n' \"${STUB_LEVEL:-3}\"\n"
    "         return 0\n"
    "         ;;\n"
    "   esac\n"
    "   case \" $* \" in\n"
    "      *\" --check \"*)\n"
    "         true\n"
    "         ;;\n"
    "      *)\n"
    "         printf '%s\\n' \"STUB-ERROR: --check not passed, got: $*\" >&2\n"
    "         return 2\n"
    "         ;;\n"
    "   esac\n"
    "   if [ -n \"${NEWROOT:-}\" ]; then\n"
    "      printf '%s\\n' \"STUB-ERROR: NEWROOT not cleared: ${NEWROOT}\" >&2\n"
    "      return 2\n"
    "   fi\n"
)

CLEAN_STUB = _REQUIRE_CHECK + (
    "   printf '%s\\n' \"OK: '/boot' has intended mount options\"\n"
    "   return 0\n"
    "}"
)

DEVIATION_STUB = _REQUIRE_CHECK + (
    "   printf '%s\\n' \"DEVIATION: '/boot' missing 'noexec' (have: 'rw,nosuid,nodev')\"\n"
    "   return 1\n"
    "}"
)

## Nonzero exit with NO DEVIATION line: the audit could not run (e.g. an older
## remount-secure that rejects --check), still receiving --check.
INDETERMINATE_STUB = _REQUIRE_CHECK + (
    "   printf '%s\\n' \"ERROR: --check unsupported\" >&2\n"
    "   return 1\n"
    "}"
)

## A DEVIATION line carrying HTML metacharacters: must not break out of the
## warning paragraph and inject a fake green OK into the GUI message.
HTML_INJECTION_STUB = _REQUIRE_CHECK + (
    "   printf '%s\\n' \"DEVIATION: '/mnt/</p><font color=green>OK</font>' missing 'noexec'\"\n"
    "   return 1\n"
    "}"
)


class CheckMountOptionsScenarios(ScenarioTestBase):
    FILE = 'check_mount_options.bsh'

    def test_hardened_emits_info_when_verbose(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=1', stubs=CLEAN_STUB)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    def test_hardened_is_silent_when_not_verbose(self) -> None:
        ## The green result is verbose-gated: a hardened system stays quiet.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0', stubs=CLEAN_STUB)
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, '0')

    def test_deviation_warns_and_fails(self) -> None:
        ## A deviation must warn regardless of verbosity, set EXIT_CODE, and
        ## surface the deviating mountpoint.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0', stubs=DEVIATION_STUB)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')
        self.assertIn('/boot', r.joined())
        self.assertIn('Not hardened', r.joined())

    def test_failed_audit_reports_indeterminate(self) -> None:
        ## A nonzero exit with no DEVIATION lines is a failed audit, reported
        ## honestly as Indeterminate rather than a false "Not hardened".
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0', stubs=INDETERMINATE_STUB)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')
        self.assertIn('Indeterminate', r.joined())
        self.assertNotIn('Not hardened', r.joined())

    def test_deviation_html_metachars_are_sanitized(self) -> None:
        ## A hardening FAILURE must never be renderable as a green OK: the
        ## injected markup must be stripped before it reaches the HTML message.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0', stubs=HTML_INJECTION_STUB)
        self.assertTrue(r.has_severity('warning'))
        emitted = r.joined()
        self.assertNotIn('<font color=green>OK</font>', emitted)
        self.assertNotIn('</p><font', emitted)
        ## The deviation must SURVIVE sanitization (markup stripped to plain
        ## text), not be dropped: a lost DEVIATION line would fall back to a
        ## bare "Indeterminate" and silently hide the hardening failure. The
        ## injected mountpoint strips to '/mnt/OK'.
        self.assertIn('Not hardened', emitted)
        self.assertIn("/mnt/OK", emitted)

    def test_newroot_is_cleared(self) -> None:
        ## An inherited NEWROOT must not redirect the audit to a fake root and
        ## fabricate a hardened pass: the check clears it, so the stub (which
        ## errors on a non-empty NEWROOT) runs normally and still flags /boot.
        r = run_check_scenario(
            self.check(self.FILE), 'check_mount_options',
            env_setup='verbose=0\nNEWROOT=/definitely-not-a-real-root',
            stubs=DEVIATION_STUB)
        self.assertTrue(r.has_severity('warning'))
        ## The failing audit must reach callers via EXIT_CODE too, not only in
        ## the message -- a warn-but-exit-0 regression would hide the failure.
        self.assertEqual(r.exit_code, '1')
        self.assertIn('/boot', r.joined())
        self.assertIn('Not hardened', r.joined())

    def test_level_below_max_is_orange_info_not_ci(self) -> None:
        ## A configured level below the most restrictive (3) is a deliberate
        ## admin choice: interactively an orange INFO notice, never a hard fail
        ## (EXIT_CODE stays 0). The clean audit is verbose-gated, so the only
        ## visible record is the level line.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0\nSTUB_LEVEL=2', stubs=CLEAN_STUB)
        self.assertIn('Mount Options Hardening Level', r.joined())
        self.assertIn('Level 2 (below 3)', r.joined())
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    def test_level_below_max_fails_in_ci(self) -> None:
        ## Under --ci a lowered level is a hard failure (non-zero exit) so it
        ## cannot ship unnoticed.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0\nci=true\nSTUB_LEVEL=0', stubs=CLEAN_STUB)
        self.assertIn('Level 0 (below 3)', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_level_max_is_silent_when_not_verbose(self) -> None:
        ## The most restrictive level (3) is the OK state: verbose-gated, so a
        ## fully-hardened system shows no level line.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0\nSTUB_LEVEL=3', stubs=CLEAN_STUB)
        self.assertNotIn('Hardening Level', r.joined())
        self.assertEqual(r.exit_code, '0')

    def test_level_indeterminate_is_orange_info_not_ci(self) -> None:
        ## --get-level unreadable (e.g. an older remount-secure) -> an orange
        ## Indeterminate level notice; a hard fail only under --ci.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0\nSTUB_LEVEL=fail', stubs=CLEAN_STUB)
        self.assertIn('Mount Options Hardening Level', r.joined())
        self.assertIn('Indeterminate', r.joined())
        self.assertEqual(r.exit_code, '0')

    def test_level_indeterminate_fails_in_ci(self) -> None:
        ## The same unreadable-level case is a hard failure under --ci.
        r = run_check_scenario(self.check(self.FILE), 'check_mount_options',
                               env_setup='verbose=0\nci=true\nSTUB_LEVEL=fail', stubs=CLEAN_STUB)
        self.assertIn('Mount Options Hardening Level', r.joined())
        self.assertEqual(r.exit_code, '1')


if __name__ == '__main__':
    unittest.main()
