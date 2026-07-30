#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for the boot-test check_journal / check_services /
check_system_ready fixes (image boot-test lane went red when check_journal was
un-skipped):

  * check_services --ignore-failed-unit: a failed unit named on the CLI ignore
    list is dropped from the failed-units set, so an otherwise-clean system
    passes (used for systemd-modules-load under Secure Boot, where the unsigned
    out-of-tree tirdad module cannot load).
  * check_system_ready --ignore-failed-unit: a 'degraded' is-system-running
    result caused SOLELY by ignored units is treated as ready, while a genuine
    non-ignored failure still fails.
  * log-checker word-boundary 'BUG': the search pattern must not match the
    substring in "FOR DEBUGGING ONLY" (debug-shell.service) yet still catch a
    real kernel "BUG:".
  * 30_default.conf journal-ignore covers the benign spice-vdagentd
    "Error getting active session" line seen on headless / sysmaint boots.
  * dm-image-test --journal-ignore-fixed covers the mount-shared failure that
    every qcow2 leg hits, because no shared folder is attached to qemu.
"""

import os
import re
import unittest

from systemcheck_testlib import (
    SystemcheckTestBase,
    ScenarioTestBase,
    read,
    run_check_scenario,
)

SERVICES = 'check_services.bsh'
SYSREADY = 'check_system_ready.bsh'


class TestCheckServicesIgnoreFailedUnit(ScenarioTestBase):
    """check_services_do honours systemcheck_ignore_failed_units_cli."""

    ## machine_command_machine / _pretty / _desc are the commands check_services_do
    ## runs to list failed units; stub them to emit a canned failed-units list.
    ## Each unit line is emitted as its own printf arg so real newlines separate
    ## them (a single repr'd string would embed a literal '\n' and collapse to
    ## one line).
    def _run(self, units: list, ignore: str):
        args = ' '.join(repr(u) for u in units)
        stubs = (
            f"failed_units_stub() {{ printf '%s\\n' {args}; }}\n"
        )
        env = (
            'check_type=system\n'
            'machine_command_machine=failed_units_stub\n'
            'machine_command_pretty=failed_units_stub\n'
            'machine_command_desc=desc\n'
            f"systemcheck_ignore_failed_units_cli={ignore!r}\n"
            'verbose=1\n'
        )
        return run_check_scenario(self.check(SERVICES), 'check_services_do',
                                  env_setup=env, stubs=stubs)

    def test_sole_ignored_unit_passes(self) -> None:
        r = self._run(
            ['systemd-modules-load.service loaded failed failed Load Kernel Modules'],
            'systemd-modules-load.service')
        self.assertEqual(r.exit_code, '0')
        self.assertIn('>OK.<', r.joined())

    def test_other_failed_unit_still_fails(self) -> None:
        r = self._run(
            ['apparmor.service loaded failed failed AppArmor',
             'systemd-modules-load.service loaded failed failed Load Kernel Modules'],
            'systemd-modules-load.service')
        ## A non-ignored failed unit remains -> the "one or more units failed"
        ## warning fires.
        self.assertIn('units failed to load', r.joined())

    def test_no_ignore_list_reports_failure(self) -> None:
        r = self._run(
            ['systemd-modules-load.service loaded failed failed Load Kernel Modules'],
            '')
        self.assertIn('units failed to load', r.joined())


class TestCheckSystemReadyIgnoreFailedUnit(ScenarioTestBase):
    """check_system_ready_system treats degraded-by-ignored-only as ready."""

    def _run(self, units: list, ignore: str):
        ## leaprun system-ready-check -> the is-system-running result; systemctl
        ## --failed ... -> the failed-units list consulted by the ignore helper.
        ## Emit each failed unit as its own printf arg (real newlines).
        args = ' '.join(repr(u) for u in units)
        stubs = (
            'leaprun() { echo degraded; }\n'
            'leaprun_cmd_describe() { echo desc; }\n'
            f"systemctl() {{ printf '%s\\n' {args}; }}\n"
        )
        env = (
            f"systemcheck_ignore_failed_units_cli={ignore!r}\n"
            'verbose=1\n'
        )
        return run_check_scenario(self.check(SYSREADY),
                                  'check_system_ready_system',
                                  env_setup=env, stubs=stubs)

    def test_degraded_only_ignored_units_is_ready(self) -> None:
        r = self._run(
            ['systemd-modules-load.service loaded failed failed Load Kernel Modules'],
            'systemd-modules-load.service')
        self.assertEqual(r.exit_code, '0')
        self.assertNotIn('Result: Failed', r.joined())

    def test_degraded_other_unit_fails(self) -> None:
        r = self._run(
            ['apparmor.service loaded failed failed AppArmor',
             'systemd-modules-load.service loaded failed failed Load Kernel Modules'],
            'systemd-modules-load.service')
        self.assertEqual(r.exit_code, '1')
        self.assertIn('Result: Failed', r.joined())

    def test_degraded_no_ignore_list_fails(self) -> None:
        r = self._run(
            ['systemd-modules-load.service loaded failed failed Load Kernel Modules'],
            '')
        self.assertEqual(r.exit_code, '1')
        self.assertIn('Result: Failed', r.joined())


class TestLogCheckerBugWordBoundary(SystemcheckTestBase):
    """log-checker's journal search pattern anchors 'BUG' on word boundaries."""

    def _pattern(self) -> str:
        text = read(os.path.join(self.dir, 'log-checker'))
        m = re.search(r'journal_search_pattern_list="([^"]*)"', text)
        self.assertIsNotNone(m, 'journal_search_pattern_list not found')
        return m.group(1)

    def test_debugging_not_flagged(self) -> None:
        pat = self._pattern()
        line = ('systemd[1]: Starting debug-shell.service - '
                'Early root shell on /dev/tty9 FOR DEBUGGING ONLY')
        self.assertIsNone(re.search(pat, line),
                          'DEBUGGING must not match the BUG pattern')

    def test_real_bug_flagged(self) -> None:
        pat = self._pattern()
        line = 'kernel: BUG: unable to handle kernel NULL pointer dereference'
        self.assertIsNotNone(re.search(pat, line),
                             'a real kernel BUG: must still be flagged')


class TestSpiceVdagentdJournalIgnore(SystemcheckTestBase):
    """30_default.conf ignores the benign spice-vdagentd session message."""

    def test_ignore_pattern_matches_real_line(self) -> None:
        ## self.dir is $REPO/usr/libexec/systemcheck; the config is at
        ## $REPO/etc/systemcheck.d/30_default.conf.
        conf_path = os.path.normpath(os.path.join(
            self.dir, '..', '..', '..', 'etc', 'systemcheck.d',
            '30_default.conf'))
        conf = read(conf_path)
        m = re.search(
            r'journal_ignore_patterns_list\+=\(\s*"(spice-vdagentd[^"]*)"\s*\)',
            conf)
        self.assertIsNotNone(
            m, 'spice-vdagentd journal_ignore pattern not found')
        pat = m.group(1)
        line = ('localhost spice-vdagentd[1447]: '
                'Error getting active session: No data available')
        self.assertIsNotNone(re.search(pat, line, re.IGNORECASE),
                             'ignore pattern must match the real journal line')


if __name__ == '__main__':
    unittest.main()


class TestMountSharedJournalIgnore(SystemcheckTestBase):
    """dm-image-test ignores the mount-shared failure qemu guarantees.

    No shared folder is attached to the boot-test qemu invocation, so
    vm-config-dist's mount-shared cannot mount /mnt/shared. The script tolerates
    that ('|| true'); only mount's stderr reaches the journal, where
    check_journal reports it and fails every qcow2 leg.
    """

    def _ignore_string(self) -> str:
        ## dm-image-test ships in this same repo, so resolve it relative to this
        ## test file rather than self.dir (which points into the systemcheck
        ## checkout).
        path = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', 'dm-image-boot-tests', 'dm-image-test'))
        text = read(path)
        m = re.search(
            r'--journal-ignore-fixed \\"(mount: [^"\\]*)\\"', text)
        self.assertIsNotNone(
            m, 'mount-shared --journal-ignore-fixed string not found')
        return m.group(1)

    def test_matches_the_real_journal_line(self) -> None:
        ## --journal-ignore-fixed is a FIXED STRING, so containment is the test.
        line = ('localhost mount-shared[1022]: mount: /mnt/shared: wrong fs '
                'type, bad option, bad superblock on shared, missing codepage '
                'or helper program, or other error.')
        self.assertIn(self._ignore_string(), line,
                      'ignore string must match the real journal line')

    def test_other_failing_mount_still_reported(self) -> None:
        ## Naming the mount point keeps an unrelated mount failure visible.
        line = ('localhost mount[900]: mount: /mnt/other: wrong fs type, bad '
                'option, bad superblock on other, missing codepage or helper '
                'program, or other error.')
        self.assertNotIn(self._ignore_string(), line,
                         'a different failing mount must still be reported')
