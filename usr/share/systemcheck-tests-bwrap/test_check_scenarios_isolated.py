#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Isolated scenario tests for individual systemcheck check functions: checks
gated on absolute-path files, or that call a binary by absolute path, run
inside a bubblewrap mount namespace so those paths can be neutralized.
Unsandboxed scenarios for the other checks: systemcheck-tests
test_check_scenarios.py.
"""

import os
import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario_isolated,
)


class TestGrubSecurityIsolatedScenarios(ScenarioTestBase):
    FILE = 'check_grub_security.bsh'
    ## Bare metal (virtualizer none) with the Qubes marker hidden, so the two
    ## early guards fall through to the real password check.
    BAREMETAL = 'systemcheck_virtualizer_detected=none\nverbose=1'
    HIDE = ['/usr/share/qubes']

    def test_password_enabled_info(self) -> None:
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_grub_security',
            env_setup=self.BAREMETAL, stubs='leaprun() { return 0; }',
            hide_dirs=self.HIDE)
        self.assertIn('>Enabled<', r.joined())
        self.assertTrue(r.has_severity('info'))

    def test_password_absent_disabled(self) -> None:
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_grub_security',
            env_setup=self.BAREMETAL, stubs='leaprun() { return 1; }',
            hide_dirs=self.HIDE)
        self.assertIn('>Disabled<', r.joined())

    def test_skipped_on_qubes(self) -> None:
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_grub_security',
            env_setup=self.BAREMETAL, stubs='leaprun() { return 0; }',
            place=[('/usr/share/qubes/marker-vm', '', False)])
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])

    def test_skipped_in_vm(self) -> None:
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_grub_security',
            env_setup='systemcheck_virtualizer_detected=kvm\nverbose=1',
            stubs='leaprun() { return 0; }', hide_dirs=self.HIDE)
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])


class TestFullDiskEncryptionIsolatedScenarios(ScenarioTestBase):
    FILE = 'check_full_disk_encryption.bsh'
    BAREMETAL = 'systemcheck_virtualizer_detected=none\nverbose=1'
    HIDE = ['/usr/share/qubes']

    def _run(self, crypt_check_rc: int):
        ## crypt-check is called by absolute path, so place a fake over it whose
        ## exit code selects the FDE state (0 full, 1 partial, else none).
        return run_check_scenario_isolated(
            self.check(self.FILE), 'check_full_disk_encryption',
            env_setup=self.BAREMETAL, hide_dirs=self.HIDE,
            place=[('/usr/libexec/systemcheck/crypt-check',
                    f"#!/bin/bash\nexit {crypt_check_rc}\n", True)])

    def test_fully_encrypted_enabled(self) -> None:
        self.assertIn('>Enabled<', self._run(0).joined())

    def test_partly_encrypted_partial(self) -> None:
        self.assertIn('>Partial<', self._run(1).joined())

    def test_unencrypted_disabled(self) -> None:
        self.assertIn('>Disabled<', self._run(2).joined())


class TestTirdadModuleIsolatedScenarios(ScenarioTestBase):
    FILE = 'check_tirdad_module.bsh'
    ## Bare-metal Intel/AMD, Secure Boot off, Qubes marker hidden.
    ENV = ('intel_amd_64_detected=true\nsecure_boot_status_enabled=false\n'
           'verbose=1\nsilent=0')
    HIDE = ['/usr/share/qubes']

    def test_module_loaded_enabled(self) -> None:
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_tirdad_module',
            env_setup=self.ENV, stubs='lsmod() { echo tirdad; }',
            hide_dirs=self.HIDE)
        self.assertIn('>Enabled<', r.joined())
        self.assertTrue(r.has_severity('info'))

    def test_module_missing_warns_and_fails(self) -> None:
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_tirdad_module',
            env_setup=self.ENV, stubs='lsmod() { echo other_module; }',
            hide_dirs=self.HIDE)
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')
        self.assertIn('>Disabled<', r.joined())

    def test_module_missing_on_qubes_is_benign_info(self) -> None:
        ## On Qubes an unloaded tirdad is a known, benign, verbose-only info.
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_tirdad_module',
            env_setup=self.ENV, stubs='lsmod() { echo other_module; }',
            place=[('/usr/share/qubes/marker-vm', '', False)])
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')


class TestApparmorIsolatedScenarios(ScenarioTestBase):
    FILE = 'check_apparmor.bsh'
    ## check_apparmor runs /usr/bin/disallowed-test (a binary AppArmor is meant
    ## to DENY) and looks for "/usr/bin/disallowed-test: Permission denied" in
    ## the output. A single-file bind places a fake there without hiding the
    ## rest of /usr/bin (which holds bash).
    DENIED = ('/usr/bin/disallowed-test',
              '#!/bin/bash\necho "/usr/bin/disallowed-test: Permission denied"\n',
              True)
    RAN = ('/usr/bin/disallowed-test', '#!/bin/bash\necho ran-unrestricted\n', True)

    def test_apparmor_enforcing_is_ok(self) -> None:
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_apparmor', env_setup='verbose=1',
            bind_files=[self.DENIED])
        self.assertTrue(r.has_severity('info'))
        self.assertIn('OK.', r.joined())
        self.assertEqual(r.exit_code, '0')

    def test_apparmor_not_confining_fails(self) -> None:
        r = run_check_scenario_isolated(
            self.check(self.FILE), 'check_apparmor', env_setup='verbose=1',
            stubs='cleanup() { :; }', bind_files=[self.RAN])
        self.assertTrue(r.has_severity('error'))
        self.assertEqual(r.exit_code, '1')
        self.assertIn('Failed', r.joined())


class TestAptRepositoryIsolatedScenarios(ScenarioTestBase):
    """check_apt_repository branches on the presence/readability of
    /etc/apt/sources.list.d/derivative.{sources,list}, so it needs the isolated
    runner to control those absolute paths.

    The Disabled branch (derivative repository NOT configured) MUST fail the run:
    a system that silently stopped receiving the project's security updates is a
    real finding, not cosmetic.
    """

    FILE = 'check_apt_repository.bsh'
    SOURCES = '/etc/apt/sources.list.d/derivative.sources'
    LEGACY = '/etc/apt/sources.list.d/derivative.list'
    ENV = ('silent=0\nverbose=1\n'
           'PROJECT_NAME=Kicksecure\n'
           'PROJECT_HOMEPAGE=https://www.kicksecure.com\n')
    SOURCES_BODY = 'Types: deb\nURIs: https://example\nSuites: bookworm\nComponents: main\n'

    def _run(self, ci: str, **kw):
        return run_check_scenario_isolated(
            self.check(self.FILE), 'check_apt_repository',
            env_setup=self.ENV + f'ci={ci}\n', **kw)

    def test_enabled_info_no_failure(self) -> None:
        ## derivative.sources present + readable -> Enabled, informational only.
        r = self._run('false', place=[(self.SOURCES, self.SOURCES_BODY, False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertIn('Enabled', r.joined())
        self.assertEqual(r.exit_code, '0')

    def test_disabled_warns_and_fails(self) -> None:
        ## Neither derivative.sources nor derivative.list present -> Disabled.
        r = self._run('false', hide_dirs=[os.path.dirname(self.SOURCES)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('Disabled', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_disabled_fails_even_under_ci(self) -> None:
        ## The guarantee this suite exists to lock in: --ci tolerates ONLY the
        ## "updates available" finding (check_operating_system). A DISABLED
        ## derivative repository must still exit non-zero under --ci, so a CI /
        ## image-build gate cannot pass with the security-update channel off.
        r = self._run('true', hide_dirs=[os.path.dirname(self.SOURCES)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('Disabled', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_legacy_list_warns_and_fails(self) -> None:
        ## Old-format derivative.list (release-upgraded system) -> Legacy warning.
        r = self._run('false', place=[(self.LEGACY,
                                       'deb https://example bookworm main\n', False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('Legacy', r.joined())
        self.assertEqual(r.exit_code, '1')


if __name__ == '__main__':
    unittest.main()
