#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Path-exercising scenario tests for individual systemcheck check functions.

Each check is run in isolation via run_check_scenario, which points the
$output_x / $output_cli emission variables at a recorder and stubs the external
commands a check calls (leaprun, dpkg, hostname, man, ...). The tests then
assert on the SEVERITY of what the check emits (info vs warning vs error) and on
$EXIT_CODE, driving each check down its info / warning / error branches to
exercise as many code paths as possible.

Checks gated on absolute-path files (e.g. `[ -f /usr/share/qubes/marker-vm ]`)
cannot be steered this way in isolation; those are covered at integration level
and tracked in COVERAGE.md.
"""

import os
import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
    run_check_scenario_isolated,
)


class TestEnvironmentVariablesScenarios(ScenarioTestBase):
    FILE = 'check_environment_variables.bsh'

    def test_gateway_missing_whonix_env_warns_and_fails(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_environment_variables',
            env_setup='vm_lower_case_short=gateway\nWHONIX=0')
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')

    def test_workstation_missing_whonix_env_warns(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_environment_variables',
            env_setup='vm_lower_case_short=workstation\nWHONIX=0')
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')

    def test_machine_missing_kicksecure_env_warns_and_fails(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_environment_variables',
            env_setup='vm_lower_case_short=machine\nKICKSECURE=0')
        self.assertTrue(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '1')

    def test_machine_ok_emits_info_no_failure(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_environment_variables',
            env_setup='vm_lower_case_short=machine\nKICKSECURE=1\nverbose=1')
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    def test_gateway_ok_emits_info(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_environment_variables',
            env_setup='vm_lower_case_short=gateway\nWHONIX=1\nverbose=1')
        self.assertTrue(r.has_severity('info'))
        self.assertEqual(r.exit_code, '0')

    def test_ok_info_is_verbose_gated(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_environment_variables',
            env_setup='vm_lower_case_short=machine\nKICKSECURE=1\nverbose=0')
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, '0')

    def test_emits_to_both_channels(self) -> None:
        ## The warning path is not verbose-gated, so emit_message must reach
        ## BOTH the GUI (x) and CLI channels.
        r = run_check_scenario(
            self.check(self.FILE), 'check_environment_variables',
            env_setup='vm_lower_case_short=machine\nKICKSECURE=0')
        channels = {channel for channel, _s, _m in r.records}
        self.assertEqual(channels, {'x', 'cli'})


class TestManScenarios(ScenarioTestBase):
    FILE = 'check_man.bsh'

    def test_broken_man_warns(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_man',
                               stubs='man() { return 1; }')
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('Broken', r.joined())

    def test_working_man_info_when_verbose(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_man',
                               env_setup='verbose=1',
                               stubs='man() { return 0; }')
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))

    def test_working_man_silent_when_not_verbose(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_man',
                               env_setup='verbose=0',
                               stubs='man() { return 0; }')
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])


class TestDpkgScenarios(ScenarioTestBase):
    FILE = 'check_dpkg.bsh'
    ENV = ('booted_in_sysmaint_session=false\n'
           'user_sysmaint_split_installed=false\n'
           'start_menu_instructions_system_first_part="Start Menu"')

    def test_broken_dpkg_state_errors_and_fails_regardless_of_verbosity(self) -> None:
        ## A real dpkg-audit failure must fail the run even when not verbose.
        r = run_check_scenario(
            self.check(self.FILE), 'check_dpkg',
            env_setup=self.ENV + '\nverbose=0',
            stubs='dpkg() { echo "pkg half-installed; needs configure"; }')
        self.assertTrue(r.has_severity('error'))
        self.assertEqual(r.exit_code, '1')

    def test_clean_dpkg_state_info_when_verbose(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_dpkg',
            env_setup=self.ENV + '\nverbose=1',
            stubs='dpkg() { return 0; }')
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('error'))
        self.assertEqual(r.exit_code, '0')

    def test_clean_dpkg_state_silent_when_not_verbose(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_dpkg',
            env_setup=self.ENV + '\nverbose=0',
            stubs='dpkg() { return 0; }')
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, '0')


class TestHostnameScenarios(ScenarioTestBase):
    FILE = 'check_hostname.bsh'
    ## Stub 'hostname' to return the Kicksecure defaults for every flag.
    GOOD = ('hostname() { case "$1" in '
            '--fqdn) echo host.localdomain;; '
            '--ip-address) echo 127.0.0.1;; '
            '--domain) echo localdomain;; '
            '*) echo host;; esac; }')

    def test_all_defaults_ok_info(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_hostname',
                               env_setup='vm_lower_case_short=gateway\nverbose=1',
                               stubs=self.GOOD)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('error'))
        self.assertEqual(r.exit_code, '0')

    def test_all_wrong_errors_and_fails(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_hostname',
                               env_setup='vm_lower_case_short=gateway\nverbose=1',
                               stubs='hostname() { echo wronghost; }')
        self.assertTrue(r.has_severity('error'))
        self.assertEqual(r.exit_code, '1')

    def test_single_field_wrong_errors(self) -> None:
        ## Only --fqdn wrong; the rest correct. Must still error + fail.
        stub = ('hostname() { case "$1" in '
                '--fqdn) echo not.the.default;; '
                '--ip-address) echo 127.0.0.1;; '
                '--domain) echo localdomain;; '
                '*) echo host;; esac; }')
        r = run_check_scenario(self.check(self.FILE), 'check_hostname',
                               env_setup='vm_lower_case_short=gateway\nverbose=1',
                               stubs=stub)
        self.assertTrue(r.has_severity('error'))
        self.assertEqual(r.exit_code, '1')

    def test_skipped_on_machine(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_hostname',
                               env_setup='vm_lower_case_short=machine',
                               stubs=self.GOOD)
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])


class TestUserSysmaintSplitScenarios(ScenarioTestBase):
    FILE = 'check_user_sysmaint_split.bsh'

    def test_installed_reports_installed(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split',
            env_setup='booted_in_sysmaint_session=false',
            stubs='leaprun() { return 0; }')
        joined = r.joined()
        self.assertIn('>Installed<', joined)
        self.assertNotIn('>Not installed<', joined)

    def test_absent_reports_not_installed(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split',
            env_setup='booted_in_sysmaint_session=false',
            stubs='leaprun() { return 1; }')
        self.assertIn('>Not installed<', r.joined())

    def test_boot_mode_reports_user_session(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split',
            env_setup='booted_in_sysmaint_session=false',
            stubs='leaprun() { return 0; }')
        self.assertIn('USER Session', r.joined())

    def test_boot_mode_reports_sysmaint_session(self) -> None:
        r = run_check_scenario(
            self.check(self.FILE), 'check_user_sysmaint_split',
            env_setup='booted_in_sysmaint_session=true',
            stubs='leaprun() { return 0; }')
        self.assertIn('SYSMAINT Session', r.joined())


class TestMetaPackagesScenarios(ScenarioTestBase):
    FILE = 'check_packages.bsh'
    ENV = 'qubes_detected=false\nvm_lower_case_short=machine'

    def test_a_meta_package_installed_info(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_meta_packages',
                               env_setup=self.ENV + '\nverbose=1',
                               stubs='dpkg() { return 0; }')
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))

    def test_no_meta_package_installed_warns(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_meta_packages',
                               env_setup=self.ENV,
                               stubs='dpkg() { return 1; }')
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('No meta package', r.joined())


class TestUnwantedPackagesScenarios(ScenarioTestBase):
    FILE = 'check_packages.bsh'

    def test_none_installed_info(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_unwanted_packages',
                               env_setup='systemcheck_unwanted_package="somepkg"\nverbose=1',
                               stubs='dpkg-query() { :; }')
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))

    def test_unwanted_package_installed_warns(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_unwanted_packages',
                               env_setup='systemcheck_unwanted_package="badpkg"\n'
                                         'qubes_detected=false',
                               stubs='dpkg-query() { echo "install ok installed"; }')
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('unwanted package', r.joined())


## ---------------------------------------------------------------------------
## Isolated scenarios: checks gated on absolute-path files, or that call a
## binary by absolute path, run inside a bubblewrap mount namespace so those
## paths can be neutralized. These SkipTest when bubblewrap / user namespaces
## are unavailable.
## ---------------------------------------------------------------------------

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


class TestTempdirScenarios(ScenarioTestBase):
    FILE = 'check_tempdir.bsh'

    ## id -> uid 1000, so the expected per-user tmpdir is /tmp/user/1000. The
    ## four temp-dir variables are set to it; verbose=1 so the OK info line is
    ## emitted (it is verbose-gated).
    GOOD_ENV = ('TMPDIR=/tmp/user/1000\nTMP=/tmp/user/1000\n'
                'TEMP=/tmp/user/1000\nTEMPDIR=/tmp/user/1000\nverbose=1\n')
    ## A safe directory: non-symlink (-h false), present and owned (-d/-O true),
    ## mode 0700. `test` and `[` are different builtins, so stubbing a `test`
    ## function steers only the directory probes, not the emit helpers' `[`.
    DIR_OK = ('id() { printf "1000\\n"; }\n'
              'stat() { printf "700\\n"; }\n'
              'test() { case "$1" in -h) return 1 ;; -d|-O) return 0 ;; '
              '*) builtin test "$@" ;; esac; }\n')

    def test_all_correct_emits_info_no_failure(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=self.GOOD_ENV, stubs=self.DIR_OK)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    def test_ok_info_is_verbose_gated(self) -> None:
        env = self.GOOD_ENV.replace('verbose=1', 'verbose=0')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=env, stubs=self.DIR_OK)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, '0')

    def test_variable_wrong_warns_and_fails(self) -> None:
        env = ('TMPDIR=/tmp/user/1000\nTMP=/tmp/user/1000\n'
               'TEMP=/tmp/user/1000\nTEMPDIR=/tmp/elsewhere\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=env, stubs='id() { printf "1000\\n"; }\n')
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('TEMPDIR=/tmp/elsewhere', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_variable_unset_warns_and_fails(self) -> None:
        env = ('TMPDIR=/tmp/user/1000\nTMP=/tmp/user/1000\n'
               'TEMP=/tmp/user/1000\nunset TEMPDIR\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=env, stubs='id() { printf "1000\\n"; }\n')
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('TEMPDIR=<unset>', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_symlink_dir_warns_and_fails(self) -> None:
        ## Variables correct, but the directory is a symlink (-h true) -> Unsafe.
        stubs = ('id() { printf "1000\\n"; }\n'
                 'stat() { printf "700\\n"; }\n'
                 'test() { case "$1" in -h) return 0 ;; *) return 0 ;; esac; }\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=self.GOOD_ENV, stubs=stubs)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('Unsafe', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_wrong_mode_dir_warns_and_fails(self) -> None:
        ## Variables correct, directory present and owned, but mode 0755 -> Unsafe.
        stubs = ('id() { printf "1000\\n"; }\n'
                 'stat() { printf "755\\n"; }\n'
                 'test() { case "$1" in -h) return 1 ;; -d|-O) return 0 ;; '
                 '*) builtin test "$@" ;; esac; }\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=self.GOOD_ENV, stubs=stubs)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('Unsafe', r.joined())
        self.assertEqual(r.exit_code, '1')


if __name__ == '__main__':
    unittest.main()
