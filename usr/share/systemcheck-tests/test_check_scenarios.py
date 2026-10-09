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
cannot be steered this way; those run in a bubblewrap mount namespace in the
systemcheck-tests-bwrap sub-suite (test_check_scenarios_isolated.py).
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario,
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


class TestTempdirScenarios(ScenarioTestBase):
    FILE = 'check_tempdir.bsh'

    ## id -> uid 1000, so the expected per-user tmpdir is /tmp/user/1000. The
    ## four temp-dir variables are set to it; verbose=1 so the OK info line is
    ## emitted (it is verbose-gated).
    GOOD_ENV = ('TMPDIR=/tmp/user/1000\nTMP=/tmp/user/1000\n'
                'TEMP=/tmp/user/1000\nTEMPDIR=/tmp/user/1000\nverbose=1\n')
    ## id stub. `test`/`stat` are stubbed per scenario; `test` and `[` are
    ## different builtins, so stubbing a `test` function steers only the
    ## directory probes, not the emit helpers' `[`.
    ID = 'id() { printf "1000\\n"; }\n'
    ## Safe layout: base /tmp/user root-owned (%u=0) mode 0711 (%a=711), per-user
    ## /tmp/user/1000 mode 0700 (%a on a path containing /tmp/user/); nothing is a
    ## symlink (-h false), dirs present and owned (-d/-O true).
    STAT_OK = ('stat() { case "$*" in *--format=%u*) printf "0\\n" ;; '
               '*--format=%a*/tmp/user/*) printf "700\\n" ;; '
               '*--format=%a*) printf "711\\n" ;; esac; }\n')
    TEST_OK = ('test() { case "$1" in -h) return 1 ;; -d|-O) return 0 ;; '
               '*) builtin test "$@" ;; esac; }\n')

    def test_all_correct_emits_info_no_failure(self) -> None:
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=self.GOOD_ENV,
                               stubs=self.ID + self.STAT_OK + self.TEST_OK)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    def test_ok_info_is_verbose_gated(self) -> None:
        env = self.GOOD_ENV.replace('verbose=1', 'verbose=0')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=env,
                               stubs=self.ID + self.STAT_OK + self.TEST_OK)
        ## assertCleanRun first: a Bash error would also leave records empty and
        ## make the empty-record assertion pass vacuously.
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, '0')

    def test_variable_wrong_warns_and_fails(self) -> None:
        env = ('TMPDIR=/tmp/user/1000\nTMP=/tmp/user/1000\n'
               'TEMP=/tmp/user/1000\nTEMPDIR=/tmp/elsewhere\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=env, stubs=self.ID)
        self.assertTrue(r.has_severity('warning'))
        ## Only the variable NAME is reported, never its (user-controlled) value.
        self.assertIn('incorrect: TEMPDIR', r.joined())
        self.assertNotIn('/tmp/elsewhere', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_variable_unset_warns_and_fails(self) -> None:
        env = ('TMPDIR=/tmp/user/1000\nTMP=/tmp/user/1000\n'
               'TEMP=/tmp/user/1000\nunset TEMPDIR\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=env, stubs=self.ID)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('incorrect: TEMPDIR', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_hostile_value_is_not_rendered(self) -> None:
        ## A user-set TMP containing markup must NOT reach the HTML message
        ## (else it could forge a green result); only the name is reported.
        env = ("TMPDIR=/tmp/user/1000\nTEMP=/tmp/user/1000\n"
               "TEMPDIR=/tmp/user/1000\n"
               "TMP='<font color=\"green\">OK</font>'\n")
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=env, stubs=self.ID)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('incorrect: TMP', r.joined())
        self.assertNotIn('<font color="green">OK</font>', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_base_dir_not_root_owned_warns(self) -> None:
        ## Variables correct, per-user dir fine, but /tmp/user is not root-owned.
        stat_base_bad = ('stat() { case "$*" in *--format=%u*) printf "1000\\n" ;; '
                         '*--format=%a*/tmp/user/*) printf "700\\n" ;; '
                         '*--format=%a*) printf "711\\n" ;; esac; }\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=self.GOOD_ENV,
                               stubs=self.ID + stat_base_bad + self.TEST_OK)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('base directory', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_symlink_peruser_dir_warns(self) -> None:
        ## Base fine; the per-user dir is a symlink (-h true only for it).
        test_symlink = ('test() { p="${!#}"; case "$1" in '
                        '-h) [ "$p" = /tmp/user/1000 ] ;; -d|-O) return 0 ;; '
                        '*) builtin test "$@" ;; esac; }\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=self.GOOD_ENV,
                               stubs=self.ID + self.STAT_OK + test_symlink)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('owned by this account', r.joined())
        self.assertEqual(r.exit_code, '1')

    def test_wrong_mode_peruser_dir_warns(self) -> None:
        ## Base fine; the per-user dir is mode 0755, not 0700.
        stat_peruser_bad = ('stat() { case "$*" in *--format=%u*) printf "0\\n" ;; '
                            '*--format=%a*/tmp/user/*) printf "755\\n" ;; '
                            '*--format=%a*) printf "711\\n" ;; esac; }\n')
        r = run_check_scenario(self.check(self.FILE), 'check_tempdir',
                               env_setup=self.GOOD_ENV,
                               stubs=self.ID + stat_peruser_bad + self.TEST_OK)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('owned by this account', r.joined())
        self.assertEqual(r.exit_code, '1')


if __name__ == '__main__':
    unittest.main()
