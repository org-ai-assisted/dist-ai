#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for systemcheck_modules_load_degrade_is_tirdad_sb_only
(preparation.bsh) -- the --ci tolerance that lets the release gate's
system-ready / services checks pass when systemd-modules-load.service is degraded
SOLELY because the unsigned out-of-tree tirdad module was rejected under Secure
Boot.

WHY this exists: tirdad ships /usr/lib/modules-load.d/30_tirdad.conf; under Secure
Boot the kernel rejects the unsigned module ("Key was rejected by service"), so
systemd-modules-load.service fails and the system is 'degraded'. The operator
accepts tirdad being absent under Secure Boot, so --ci tolerates that -- but
MODULE-SPECIFICALLY: a blanket ignore of systemd-modules-load.service would also
mask a jitterentropy_rng (security-misc) load failure, the exact
"stable users bricked" regression the gate protects. These tests pin that the
tolerance fires ONLY for the tirdad-under-Secure-Boot case and FAILS on any other
module failure, Secure Boot off, or systemd-modules-load not actually failed.

Sources the real preparation.bsh, then stubs check_secure_boot_enabled /
systemctl / lsmod and sets the modules-load.d dir test seam
(systemcheck_modules_load_d_dirs).
"""

import os
import shutil
import tempfile
import unittest

from systemcheck_testlib import (
    SystemcheckTestBase,
    fragment_sources,
    run_sourced,
)


class TestModulesLoadTirdadTolerance(SystemcheckTestBase):
    def _verdict(self, sb_rc, modules_load_failed, loaded_mods, confs) -> str:
        """Return 'tolerate' or 'no' for the given mocked state."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for name, content in confs.items():
            with open(os.path.join(tmp, name), 'w', encoding='utf-8') as handle:
                handle.write(content)
        ml_rc = 0 if modules_load_failed else 1
        if loaded_mods:
            lsmod_body = 'printf "Module Size Used\\n"; ' + '; '.join(
                f'printf "%s 1 0\\n" {mod}' for mod in loaded_mods)
        else:
            lsmod_body = 'printf "Module Size Used\\n"'
        env_setup = (
            f'check_secure_boot_enabled() {{ return {sb_rc}; }}\n'
            f'systemctl() {{ if [ "$1" = is-failed ]; then return {ml_rc}; fi; return 0; }}\n'
            f'lsmod() {{ {lsmod_body}; }}\n'
            f'systemcheck_modules_load_d_dirs={tmp!r}\n'
        )
        return run_sourced(
            fragment_sources(),
            'systemcheck_modules_load_degrade_is_tirdad_sb_only '
            '&& echo tolerate || echo no',
            setup=env_setup,
        )

    _CONFS = {
        '30_security-misc.conf': 'jitterentropy_rng\n',
        '30_tirdad.conf': 'tirdad\n',
    }

    def test_sb_on_only_tirdad_missing_is_tolerated(self) -> None:
        self.assertEqual(
            'tolerate',
            self._verdict(0, True, ['jitterentropy_rng'], self._CONFS))

    def test_jitterentropy_also_failed_is_not_tolerated(self) -> None:
        ## tirdad AND jitterentropy_rng both missing -> a real shipped-module
        ## regression; must NOT be masked.
        self.assertEqual(
            'no',
            self._verdict(0, True, [], self._CONFS))

    def test_secure_boot_off_is_not_tolerated(self) -> None:
        ## Not under Secure Boot: a tirdad load failure is a real problem.
        self.assertEqual(
            'no',
            self._verdict(1, True, ['jitterentropy_rng'], self._CONFS))

    def test_modules_load_not_failed_is_not_tolerated(self) -> None:
        self.assertEqual(
            'no',
            self._verdict(0, False, ['jitterentropy_rng'], self._CONFS))

    def test_nothing_missing_is_not_tolerated(self) -> None:
        self.assertEqual(
            'no',
            self._verdict(0, True, ['jitterentropy_rng', 'tirdad'], self._CONFS))

    def test_second_nontirdad_module_missing_is_not_tolerated(self) -> None:
        ## tirdad plus an unrelated module missing -> not sole -> not tolerated.
        confs = dict(self._CONFS)
        confs['30_other.conf'] = 'some_other_mod\n'
        self.assertEqual(
            'no',
            self._verdict(0, True, ['jitterentropy_rng'], confs))

    def test_comments_and_dash_normalization(self) -> None:
        ## '#' comments ignored; a '-' in a module name matches the '_' lsmod form.
        self.assertEqual(
            'tolerate',
            self._verdict(0, True, ['some_mod'],
                          {'30_x.conf': '# a comment\nsome-mod\ntirdad\n'}))

    def test_semicolon_comment_ignored(self) -> None:
        ## A ';' comment line is not a module name (modules-load.d treats '#' and
        ## ';' alike); it must not count as a second not-loaded module.
        self.assertEqual(
            'tolerate',
            self._verdict(0, True, ['jitterentropy_rng'],
                          {'30_security-misc.conf': 'jitterentropy_rng\n',
                           '30_tirdad.conf': '; Secure Boot exception\ntirdad\n'}))

    def test_final_line_without_trailing_newline(self) -> None:
        ## A module on the last line with no trailing newline must still be read.
        self.assertEqual(
            'tolerate',
            self._verdict(0, True, ['jitterentropy_rng'],
                          {'30_security-misc.conf': 'jitterentropy_rng\n',
                           '30_tirdad.conf': 'tirdad'}))


class TestCiToleranceInjection(SystemcheckTestBase):
    """
    systemcheck_modules_load_ci_tolerance injects systemd-modules-load.service +
    its journal lines into the EXISTING ignore lists -- but ONLY in --ci and ONLY
    when the helper confirms the tirdad-under-Secure-Boot case.
    """

    def _inject(self, ci, sb_rc, modules_load_failed, loaded_mods, confs) -> str:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for name, content in confs.items():
            with open(os.path.join(tmp, name), 'w', encoding='utf-8') as handle:
                handle.write(content)
        ml_rc = 0 if modules_load_failed else 1
        if loaded_mods:
            lsmod_body = 'printf "Module Size Used\\n"; ' + '; '.join(
                f'printf "%s 1 0\\n" {mod}' for mod in loaded_mods)
        else:
            lsmod_body = 'printf "Module Size Used\\n"'
        env_setup = (
            f'ci={ci!r}\n'
            'systemcheck_ignore_failed_units_cli=""\n'
            'systemcheck_journal_ignore_fixed_cli=""\n'
            f'check_secure_boot_enabled() {{ return {sb_rc}; }}\n'
            f'systemctl() {{ if [ "$1" = is-failed ]; then return {ml_rc}; fi; return 0; }}\n'
            f'lsmod() {{ {lsmod_body}; }}\n'
            f'systemcheck_modules_load_d_dirs={tmp!r}\n'
        )
        return run_sourced(
            fragment_sources(),
            'systemcheck_modules_load_ci_tolerance; '
            'printf "IGN=[%s] JRN=[%s]\\n" '
            '"$systemcheck_ignore_failed_units_cli" '
            '"$systemcheck_journal_ignore_fixed_cli"',
            setup=env_setup,
        )

    _CONFS = {
        '30_security-misc.conf': 'jitterentropy_rng\n',
        '30_tirdad.conf': 'tirdad\n',
    }

    def test_ci_tirdad_sb_injects_unit_and_journal(self) -> None:
        out = self._inject('true', 0, True, ['jitterentropy_rng'], self._CONFS)
        ## Split IGN=[...] JRN=[...] so each list is asserted on its own: the unit
        ## in the failed-units ignore list, BOTH journal patterns in the journal
        ## list (the 'systemd-modules-load' one covers the "Failed to start
        ## systemd-modules-load.service" journal line that --ignore-failed-unit
        ## does not filter).
        ign, _, jrn = out.partition(' JRN=')
        self.assertIn('systemd-modules-load.service', ign)
        self.assertIn('systemd-modules-load', jrn)
        self.assertIn('Key was rejected by service', jrn)

    def test_non_ci_does_not_inject(self) -> None:
        out = self._inject('false', 0, True, ['jitterentropy_rng'], self._CONFS)
        self.assertEqual('IGN=[] JRN=[]', out)

    def test_ci_jitterentropy_also_failed_does_not_inject(self) -> None:
        out = self._inject('true', 0, True, [], self._CONFS)
        self.assertEqual('IGN=[] JRN=[]', out)

    def test_ci_secure_boot_off_does_not_inject(self) -> None:
        out = self._inject('true', 1, True, ['jitterentropy_rng'], self._CONFS)
        self.assertEqual('IGN=[] JRN=[]', out)


if __name__ == '__main__':
    unittest.main()
