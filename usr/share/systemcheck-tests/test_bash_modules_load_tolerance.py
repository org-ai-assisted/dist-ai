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

WHY this exists: under Secure Boot the kernel rejects the unsigned tirdad module
("Key was rejected by service"), so systemd-modules-load.service fails and the
system is 'degraded'. The operator accepts tirdad being absent under Secure Boot,
so --ci tolerates that -- but MODULE-SPECIFICALLY: a blanket ignore of
systemd-modules-load.service would also mask a jitterentropy_rng (security-misc)
load failure, the exact "stable users bricked" regression the gate protects.
These tests pin that the tolerance fires ONLY for the tirdad-under-Secure-Boot
case and FAILS on any other failed unit, any non-tirdad failed module, Secure Boot
off, systemd-modules-load not actually failed, or a rejected-count mismatch.

The real preparation.bsh helper now sources its evidence from:
  * `systemctl list-units --output json` (+ jq) -- no unit but
    systemd-modules-load.service may be 'failed', and it MUST be 'failed';
  * `check_secure_boot_enabled` -- Secure Boot must be on;
  * leaprun `log-checker-get-failed-load-modules-list` -- every failed module
    must be 'tirdad';
  * leaprun `log-checker-get-kernel-module-key-rejected-count` -- must equal the
    number of failed modules.
The tests stub exactly those four interfaces (jq is a real dependency).
"""

import json
import shlex
import unittest

from systemcheck_testlib import (
    SystemcheckTestBase,
    fragment_sources,
    run_sourced,
)


def _tirdad_env(sb_rc, modules_load_failed, failed_modules, rejected_count,
                other_failed_unit=False, ci=None) -> str:
    """Build the env_setup stubbing the helper's four evidence sources.

    sb_rc            -- check_secure_boot_enabled return code (0 = SB on).
    modules_load_failed -- whether systemd-modules-load.service is 'failed'.
    failed_modules   -- list fed back by log-checker-get-failed-load-modules-list.
    rejected_count   -- log-checker-get-kernel-module-key-rejected-count value.
    other_failed_unit -- add an unrelated 'failed' unit to the systemctl json.
    ci               -- when set, also prime the --ci injection vars.
    """
    units = [
        {'unit': 'systemd-modules-load.service',
         'active': 'failed' if modules_load_failed else 'active'},
        {'unit': 'some-ok.service', 'active': 'active'},
    ]
    if other_failed_unit:
        units.append({'unit': 'apparmor.service', 'active': 'failed'})
    units_json = json.dumps(units)
    failed_list = '\n'.join(failed_modules)
    env = ''
    if ci is not None:
        env += (f'ci={ci!r}\n'
                'systemcheck_ignore_failed_units_cli=""\n'
                'systemcheck_journal_ignore_fixed_cli=""\n')
    env += (
        f'check_secure_boot_enabled() {{ return {sb_rc}; }}\n'
        'systemctl() { case "$1" in list-units) printf %s '
        f'{shlex.quote(units_json)} ;; *) return 0 ;; esac; }}\n'
        'leaprun() { case "$1" in '
        'log-checker-get-failed-load-modules-list) printf "%s\\n" '
        f'{shlex.quote(failed_list)} ;; '
        'log-checker-get-kernel-module-key-rejected-count) printf "%s\\n" '
        f'{rejected_count} ;; esac; }}\n'
    )
    return env


class TestModulesLoadTirdadTolerance(SystemcheckTestBase):
    def _verdict(self, sb_rc, modules_load_failed, failed_modules,
                 rejected_count, other_failed_unit=False) -> str:
        """Return 'tolerate' or 'no' for the given mocked state."""
        return run_sourced(
            fragment_sources(),
            'systemcheck_modules_load_degrade_is_tirdad_sb_only '
            '&& echo tolerate || echo no',
            setup=_tirdad_env(sb_rc, modules_load_failed, failed_modules,
                              rejected_count, other_failed_unit),
        )

    def test_sb_on_only_tirdad_missing_is_tolerated(self) -> None:
        self.assertEqual('tolerate', self._verdict(0, True, ['tirdad'], 1))

    def test_jitterentropy_also_failed_is_not_tolerated(self) -> None:
        ## tirdad AND jitterentropy_rng both failed -> a real shipped-module
        ## regression; must NOT be masked.
        self.assertEqual(
            'no', self._verdict(0, True, ['tirdad', 'jitterentropy_rng'], 2))

    def test_secure_boot_off_is_not_tolerated(self) -> None:
        ## Not under Secure Boot: a tirdad load failure is a real problem.
        self.assertEqual('no', self._verdict(1, True, ['tirdad'], 1))

    def test_modules_load_not_failed_is_not_tolerated(self) -> None:
        ## systemd-modules-load.service not 'failed' -> degrade is not this case.
        self.assertEqual('no', self._verdict(0, False, ['tirdad'], 1))

    def test_nothing_missing_is_not_tolerated(self) -> None:
        ## No failed module reported -> not the tirdad case.
        self.assertEqual('no', self._verdict(0, True, [], 0))

    def test_second_nontirdad_module_missing_is_not_tolerated(self) -> None:
        ## tirdad plus an unrelated module failed -> not sole -> not tolerated.
        self.assertEqual(
            'no', self._verdict(0, True, ['tirdad', 'some_other_mod'], 2))

    def test_other_failed_unit_is_not_tolerated(self) -> None:
        ## A non-modules-load unit also 'failed' -> the degrade is not SOLELY
        ## systemd-modules-load -> not tolerated.
        self.assertEqual(
            'no', self._verdict(0, True, ['tirdad'], 1, other_failed_unit=True))

    def test_rejected_count_mismatch_is_not_tolerated(self) -> None:
        ## Kernel key-rejection count must equal the failed-module count; a
        ## mismatch means some failure is not a key rejection -> not tolerated.
        self.assertEqual('no', self._verdict(0, True, ['tirdad'], 2))


class TestCiToleranceInjection(SystemcheckTestBase):
    """
    systemcheck_modules_load_ci_tolerance injects systemd-modules-load.service +
    its journal lines into the EXISTING ignore lists -- but ONLY in --ci and ONLY
    when the helper confirms the tirdad-under-Secure-Boot case.
    """

    def _inject(self, ci, sb_rc, modules_load_failed, failed_modules,
                rejected_count, other_failed_unit=False) -> str:
        return run_sourced(
            fragment_sources(),
            'systemcheck_modules_load_ci_tolerance; '
            'printf "IGN=[%s] JRN=[%s]\\n" '
            '"$systemcheck_ignore_failed_units_cli" '
            '"$systemcheck_journal_ignore_fixed_cli"',
            setup=_tirdad_env(sb_rc, modules_load_failed, failed_modules,
                              rejected_count, other_failed_unit, ci=ci),
        )

    def test_ci_tirdad_sb_injects_unit_and_journal(self) -> None:
        out = self._inject('true', 0, True, ['tirdad'], 1)
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
        out = self._inject('false', 0, True, ['tirdad'], 1)
        self.assertEqual('IGN=[] JRN=[]', out)

    def test_ci_jitterentropy_also_failed_does_not_inject(self) -> None:
        out = self._inject('true', 0, True, ['tirdad', 'jitterentropy_rng'], 2)
        self.assertEqual('IGN=[] JRN=[]', out)

    def test_ci_secure_boot_off_does_not_inject(self) -> None:
        out = self._inject('true', 1, True, ['tirdad'], 1)
        self.assertEqual('IGN=[] JRN=[]', out)


if __name__ == '__main__':
    unittest.main()
