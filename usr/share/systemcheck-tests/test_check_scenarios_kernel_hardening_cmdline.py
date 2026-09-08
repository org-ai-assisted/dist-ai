#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Bubblewrap-isolated scenario tests for check_kernel_hardening_cmdline
(check_kernel_hardening_cmdline.bsh).

This check verifies that security-misc's kernel command-line hardening
(baked in by grub-mkconfig on a disk image, or scraped into the live boot
config on a live ISO) actually reached the RUNNING kernel, by reading
/proc/cmdline. /proc/cmdline is a pseudo-file the check reads by absolute
path, so it can only be steered inside a bubblewrap mount namespace: every
scenario here binds a fake file over /proc/cmdline via bind_files (proven to
work: a --ro-bind layered after --proc /proc successfully shadows the real
pseudo-file for the sandboxed process).

The list of asserted hardening tokens is NOT duplicated by hand here -- it is
parsed straight out of the real check function's `hardening_tokens=(...)`
bash array (see _load_tokens), so this suite can never silently drift from
what the check actually asserts.
"""

import os
import re
import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario_isolated,
    extract_bash_function,
)

FILE = 'check_kernel_hardening_cmdline.bsh'
FUNC = 'check_kernel_hardening_cmdline'

## A realistic prefix so the scenario cmdline looks like a real /proc/cmdline
## rather than just the bare hardening tokens.
CMDLINE_PREFIX = 'BOOT_IMAGE=/vmlinuz-6.1.0-amd64 root=/dev/mapper/dmroot ro'

_MISSING_RE = re.compile(
    r"Missing from the running kernel's <code>/proc/cmdline</code>: "
    r"<code>([^<]*)</code>")


def _load_tokens(path: str) -> list:
    """Parse the hardening_tokens=(...) bash array literal straight out of
    the real check function, so this suite exercises exactly what the check
    asserts and can never drift from it by hand-copying the list."""
    func_src = extract_bash_function(path, FUNC)
    match = re.search(r"hardening_tokens=\((.*?)\n\s*\)", func_src, re.DOTALL)
    if not match:
        raise LookupError(
            f"hardening_tokens array not found in {FUNC}() in {path}")
    tokens = re.findall(r"'([^']+)'", match.group(1))
    if not tokens:
        raise LookupError(f"hardening_tokens array in {path} parsed empty")
    return tokens


def _missing_list(joined: str) -> list:
    """Extract the space-separated token list from the check's 'Missing from
    ...: <code>...</code>' status message, or [] if the message is absent."""
    match = _MISSING_RE.search(joined)
    if not match:
        return []
    return match.group(1).split()


class TestKernelHardeningCmdlineIsolatedScenarios(ScenarioTestBase):
    HIDE = ['/usr/share/qubes']

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.tokens = _load_tokens(os.path.join(cls.dir, FILE))

    def _run(self, cmdline_content: str, verbose: int = 1):
        return run_check_scenario_isolated(
            self.check(FILE), FUNC,
            env_setup=f'verbose={verbose}',
            hide_dirs=self.HIDE,
            bind_files=[('/proc/cmdline', cmdline_content, False)])

    ## -- fully hardened cmdline: every token present -----------------------
    def test_all_tokens_present_ok(self) -> None:
        cmdline = CMDLINE_PREFIX + ' ' + ' '.join(self.tokens)
        r = self._run(cmdline)
        self.assertCleanRun(r)
        self.assertIn('>Present<', r.joined())
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertEqual(r.exit_code, '0')

    ## -- completely unhardened cmdline: this is the exact codex-reported gap
    def test_all_tokens_missing_reports_every_token_and_fails(self) -> None:
        r = self._run(CMDLINE_PREFIX)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('>Missing<', r.joined())
        missing = _missing_list(r.joined())
        self.assertEqual(set(missing), set(self.tokens))
        self.assertEqual(r.exit_code, '1')

    ## -- canary: EVERY asserted token, individually removed, is caught -----
    def test_each_token_individually_missing_is_caught(self) -> None:
        for missing_token in self.tokens:
            with self.subTest(token=missing_token):
                present = [t for t in self.tokens if t != missing_token]
                cmdline = CMDLINE_PREFIX + ' ' + ' '.join(present)
                r = self._run(cmdline)
                self.assertCleanRun(r)
                self.assertTrue(r.has_severity('warning'))
                self.assertEqual(r.exit_code, '1')
                missing = _missing_list(r.joined())
                ## Exactly the one removed token is reported missing -- no
                ## false positives against the tokens that ARE present, and
                ## no false negative on the one that is not.
                self.assertEqual(missing, [missing_token])

    ## -- a token present only as a substring of another does not count -----
    def test_substring_collision_does_not_count_as_present(self) -> None:
        ## 'amd_iommu=force_isolation' contains 'iommu=force' as a raw
        ## substring but is a DIFFERENT, distinct cmdline token. Assert that
        ## having only the former still reports 'iommu=force' missing (whole
        ## word / space-boundary matching, not substring matching).
        self.assertIn('iommu=force', self.tokens)
        self.assertIn('amd_iommu=force_isolation', self.tokens)
        present = [t for t in self.tokens if t != 'iommu=force']
        cmdline = CMDLINE_PREFIX + ' ' + ' '.join(present)
        r = self._run(cmdline)
        self.assertCleanRun(r)
        missing = _missing_list(r.joined())
        self.assertEqual(missing, ['iommu=force'])

    ## -- a later conflicting override wins on the real kernel, so it must --
    ## -- win here too (ai-review finding: presence-anywhere is not enough) --
    def test_later_conflicting_override_is_reported_missing(self) -> None:
        ## The Linux cmdline parser is last-occurrence-wins for a repeated
        ## 'key=value' parameter. A cmdline carrying security-misc's own
        ## 'iommu=force' AND a later 'iommu=pt' (e.g. appended by some other
        ## boot-config layer) actually boots with iommu=pt in effect -- the
        ## hardened value never took hold, even though 'iommu=force' still
        ## appears verbatim earlier in the string. A naive substring/word
        ## check would misreport this as hardened; assert it is caught.
        self.assertIn('iommu=force', self.tokens)
        present = [t for t in self.tokens if t != 'iommu=force']
        cmdline = (CMDLINE_PREFIX + ' iommu=force ' + ' '.join(present)
                   + ' iommu=pt')
        r = self._run(cmdline)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('warning'))
        missing = _missing_list(r.joined())
        self.assertEqual(missing, ['iommu=force'])
        self.assertEqual(r.exit_code, '1')

    ## -- a later occurrence of the SAME value is still fully hardened -------
    def test_later_repeated_same_value_still_present(self) -> None:
        ## The inverse case: the key repeats but the LAST value still matches
        ## the required hardened value -- must NOT be reported missing (an
        ## overly strict "must appear exactly once" rule would false-fail
        ## this legitimate case).
        self.assertIn('iommu=force', self.tokens)
        cmdline = (CMDLINE_PREFIX + ' iommu=force ' + ' '.join(self.tokens)
                   + ' iommu=force')
        r = self._run(cmdline)
        self.assertCleanRun(r)
        self.assertIn('>Present<', r.joined())
        self.assertEqual(r.exit_code, '0')

    ## -- Qubes: cmdline model differs, report info rather than fail --------
    def test_qubes_reports_info_not_failure(self) -> None:
        r = run_check_scenario_isolated(
            self.check(FILE), FUNC,
            env_setup='verbose=1',
            place=[('/usr/share/qubes/marker-vm', '', False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertIn('not applicable on Qubes', r.joined())
        self.assertEqual(r.exit_code, '0')

    ## -- /proc/cmdline empty/unavailable: info, not a false failure --------
    def test_empty_cmdline_reports_info_not_failure(self) -> None:
        r = self._run('', verbose=1)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity('info'))
        self.assertFalse(r.has_severity('warning'))
        self.assertIn('unavailable or empty', r.joined())
        self.assertEqual(r.exit_code, '0')

    ## -- verbose gating of the raw /proc/cmdline dump -----------------------
    def test_verbose_shows_raw_cmdline(self) -> None:
        cmdline = CMDLINE_PREFIX + ' ' + ' '.join(self.tokens)
        r = self._run(cmdline, verbose=1)
        self.assertIn(CMDLINE_PREFIX, r.joined())

    def test_non_verbose_hides_raw_cmdline(self) -> None:
        cmdline = CMDLINE_PREFIX + ' ' + ' '.join(self.tokens)
        r = self._run(cmdline, verbose=0)
        self.assertNotIn(CMDLINE_PREFIX, r.joined())


if __name__ == '__main__':
    unittest.main()
