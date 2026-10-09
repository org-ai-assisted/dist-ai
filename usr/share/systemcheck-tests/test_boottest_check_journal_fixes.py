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
  * dm-smbios-reader-image-test --journal-ignore-fixed covers the mount-shared failure that
    every qcow2 leg hits, because no shared folder is attached to qemu.
"""

import os
import re
import shlex
import subprocess
import tempfile
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
        assert m is not None
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
        assert m is not None
        pat = m.group(1)
        line = ('localhost spice-vdagentd[1447]: '
                'Error getting active session: No data available')
        self.assertIsNotNone(re.search(pat, line, re.IGNORECASE),
                             'ignore pattern must match the real journal line')


class TestLogCheckerCriticalKernelStream(SystemcheckTestBase):
    """check_critical_logs force-shows kernel catastrophes read from the KERNEL-TRANSPORT
    journal stream that check_service_logs captures via journalctl --dmesg (the
    read-journalctl-kernel-logs-* leap actions). Because that stream is _TRANSPORT=kernel, a
    userspace process cannot forge a kernel line into it: the origin guarantee is STRUCTURAL
    (capture-time), so this function only matches the catastrophe tokens (Bad RAM / CPU-stall
    / nouveau, and a kernel ' BUG:'/oops). Tor's userspace 'Bug:' lines -- non-fatal asserts,
    fatal aborts, and log_backtrace() frames -- never reach this stream, so they are never
    force-shown here; that exclusion is enforced by the --dmesg capture, NOT by this grep
    (so it is not re-tested here). check_critical_logs greps the RAW kernel stream before
    sanitizing, so a '<' in an unrelated line cannot swallow a later catastrophe line; this
    suite canaries that. Drives the REAL function against a crafted kernel stream."""

    KERNEL_BUG = 'host kernel: BUG: unable to handle kernel NULL pointer dereference'
    BAD_RAM = 'host kernel: EDAC MC0: Bad RAM detected'
    CPU_STALL = 'host kernel: rcu: INFO: rcu_sched self-detected stall on CPU'
    ## A benign kernel line (journalctl --dmesg --output short): no catastrophe token.
    BENIGN = 'host kernel: usb 1-1: new high-speed USB device number 2 using xhci_hcd'
    ## A benign kernel line ending in an unclosed '<word' (e.g. a device string the kernel
    ## echoes). sanitize-string treats it as an open HTML tag and, parsing the whole blob,
    ## deletes everything to the next '>' (or EOF) -- so sanitize-before-grep would swallow a
    ## following catastrophe line. Verified to trigger the eating against sanitize-string.
    TAG_NOISE = 'host kernel: usb 1-1: Manufacturer: Acme <widget corp'

    def _run_check_critical(self, kernel_lines: list) -> str:
        """Run the REAL check_critical_logs against a crafted RAW KERNEL-transport stream
        (the journalctl_kernel.txt file check_service_logs writes). Mirrors log-checker's
        own shell options (errexit + nounset, NO pipefail -- the grep pipeline legitimately
        exits non-zero on no-match). stcatn/safe-rm/br_add_to_file are irrelevant to the
        classification under test, so they are stubbed; sanitize-string runs for real."""
        log_checker = os.path.join(self.dir, 'log-checker')
        with tempfile.TemporaryDirectory() as td:
            raw = os.path.join(td, 'journalctl_kernel.txt')
            with open(raw, 'w', encoding='utf-8') as handle:
                handle.write('\n'.join(kernel_lines) + '\n')
            ## log-checker is source-able: sourcing defines its functions without
            ## auto-running or enabling strict mode; the stubs follow so they shadow.
            script = (
                f'source {shlex.quote(log_checker)}\n'
                'set -o errexit\n'
                'set -o nounset\n'
                f'TMPDIR={shlex.quote(td)}\n'
                'stcatn() { cat -- "$@"; }\n'
                'safe-rm() { :; }\n'
                'check_critical_logs\n'
            )
            proc = subprocess.run(['bash', '-c', script], capture_output=True,
                                  text=True, timeout=30)
            self.assertEqual(proc.returncode, 0,
                             f'check_critical_logs crashed: {proc.stderr}')
            return proc.stdout

    def test_kernel_bug_critical(self) -> None:
        out = self._run_check_critical([self.KERNEL_BUG])
        self.assertIn('NULL pointer dereference', out,
                      'a real kernel BUG: must be critical')

    def test_control_byte_line_still_matched(self) -> None:
        ## The kernel reader uses journalctl --all, so a catastrophe printk carrying a
        ## control byte (e.g. a soft-lockup line echoing a prctl-set comm) arrives RAW, not
        ## blanked to '[blob data]'. check_critical_logs must still match it on the token.
        out = self._run_check_critical(
            ['host kernel: BUG: soft lockup - CPU#0 stuck for 22s! [\x01bad:42]'])
        self.assertIn('soft lockup', out,
                      'a catastrophe line with a control byte must still be critical')

    def test_nul_byte_does_not_hide_catastrophe(self) -> None:
        ## A NUL anywhere in the raw (--all) stream makes GNU grep treat it as binary and
        ## print 'binary file matches' instead of the line; '--text' must force line-wise
        ## matching so a real catastrophe is still emitted (the NUL itself is neutralized).
        out = self._run_check_critical([
            'host kernel: usb 1-1: Product: evil\x00descriptor',
            'host kernel: BUG: unable to handle kernel NULL pointer dereference',
        ])
        ## Without --text, grep emits no matching line to stdout (its 'Binary file matches'
        ## diagnostic goes to stderr), so the catastrophe would be absent here.
        self.assertIn('NULL pointer dereference', out,
                      'a NUL elsewhere in the stream must not hide a real catastrophe')

    def test_terminal_escape_neutralized(self) -> None:
        ## '--all' delivers raw bytes, so attacker-echoed kernel text can carry an ANSI/OSC
        ## escape. The line is still shown (catastrophe), but the ESC byte must be
        ## neutralized to '_' so it cannot inject a terminal escape sequence downstream.
        out = self._run_check_critical(
            ['host kernel: BUG: evil \x1b[2Jclear \x1b]0;hijack\x07 lockup'])
        self.assertIn('lockup', out, 'the catastrophe line must still be shown')
        self.assertNotIn('\x1b', out, 'ESC bytes must be neutralized, not passed through')
        self.assertNotIn('\x07', out, 'BEL bytes must be neutralized')

    def test_bug_on_macro_critical(self) -> None:
        ## The BUG()/BUG_ON() macro logs 'kernel BUG at <file>:<line>!' -- ' BUG ' with no
        ## colon. The word-boundary token must catch it (a plain ' BUG:' substring would
        ## miss this genuine kernel catastrophe).
        out = self._run_check_critical(
            ['host kernel: kernel BUG at mm/slub.c:4567!'])
        self.assertIn('kernel BUG at', out,
                      'a BUG_ON() (kernel BUG at ...) must be critical')

    def test_apparmor_bug_path_not_critical(self) -> None:
        ## A kernel-echoed, attacker-controlled path with a BARE 'BUG' token (an AppArmor
        ## denial for '/tmp/BUG') must NOT be force-shown: the token requires 'BUG:' or
        ## 'BUG at ', so a bare 'BUG' in a path does not trip a false critical. (A crafted
        ## path that embeds the literal ' BUG:' DOES still match -- an accepted residual
        ## false-positive; it can never HIDE a real catastrophe, which is the safe direction.)
        out = self._run_check_critical(
            ['host kernel: audit: apparmor="DENIED" operation="open" '
             'name="/tmp/BUG" pid=123 comm="probe"'])
        self.assertEqual(out.strip(), '',
                         'a bare BUG token in a kernel-echoed path must NOT be critical')

    def test_many_matches_all_shown(self) -> None:
        ## Many distinct catastrophe lines must ALL be shown -- there is no cap, precisely so
        ## an attacker who floods earlier-sorting forged lines cannot push a real catastrophe
        ## past a cut. HTML neutralization is a single-pass translation (not a per-line fork),
        ## so a large match set neither stalls nor truncates. (A pathological multi-MiB flood
        ## can still hit the GUI message dispatcher's own volume limit downstream -- a
        ## separate, pre-existing component, not this function's concern.)
        lines = ['host kernel: BUG: synthetic oops number %d' % i for i in range(250)]
        out = self._run_check_critical(lines)
        self.assertEqual(out.count('synthetic oops number'), 250,
                         'every matched catastrophe line must be shown, none dropped')
        ## Distinct-line guard: the total count alone passes even if one line were omitted
        ## and another duplicated (both among the unprobed indices). Assert EACH of the 250
        ## lines appears EXACTLY once -- the '<br />' delimiter makes each per-line substring
        ## unambiguous ('number 2<br />' cannot match inside 'number 12<br />'), so a count
        ## of 1 means present-and-not-duplicated and a count of 0/>=2 is caught.
        for i in range(250):
            self.assertEqual(out.count('synthetic oops number %d<br />' % i), 1,
                             'line %d must appear exactly once (not omitted or duplicated)' % i)

    def test_bad_ram_critical(self) -> None:
        out = self._run_check_critical([self.BAD_RAM])
        self.assertIn('Bad RAM detected', out)

    def test_cpu_stall_critical(self) -> None:
        out = self._run_check_critical([self.CPU_STALL])
        self.assertIn('self-detected stall on CPU', out)

    def test_benign_kernel_line_not_critical(self) -> None:
        ## A kernel line with no catastrophe token is not force-shown, so the critical tier
        ## stays quiet on a healthy boot.
        out = self._run_check_critical([self.BENIGN])
        self.assertEqual(out.strip(), '',
                         'a benign kernel line must NOT be critical')

    def test_mixed_only_catastrophes_shown(self) -> None:
        ## In a kernel stream mixing benign and catastrophe lines, only the catastrophes
        ## are force-shown.
        out = self._run_check_critical([self.BENIGN, self.KERNEL_BUG, self.BAD_RAM])
        self.assertIn('NULL pointer dereference', out)
        self.assertIn('Bad RAM detected', out)
        self.assertNotIn('new high-speed USB device', out,
                         'a benign kernel line must not ride along')

    def test_tag_noise_line_does_not_hide_bug(self) -> None:
        ## A benign kernel line with an unclosed '<' precedes a real kernel BUG. Because
        ## check_critical_logs greps the RAW stream BEFORE sanitizing, sanitize-string's
        ## whole-blob HTML parse cannot swallow the BUG line. (RED if sanitize ran first.)
        out = self._run_check_critical([self.TAG_NOISE, self.KERNEL_BUG])
        self.assertIn('NULL pointer dereference', out,
                      'a catastrophe line must survive a preceding unclosed-tag line')

    def test_catastrophe_with_tag_does_not_hide_next(self) -> None:
        ## Two catastrophe lines where the FIRST carries an unclosed '<' (a kernel-echoed
        ## process comm can inject one). HTML neutralization translates '<>&' to '_' in one
        ## pass, so the '<' cannot eat the SECOND catastrophe. (RED if the matches were run
        ## through sanitize-string as one HTML blob.)
        out = self._run_check_critical([
            'host kernel: BUG: soft lockup note <unclosed',
            'host kernel: EDAC MC0: Bad RAM detected',
        ])
        self.assertIn('Bad RAM detected', out,
                      'a later catastrophe must survive an earlier matched line with "<"')
        self.assertIn('BUG:', out, 'the first catastrophe is still shown')

    def test_debug_token_not_matched(self) -> None:
        ## The leading space in ' BUG:' avoids matching 'debug:'; a kernel line mentioning
        ## 'debug:' without a real ' BUG:' is not force-shown.
        out = self._run_check_critical(
            ['host kernel: audit: type=1400 debug: profile loaded'])
        self.assertEqual(out.strip(), '',
                         "'debug:' must not trip the ' BUG:' token")

    def test_kernel_bug_with_trailing_noise_stays_critical(self) -> None:
        ## A kernel BUG line stays critical regardless of trailing text in its message
        ## (e.g. a process comm echoed by the kernel): a real catastrophe is never hidden.
        line = ('host kernel: BUG: soft lockup - CPU#0 stuck for 22s! '
                '[comm_with_bug_text]')
        out = self._run_check_critical([line])
        self.assertIn('soft lockup', out,
                      'a kernel BUG: must stay critical despite trailing text')

    def test_hard_critical_with_trailing_phrase_stays_critical(self) -> None:
        ## A hard kernel token (Bad RAM / CPU-stall / nouveau) stays critical regardless of
        ## any trailing noise phrase on the same line.
        line = ('host kernel: EDAC MC0: Bad RAM detected -- '
                'some trailing noise')
        out = self._run_check_critical([line])
        self.assertIn('Bad RAM detected', out,
                      'a hard-critical token must survive a trailing phrase')


class TestMountSharedJournalIgnore(SystemcheckTestBase):
    """dm-smbios-reader-image-test ignores the mount-shared failure qemu guarantees.

    No shared folder is attached to the boot-test qemu invocation, so
    vm-config-dist's mount-shared cannot mount /mnt/shared. The script tolerates
    that ('|| true'); only mount's stderr reaches the journal, where
    check_journal reports it and fails every qcow2 leg.
    """

    def _ignore_string(self) -> str:
        ## dm-smbios-reader-image-test ships in this same repo, so resolve it relative to this
        ## test file rather than self.dir (which points into the systemcheck
        ## checkout).
        path = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', 'dm-smbios-reader-boot-tests', 'dm-smbios-reader-image-test'))
        text = read(path)
        m = re.search(
            r'--journal-ignore-fixed \\"(mount: [^"\\]*)\\"', text)
        self.assertIsNotNone(
            m, 'mount-shared --journal-ignore-fixed string not found')
        assert m is not None
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


class TestAnondateGetJournalIgnore(SystemcheckTestBase):
    """dm-smbios-reader-image-test ignores anondate-get's no-Tor cert-lifetime warnings.

    With no Tor reachable on the CI boot, anondate-get cannot read a Tor
    certificate lifetime and logs two fixed WARNING lines that check_journal
    greps as warnings and fails every leg -- the same no-tor condition the
    check_tor_* skips cover. Ignored on the consumer side, not silenced in the
    shipped anondate (which would hide a real Tor-cert problem on a Tor system).
    """

    def _ignore_strings(self) -> list:
        path = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', 'dm-smbios-reader-boot-tests', 'dm-smbios-reader-image-test'))
        text = read(path)
        found = re.findall(
            r'--journal-ignore-fixed \\"(anondate-get: WARNING: [^"\\]*)\\"',
            text)
        self.assertEqual(
            len(found), 2,
            'expected two anondate-get --journal-ignore-fixed strings')
        return found

    def test_matches_the_real_journal_lines(self) -> None:
        ## --journal-ignore-fixed is a FIXED STRING, so containment is the test;
        ## the anondate-get substring matches regardless of the source prefix
        ## (both the anondate and sdwdate-file-watcher journal copies carry it).
        real = [
            ('localhost anondate[2091]: ______ /usr/sbin/anondate-get: '
             'WARNING: Could not determine Tor certificate lifetime.'),
            ('localhost sdwdate-start-anondate-set-file-watcher[1845]: ______ '
             '/usr/sbin/anondate-get: WARNING: Tor certificate lifetime '
             'invalid according to Tor log. This information might be '
             'outdated.'),
        ]
        for ignore in self._ignore_strings():
            self.assertTrue(
                any(ignore in line for line in real),
                'ignore string %r must match a real journal line' % ignore)

    def test_unrelated_anondate_error_still_reported(self) -> None:
        ## The substrings name the specific no-Tor warnings, so a different
        ## anondate failure is still surfaced by check_journal.
        line = ('localhost anondate[2091]: /usr/sbin/anondate-get: ERROR: '
                'unexpected internal failure.')
        for ignore in self._ignore_strings():
            self.assertNotIn(
                ignore, line,
                'an unrelated anondate error must still be reported')


class TestCheckJournalReadFailure(ScenarioTestBase):
    """check_journal must surface a journal-READ failure, never read it as clean.

    The four 'leaprun log-checker-*' reads were each '|| true', so a failed read
    (privleap denial, broken journalctl, a corrupt journal) produced an EMPTY
    result that the critical/verbose printers then reported as a clean journal -- a
    false green. This-boot reads (the running boot always exists) now fail LOUD;
    last-boot reads stay lenient because 'journalctl --boot=-1' legitimately fails
    with "No journal boot entry found" when there is no previous boot.
    """

    def _run(self, leaprun_body: str):
        stubs = "leaprun() {\n%s\n}\n" % leaprun_body
        env = 'verbose=1\nsystemcheck_virtualizer_detected=none\n'
        result = run_check_scenario(self.check(SERVICES), 'check_journal',
                                    env_setup=env, stubs=stubs)
        ## A silent bash crash in check_journal emits nothing, so the clean-case
        ## tests below ('no warning', exit 0) would pass vacuously -- guard first
        ## (COVERAGE.md: assertCleanRun before asserting a clean result).
        self.assertCleanRun(result)
        return result

    def test_this_boot_read_failure_warns_and_sets_exit(self) -> None:
        ## Every read fails -> the this-boot failure must warn and set EXIT_CODE=1
        ## (the authoritative not-a-clean-result signals), never a silent exit 0.
        r = self._run('return 1')
        self.assertEqual(r.exit_code, '1',
                         'a journal-read failure must set EXIT_CODE=1')
        self.assertTrue(r.has_severity('warning'),
                        'a journal-read failure must emit a warning')
        self.assertIn('Could not read the systemd journal', r.joined())

    def test_read_failure_still_shows_captured_critical(self) -> None:
        ## A this-boot SERVICE read error must NOT suppress a critical line that was
        ## captured anyway (kernel line tee'd before the stream errored, or a
        ## successfully-read boot). The read-failure warning is ADDITIVE, not an
        ## early return. Fails on the old 'return 0' that dropped the finding.
        body = ('case "$1" in '
                '*service_logs_this_boot*) return 1 ;; '
                '*check_critical_logs*) printf "host kernel: Bad RAM detected\\n" ;; '
                '*) printf "" ;; esac')
        r = self._run(body)
        self.assertEqual(r.exit_code, '1')
        self.assertTrue(r.has_severity('warning'))
        self.assertIn('Could not read the systemd journal', r.joined())
        self.assertIn('Bad RAM detected', r.joined(),
                      'a captured critical must still be reported despite a '
                      'this-boot read failure')

    def test_this_boot_ok_last_boot_missing_does_not_warn(self) -> None:
        ## This-boot reads succeed (empty output = clean); only the last-boot
        ## service read fails (no previous boot). Benign -> no warning, exit 0.
        body = 'case "$1" in *last_boot*) return 1 ;; *) printf "" ;; esac'
        r = self._run(body)
        self.assertEqual(r.exit_code, '0',
                         'a benign no-previous-boot must not fail the check')
        self.assertNotIn('Could not read the systemd journal', r.joined(),
                         'no-previous-boot is benign and must not warn')

    def test_clean_reads_report_no_warning(self) -> None:
        ## All reads succeed with empty output = a genuinely clean journal.
        r = self._run('printf ""')
        self.assertEqual(r.exit_code, '0')
        self.assertNotIn('Could not read the systemd journal', r.joined())


if __name__ == '__main__':
    unittest.main()
