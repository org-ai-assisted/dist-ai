#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
RUNTIME AppArmor-confinement e2e for sdwdate's two privileged helpers.

The sibling text-scan (test_apparmor_confinement.py) proves the profile SOURCE
is right: enforce (not complain), minimal, stacked via 'Cx -> &'. It cannot
prove the KERNEL actually lands the helper in that stacked label at runtime --
and the two are not the same. A stacking transition that silently failed to
apply would leave the helper in the broad PARENT label (or unconfined), and that
failure is INVISIBLE to a 'zero denials + working clock' check: the parent
profile already grants sys_time and network, so nothing is denied and the clock
still changes. The only proof is the live label of the running helper.

This test reproduces the daemon's EXACT transition and reads the resulting label:
enter the daemon profile via aa-exec, then let an in-profile bash exec the helper
so the daemon profile's own '... rmCx -> &<helper>' rule fires -- identical to
what the running daemon does. (A bare 'aa-exec -p daemon -- helper' would NOT:
the onexec override would land the helper in the plain daemon label, not the
stack.) It asserts each helper runs under its OWN profile stacked with the
daemon, in ENFORCE -- not the daemon-alone label, not unconfined.

Needs a real enforcing-AppArmor host, root, aa-exec, and the three profiles
LOADED in enforce -- i.e. an installed+booted sdwdate, not a CI container or the
AppArmor-less dev VM. Skips (authorized) when that environment is absent.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest

DAEMON_PATH = '/usr/libexec/sdwdate/sdwdate'
SCLOCKADJ_PATH = '/usr/libexec/sdwdate/sclockadj'
URL_TO_UNIXTIME_PATH = '/usr/bin/url_to_unixtime'
PROFILES_FILE = '/sys/kernel/security/apparmor/profiles'

## sclockadj 1: sleep(1) then move the clock by ONE nanosecond -- a ~1s-alive,
## clock-neutral invocation whose only purpose is to be catchable.
SCLOCKADJ_ARGV = [SCLOCKADJ_PATH, '1']
## A real HTTP Date fetch over Tor's SOCKS port; keeps url_to_unixtime alive for
## the round-trip and also proves the ENFORCE profile is functionally complete.
U2U_ARGV = [URL_TO_UNIXTIME_PATH, '127.0.0.1', '9050',
            'https://check.torproject.org', '80', 'true']


def _loaded_profiles() -> dict:
    """Map profile name -> mode, from securityfs (empty if unreadable)."""
    out = {}
    try:
        with open(PROFILES_FILE, encoding='utf-8') as handle:
            for line in handle:
                m = re.match(r'^(\S.*?) \((\w+)\)\s*$', line)
                if m:
                    out[m.group(1)] = m.group(2)
    except OSError:
        pass
    return out


def _skip_reason() -> str:
    if os.geteuid() != 0:
        return 'needs root (reads other processes /proc/<pid>/attr/current)'
    if shutil.which('aa-exec') is None:
        return 'aa-exec not found (apparmor-utils not installed)'
    for binary in (SCLOCKADJ_PATH, URL_TO_UNIXTIME_PATH):
        if not os.path.exists(binary):
            return '%s not installed' % binary
    loaded = _loaded_profiles()
    ## Require the profiles merely LOADED -- the enforce-vs-complain mode is the
    ## thing under test (asserted below), not a precondition. Gating on 'enforce'
    ## here would turn a complain regression into a silent SKIP instead of a
    ## FAIL; the daemon profile being enforce is what marks a real sdwdate host.
    if loaded.get(DAEMON_PATH) != 'enforce':
        return ('daemon profile %s not loaded in enforce (is %r); not a running '
                'sdwdate host' % (DAEMON_PATH, loaded.get(DAEMON_PATH)))
    for prof in (SCLOCKADJ_PATH, URL_TO_UNIXTIME_PATH):
        if prof not in loaded:
            return ('profile %s not loaded; the package must be installed and '
                    'its profiles loaded' % prof)
    return ''


def _proc_label(pid: str):
    try:
        with open('/proc/%s/attr/current' % pid, encoding='utf-8') as handle:
            return handle.read().strip('\x00 \n')
    except OSError:
        return None


def _proc_exe(pid: str):
    try:
        return os.readlink('/proc/%s/exe' % pid)
    except OSError:
        return None


def _proc_cmdline(pid: str):
    try:
        with open('/proc/%s/cmdline' % pid, 'rb') as handle:
            return handle.read().replace(b'\x00', b' ').decode('utf-8', 'replace')
    except OSError:
        return ''


def _capture_label(exec_argv, matches, timeout_s=8.0):
    """Run exec_argv under the daemon's real transition and return the set of
    AppArmor labels of the matching process(es) seen while it is alive.

    exec_argv is run by an in-profile bash (second exec fires the daemon's Cx
    rule). `matches(exe, cmdline)` selects the target process by EXE (immune to
    the argv self-match: our own harness exe is bash/python, never the helper).
    """
    quoted = ' '.join("'%s'" % a.replace("'", "'\\''") for a in exec_argv)
    proc = subprocess.Popen(
        ['aa-exec', '-p', DAEMON_PATH, '--', '/bin/bash', '-c', quoted],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    labels = set()
    deadline = time.monotonic() + timeout_s
    try:
        while time.monotonic() < deadline:
            for pid in os.listdir('/proc'):
                if not pid.isdigit():
                    continue
                exe = _proc_exe(pid)
                if exe is None:
                    continue
                if matches(exe, _proc_cmdline(pid)):
                    lbl = _proc_label(pid)
                    if lbl:
                        labels.add(lbl)
            if labels and proc.poll() is not None:
                break
            time.sleep(0.01)
    finally:
        if proc.poll() is None:
            proc.terminate()
        stdout, _ = proc.communicate(timeout=10)
    return labels, proc.returncode, stdout.decode('utf-8', 'replace').strip()


def _assert_stacked_enforce(testcase, labels, helper_path):
    testcase.assertTrue(
        labels, 'no running process was caught under the transition -- cannot '
        'assert the label (the helper may have exited too fast)')
    testcase.assertEqual(
        len(labels), 1, 'helper seen under more than one label: %r' % (labels,))
    label = next(iter(labels))
    testcase.assertNotIn(
        'unconfined', label,
        '%s ran UNCONFINED (%r) -- the stacking transition did not apply'
        % (helper_path, label))
    ## Stacked label is '<helper>//&<daemon> (enforce)' (exec'd profile first).
    testcase.assertIn(
        helper_path, label,
        '%s is NOT in its own profile; label %r lacks its path (stack did not '
        'narrow it to its own set)' % (helper_path, label))
    testcase.assertIn(
        '//&', label,
        '%s label %r is not a STACK (no "//&"); it is a single profile, so the '
        'additive helper profile is not in effect' % (helper_path, label))
    testcase.assertIn(
        DAEMON_PATH, label,
        '%s label %r does not include the daemon profile in the stack'
        % (helper_path, label))
    testcase.assertIn(
        '(enforce)', label,
        '%s label %r is not in enforce mode -- complain is permissive, so the '
        'profile adds no real restriction' % (helper_path, label))


@unittest.skipIf(_skip_reason(),
                 ## style-ok: allow-skip: runtime AppArmor needs an enforcing
                 ## host + root + loaded profiles (absent in CI / the dev VM).
                 'runtime AppArmor confinement not testable here: '
                 + _skip_reason())
class SdwdateRuntimeConfinementTest(unittest.TestCase):
    def test_sclockadj_runs_under_own_stacked_enforce_profile(self) -> None:
        labels, _rc, _out = _capture_label(
            SCLOCKADJ_ARGV,
            lambda exe, _cmd: exe == SCLOCKADJ_PATH,
            timeout_s=6.0)
        _assert_stacked_enforce(self, labels, SCLOCKADJ_PATH)

    def test_url_to_unixtime_runs_confined_and_functional(self) -> None:
        labels, rc, out = _capture_label(
            U2U_ARGV,
            lambda exe, cmd: (os.path.basename(exe).startswith('python3')
                              and URL_TO_UNIXTIME_PATH in cmd),
            timeout_s=30.0)
        if rc != 0:
            ## style-ok: allow-skip: no working Tor time source on this host, so
            ## the fetch cannot run; the confinement cannot be exercised here.
            raise unittest.SkipTest(
                'url_to_unixtime fetch failed (rc=%s, out=%r) -- no working Tor '
                'time source; cannot exercise its confinement' % (rc, out))
        ## Functional proof: the ENFORCE profile is complete (fetch succeeded and
        ## returned a plausible 10-digit unixtime), so enforce did not break it.
        self.assertRegex(
            out, r'^\d{10}$',
            'url_to_unixtime did not return a unixtime under enforce (got %r); '
            'the enforce profile may be incomplete' % out)
        _assert_stacked_enforce(self, labels, URL_TO_UNIXTIME_PATH)


## Per-profile file-access canary: each profile must READ a trivial file in its
## own set, and be DENIED a trivial file outside it. The deny file MUST exist, so
## a refusal is EACCES (permission) not ENOENT (missing) -- an ENOENT would pass
## vacuously. `aa-exec -p <profile> -- python3 -I` enters the profile and runs the
## reader: the reader's exec is the profile ENTRY (onexec, needs no x rule), while
## its open() calls ARE mediated by the profile; `-I` keeps python to builtins so
## it starts even under the minimal sclockadj set. Testing the profile ALONE
## isolates its own ruleset; the runtime label additionally stacks the daemon
## (strictly tighter), proven by the label tests above. Note this ALSO catches
## complain: a complain profile permits the deny-read, so the EACCES assert fails.
_READER = '/usr/bin/python3'
_READ_PROBE = (
    'import sys\n'
    'try:\n'
    '    open(sys.argv[1], "rb").read(1)\n'
    '    print("OK")\n'
    'except PermissionError:\n'
    '    print("EACCES")\n'
    'except FileNotFoundError:\n'
    '    print("ENOENT")\n'
    'except OSError as exc:\n'
    '    print("ERR%d" % exc.errno)\n')

## Always-present allow files (grounded in the loaded profiles):
##   sclockadj:       reads only its own binary.
##   url_to_unixtime: its own binary + a CA cert (abstractions/ssl_certs).
##   daemon:          the translations yaml + sclockadj it execs + its replay file.
_SSL_CERT = '/etc/ssl/certs/ca-certificates.crt'
_DAEMON_TRANSLATIONS = '/usr/share/translations/sdwdate.yaml'
_DAEMON_REPLAY_FILE = '/var/lib/sdwdate/time-replay-protection-utc-unixtime'


def _read_under(profile, path):
    result = subprocess.run(
        ['aa-exec', '-p', profile, '--', _READER, '-I', '-c', _READ_PROBE, path],
        capture_output=True, text=True)
    return result.stdout.strip()


@unittest.skipIf(_skip_reason(),
                 ## style-ok: allow-skip: runtime AppArmor needs an enforcing
                 ## host + root + loaded profiles (absent in CI / the dev VM).
                 'runtime AppArmor file-access canary not testable here: '
                 + _skip_reason())
class SdwdateProfileFileAccessCanaryTest(unittest.TestCase):
    """Per-profile allow+deny LIST canary.

    Each profile must READ several files in its own set and be DENIED several
    files outside it. Every deny file MUST exist, so a refusal is EACCES
    (mediated) not ENOENT (vacuous). The deny targets are chosen from the actual
    profile rules: url_to_unixtime's abstraction denies @{HOME}/**, /tmp/** and
    @{PROC}/**; the daemon profile READS /etc/passwd (leaprun uid resolution --
    see SdwdateLeaprunPrivleapClientTest) but is denied /etc/shadow; the minimal
    sclockadj profile denies everything but its own binary. Catches a landing in
    the wrong (broader) label AND a complain profile (which would permit a deny).
    """

    def setUp(self) -> None:
        self._cleanup: list[str] = []
        ## Existing files OUTSIDE url_to_unixtime's set (so EACCES, not ENOENT).
        home_deny = self._make_temp(os.path.expanduser('~'), 'home')
        tmp_deny = self._make_temp('/tmp', 'tmp')
        daemon_allow = [_DAEMON_TRANSLATIONS, SCLOCKADJ_PATH]
        if os.path.exists(_DAEMON_REPLAY_FILE):
            daemon_allow.append(_DAEMON_REPLAY_FILE)
        self.canary = {
            SCLOCKADJ_PATH: {
                'allow': [SCLOCKADJ_PATH],
                'deny': ['/etc/hostname'],
            },
            URL_TO_UNIXTIME_PATH: {
                'allow': [URL_TO_UNIXTIME_PATH, _SSL_CERT],
                'deny': ['/proc/1/stat', home_deny, tmp_deny],
            },
            DAEMON_PATH: {
                ## passwd/nsswitch MUST be readable: leaprun (the privleap client
                ## the daemon drives) getpwuid()'s its own euid to find
                ## /run/privleapd/comm/<uid>; denying them makes leaprun abort
                ## "Could not connect to privleapd" -> no time sync. shadow stays
                ## denied, so the EACCES proof is still non-vacuous + enforcing.
                'allow': daemon_allow + ['/etc/passwd', '/etc/nsswitch.conf'],
                'deny': ['/etc/shadow'],
            },
        }

    def tearDown(self) -> None:
        for path in self._cleanup:
            try:
                os.unlink(path)
            except OSError:
                ## best-effort cleanup of a temp canary file; already-gone is fine.
                pass

    def _make_temp(self, directory: str, tag: str) -> str:
        handle, path = tempfile.mkstemp(
            dir=directory, prefix='sdwdate-canary-%s.' % tag)
        os.write(handle, b'x')
        os.close(handle)
        self._cleanup.append(path)
        return path

    def test_each_profile_allows_its_set_and_denies_outside(self) -> None:
        for profile, spec in self.canary.items():
            allow_existing = [p for p in spec['allow'] if os.path.exists(p)]
            self.assertTrue(
                allow_existing,
                '%s: no allow file present to test (package not installed?)'
                % profile)
            for allow in allow_existing:
                with self.subTest(profile=profile, allow=allow):
                    self.assertEqual(
                        _read_under(profile, allow), 'OK',
                        '%s CANNOT read %s, which is in its allowed set'
                        % (profile, allow))
            for deny in spec['deny']:
                with self.subTest(profile=profile, deny=deny):
                    self.assertTrue(
                        os.path.exists(deny),
                        'canary deny-file %s must EXIST so a refusal is EACCES '
                        'not ENOENT' % deny)
                    verdict = _read_under(profile, deny)
                    self.assertEqual(
                        verdict, 'EACCES',
                        '%s read of out-of-set %s returned %r; expected EACCES '
                        '(OK = NOT confined / complain mode; ENOENT = deny-file '
                        'missing = vacuous)' % (profile, deny, verdict))


## A7: leaprun (privleap client) must CONNECT under the enforced daemon profile.
_LEAPRUN = shutil.which('leaprun') or '/usr/bin/leaprun'
_PRIVLEAP_COMM_DIR = '/run/privleapd/comm'


def _leaprun_skip_reason() -> str:
    base = _skip_reason()
    if base:
        return base
    if not os.path.exists(_LEAPRUN):
        return 'leaprun not installed'
    if not os.path.isdir(_PRIVLEAP_COMM_DIR):
        return 'privleapd not running (no %s)' % _PRIVLEAP_COMM_DIR
    return ''


@unittest.skipIf(_leaprun_skip_reason(),
                 ## style-ok: allow-skip: needs an enforcing host + root + loaded
                 ## profiles + a running privleapd (absent in CI / the dev VM).
                 'leaprun-under-profile regression not testable here: '
                 + _leaprun_skip_reason())
class SdwdateLeaprunPrivleapClientTest(unittest.TestCase):
    """Regression: leaprun must CONNECT to privleapd under the enforced daemon
    profile. The daemon drives leaprun for every tor/anondate check; leaprun
    getpwuid()'s its own euid to locate /run/privleapd/comm/<uid>, so a
    passwd/nsswitch deny makes that lookup fail and leaprun aborts "Could not
    connect to privleapd" -- sdwdate then never syncs time and systemcheck's Tor
    check hangs (>300s). The deny is SILENT (no audit line), so only a live
    connect attempt catches it. FAILS on the old `deny /etc/passwd` profile."""

    def test_leaprun_connects_under_daemon_profile(self) -> None:
        ## --check validates authorization and returns a definitive AUTHORIZED /
        ## UNAUTHORIZED response WITHOUT running the action (deterministic, no side
        ## effect). aa-exec enters the daemon profile on the leaprun exec (onexec,
        ## no x rule needed), as the daemon's own 'leaprun rix' does; euid 0 ->
        ## connects to comm/0.
        result = subprocess.run(
            ['aa-exec', '-p', DAEMON_PATH, '--', _LEAPRUN, '--check',
             'tor-bootstrap-check'],
            capture_output=True, text=True, timeout=30)
        combined = result.stdout + result.stderr

        ## (a) aa-exec must actually have LAUNCHED leaprun under the profile. A
        ## failed exec (aa-exec error, binary missing/denied, python import denied)
        ## produces NEITHER the connect-fail string NOR a privleapd response, so a
        ## bare assertNotIn('Could not connect') would pass VACUOUSLY. 126/127 = an
        ## exec failure; the 'aa-exec:' text catches a profile-apply failure.
        self.assertNotIn(
            'aa-exec:', combined,
            'aa-exec could not launch leaprun under %s (got %r) -- the connection '
            'test never ran.' % (DAEMON_PATH, combined))
        self.assertNotIn(
            result.returncode, (126, 127),
            'leaprun failed to exec under %s (rc=%d; %r) -- the connection test '
            'never ran.' % (DAEMON_PATH, result.returncode, combined))

        ## (b) the connect-fail string must be ABSENT ...
        self.assertNotIn(
            'Could not connect to privleapd', combined,
            'leaprun could NOT connect to privleapd under the daemon profile '
            '(got %r); the profile likely denies /etc/passwd or /etc/nsswitch.conf, '
            "breaking leaprun's getpwuid() uid->comm-socket resolution." % combined)

        ## ... AND positive privleapd-response evidence must be PRESENT (exit status
        ## alone is NOT proof of a connection). The regression under test is the
        ## getpwuid()->comm-socket resolution, i.e. the CONNECT. EVERY string below
        ## is emitted by leaprun ONLY after it connected over comm/<uid> and read (or
        ## tried to read) a reply, so any of them proves that resolution worked. A
        ## protocol-error-after-connect is deliberately accepted: it still proves the
        ## connect, and rejecting it would false-RED the apparmor fix on an unrelated
        ## privleapd hiccup. In the healthy env the skip-guard requires, a --check run
        ## deterministically yields the AUTHORIZED/UNAUTHORIZED notice ('authorized to
        ## run action', from print_auth_notice); the rest are post-connect fallbacks
        ## (handle_response / unexpected_msg_error). The connect-FAIL path exits via
        ## generic_error('Could not connect ...') BEFORE any of these.
        connect_evidence = (
            'authorized to run action',
            'privleapd returned',
            "privleapd didn't return",
        )
        self.assertTrue(
            any(ev in combined for ev in connect_evidence),
            'no positive evidence leaprun reached privleapd under the daemon '
            'profile (got %r) -- a connection to comm/0 yields an AUTHORIZED/'
            'UNAUTHORIZED notice; its absence means leaprun never connected '
            '(possible vacuous pass).' % combined)


## A5: daemon -> privileged-child stacked signal-peer. The reapers kill with
## SIGKILL -- run_command (url_to_unixtime) at the 120s timeout, kill_sclockadj
## (sclockadj) on a new sync / shutdown -- via process.kill(). Each needs the
## daemon profile's 'signal send set=kill peer=<child>//&<daemon>' rule AND the
## child profile's matching 'signal receive set=kill' to hold at runtime against
## the STACKED label. A daemon-labeled Python starts the child via the Cx
## transition (child lands in the stacked label) and SIGKILLs it; an apparmor
## denial surfaces as os.kill -> PermissionError. Probing SIGKILL (not SIGTERM)
## matters: a SIGTERM probe passes even while the real reaper path is denied,
## since the code never sends SIGTERM.
_SIGNAL_PEER_PROBE = (
    'import os, signal, subprocess, sys, time\n'
    'argv = sys.argv[1:]\n'
    'proc = subprocess.Popen(\n'
    '    argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n'
    'time.sleep(0.5)\n'
    'if proc.poll() is not None:\n'
    '    print("GONE")\n'
    '    sys.exit(0)\n'
    'try:\n'
    '    os.kill(proc.pid, signal.SIGKILL)\n'
    '    print("SENT")\n'
    'except PermissionError:\n'
    '    print("EPERM")\n'
    'except ProcessLookupError:\n'
    '    print("ESRCH")\n'
    'finally:\n'
    '    try:\n'
    '        proc.wait(timeout=5)\n'
    '    except Exception:\n'
    '        proc.kill()\n')


@unittest.skipIf(_skip_reason(),
                 ## style-ok: allow-skip: runtime AppArmor needs an enforcing
                 ## host + root + loaded profiles (absent in CI / the dev VM).
                 'runtime AppArmor signal-peer test not testable here: '
                 + _skip_reason())
class SdwdateDaemonSignalPeerTest(unittest.TestCase):
    def _assert_reapable(self, tag, child_argv) -> None:
        result = subprocess.run(
            ['aa-exec', '-p', DAEMON_PATH, '--', _READER, '-I', '-c',
             _SIGNAL_PEER_PROBE] + child_argv,
            capture_output=True, text=True, timeout=60)
        lines = result.stdout.strip().splitlines()
        verdict = lines[-1] if lines else ''
        if verdict in ('GONE', 'ESRCH'):
            ## style-ok: allow-skip: the child exited before it could be
            ## signalled (e.g. no working Tor time source), so the signal rule
            ## cannot be exercised; never report that as a pass.
            raise unittest.SkipTest(
                '%s child not alive to signal (verdict=%r)' % (tag, verdict))
        self.assertEqual(
            verdict, 'SENT',
            'daemon -> %s SIGKILL was DENIED (verdict=%r): the daemon lacks the '
            'stacked signal-send set=kill peer rule (or the child lacks the '
            'matching receive), so the reaper cannot kill it' % (tag, verdict))

    def test_daemon_can_sigkill_url_to_unixtime(self) -> None:
        self._assert_reapable('url_to_unixtime', U2U_ARGV)

    def test_daemon_can_sigkill_sclockadj(self) -> None:
        self._assert_reapable('sclockadj', SCLOCKADJ_ARGV)


## A6: daemon own-profile ENFORCE functional smoke. Only a live enforce run
## catches an over-tight rule (the original class of bug: the missing leaprun
## rule, invisible to the source scan). Restart the real service -- which runs
## under the loaded enforce daemon profile -- drive one preparation+fetch cycle,
## and assert zero apparmor DENIED attributable to the daemon label over the run.
## Needs working Tor; an unreachable time source is an authorized skip.
_STATUS_FILE = '/run/sdwdate/status'


def _status_icon():
    try:
        with open(_STATUS_FILE, encoding='utf-8') as handle:
            return json.load(handle).get('icon', '')
    except (OSError, ValueError):
        return None


def _journal_cursor():
    """A journal cursor for the current tip. Cursors are monotonic sequence
    positions, so --after-cursor is immune to the clock stepping (which sdwdate
    DOES during a cycle) -- a wall-clock --since would drop post-step entries."""
    result = subprocess.run(
        ['journalctl', '--no-pager', '-n0', '--show-cursor'],
        capture_output=True, text=True)
    for line in result.stdout.splitlines():
        prefix = '-- cursor: '
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def _journal_after(cursor, extra_args):
    result = subprocess.run(
        ['journalctl', '--no-pager', '--after-cursor', cursor, '-o', 'cat']
        + extra_args,
        capture_output=True, text=True)
    return result.stdout


@unittest.skipIf(_skip_reason(),
                 ## style-ok: allow-skip: runtime AppArmor needs an enforcing
                 ## host + root + loaded profiles (absent in CI / the dev VM).
                 'runtime AppArmor enforce smoke not testable here: '
                 + _skip_reason())
class SdwdateDaemonEnforceSmokeTest(unittest.TestCase):
    def test_one_fetch_cycle_has_zero_daemon_denials(self) -> None:
        if shutil.which('systemctl') is None or shutil.which('journalctl') is None:
            ## style-ok: allow-skip: systemd tooling absent; cannot drive or
            ## observe a live service cycle on this host.
            raise unittest.SkipTest('systemctl/journalctl not available')
        cursor = _journal_cursor()
        if cursor is None:
            ## style-ok: allow-skip: no readable journal cursor; cannot observe
            ## the run clock-step-safely, so the enforce path cannot be judged.
            raise unittest.SkipTest('no journal cursor available')
        restart = subprocess.run(
            ['systemctl', 'restart', 'sdwdate'],
            capture_output=True, text=True)
        self.assertEqual(
            restart.returncode, 0,
            'could not restart sdwdate: %s' % restart.stderr.strip())

        ## Let preparation+fetch actually RUN: break early only on success, else
        ## keep waiting the full window. A transient error status appears within a
        ## second of restart; breaking on it would scan before the preparation
        ## retries (which is where an over-tight rule is hit) have logged anything.
        icon = None
        deadline = time.monotonic() + 150.0
        while time.monotonic() < deadline:
            icon = _status_icon()
            if icon == 'success':
                break
            time.sleep(2.0)

        ## Scan for daemon-label denials over the run FIRST, independent of the
        ## status. A denial is the exact failure A6 guards against (an over-tight
        ## enforce profile the source scan cannot catch), so it must FAIL -- never
        ## be masked by the skip below. The scan is cursor-anchored, not
        ## wall-clock: sdwdate STEPS the clock mid-cycle, which would move a
        ## post-step denial's timestamp before a --since marker and hide it.
        denials = [
            line for line in _journal_after(cursor, ['-k']).splitlines()
            if 'apparmor="DENIED"' in line and DAEMON_PATH in line]
        self.assertEqual(
            denials, [],
            'AppArmor DENIED the daemon label during a live enforce run -- the '
            'enforce profile is over-tight (an incomplete ruleset the source '
            'scan cannot catch):\n%s' % '\n'.join(denials[:20]))

        ## Zero denials is the core guarantee. Requiring a successful FETCH would
        ## make the test flaky (a full fetch+set over Tor often exceeds the
        ## window), so instead require only EVIDENCE the daemon actually ran under
        ## the enforce profile: success, or any sdwdate unit log after the cursor
        ## (cursor-anchored, so a clock step cannot hide it). If it never ran, the
        ## zero-denial result is vacuous -> authorized skip.
        daemon_ran = (icon == 'success'
                      or bool(_journal_after(cursor, ['-u', 'sdwdate']).strip()))
        if not daemon_ran:
            ## style-ok: allow-skip: the daemon did not run a preparation cycle
            ## here (service/Tor unavailable), so the enforce path was not
            ## exercised; a zero-denial result would be vacuous, never a pass.
            raise unittest.SkipTest(
                'sdwdate did not run a preparation cycle (status icon=%r); the '
                'enforce path was not exercised' % icon)


if __name__ == '__main__':
    unittest.main()
