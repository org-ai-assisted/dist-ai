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

import os
import re
import shutil
import subprocess
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


if __name__ == '__main__':
    unittest.main()
