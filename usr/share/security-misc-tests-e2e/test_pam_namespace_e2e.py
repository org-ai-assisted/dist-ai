#!/usr/bin/python3 -Bsu

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
End-to-end test for security-misc pam_namespace polyinstantiation, on a REAL
booted systemd system (the VBox LXQt image lane, or any installed host).

Verifies the user-method-on-hardened-tmpfs design actually works at runtime:
  - the dedicated /run/security_misc tmpfs is mounted nosuid,nodev,noexec;
  - a logged-in account's /tmp, /dev/shm, /var/tmp are its own per-account
    instances with the expected mount options, and noexec is ENFORCED;
  - two accounts are isolated (neither sees the other's temp files);
  - the systemd --user manager shares the SAME /tmp instance as the login
    session (the no-split property that the 'user' method buys), and
    systemctl --user management still works.

DESTRUCTIVE + root-only: creates and removes throwaway accounts and toggles
linger. Runs as root on the target; an authorized skip off-target.
"""

import os
import subprocess
import unittest

HARDENED_TMPFS = '/run/pam-namespace'
NS_CONF = '/etc/security/namespace.d/30_security-misc.conf'
USERS = ('smnse2e1', 'smnse2e2')
HARDEN_OPTS = ('nosuid', 'nodev', 'noexec')
## Temporary passwordless-sudo grant for the Option-B elevation test; swept in
## teardown. 'zzz-' sorts last so it overrides, no dot so sudo reads it.
ELEV_SUDOERS = '/etc/sudoers.d/zzz-sm-ns-e2e'


def sh(cmd):
    return subprocess.run(['bash', '-c', cmd], capture_output=True, text=True)


def login_sh(user, cmd):
    """Run cmd in a real login PAM session (triggers pam_namespace)."""
    return sh('su -l %s -c %s' % (user, _q(cmd)))


def _q(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _uid(user):
    return sh('id -u %s' % user).stdout.strip()


class PamNamespaceE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            ## style-ok: allow-skip: e2e needs root on the target system
            raise unittest.SkipTest('needs root')
        if not os.path.isdir('/run/systemd/system'):
            ## style-ok: allow-skip: not a booted systemd system
            raise unittest.SkipTest('not a booted systemd system')
        if not os.path.exists(NS_CONF):
            ## style-ok: allow-skip: security-misc pam_namespace not installed
            raise unittest.SkipTest('pam_namespace config %s absent' % NS_CONF)
        ## Refuse to run if either throwaway name already exists: tearDownClass
        ## does 'userdel -rf', which would delete a REAL account and its home.
        ## Modify nothing in that case; only remove accounts we created.
        preexisting = [u for u in USERS if sh('id -u %s' % u).returncode == 0]
        if preexisting:
            raise RuntimeError(
                'refusing to run: test account(s) already exist and teardown '
                'would delete them: %s' % ', '.join(preexisting))
        cls._created = []
        for user in USERS:
            if sh('useradd --create-home --shell /bin/bash %s'
                  % user).returncode == 0:
                cls._created.append(user)

    @classmethod
    def tearDownClass(cls):
        if os.geteuid() != 0:
            return
        if os.path.exists(ELEV_SUDOERS):
            os.remove(ELEV_SUDOERS)
        for user in getattr(cls, '_created', []):
            sh('loginctl disable-linger %s 2>/dev/null' % user)
            sh('pkill -u %s 2>/dev/null; sleep 1; userdel -rf %s 2>/dev/null'
               % (user, user))

    def test_1_hardened_tmpfs_mounted(self):
        res = sh('findmnt -no FSTYPE,OPTIONS %s' % HARDENED_TMPFS)
        self.assertEqual(res.returncode, 0,
                         '%s is not a mount: %s' % (HARDENED_TMPFS, res.stderr))
        self.assertIn('tmpfs', res.stdout)
        for opt in HARDEN_OPTS:
            self.assertIn(opt, res.stdout,
                          '%s missing %s (got %s)'
                          % (HARDENED_TMPFS, opt, res.stdout.strip()))

    def test_2_pam_weaving(self):
        for stack in ('common-session', 'common-session-noninteractive'):
            res = sh('grep -q pam_namespace /etc/pam.d/%s' % stack)
            self.assertEqual(res.returncode, 0,
                             'pam_namespace not woven into %s' % stack)

    def test_3_per_account_instance_and_options(self):
        user = USERS[0]
        checks = {
            '/tmp': ('%s/tmp-inst/%s' % (HARDENED_TMPFS, user), HARDEN_OPTS),
            '/dev/shm': ('%s/shm-inst/%s' % (HARDENED_TMPFS, user), HARDEN_OPTS),
            '/var/tmp': ('/var/tmp/tmp-inst/%s' % user, ('nosuid', 'nodev')),
        }
        for polydir, (want_src, want_opts) in checks.items():
            res = login_sh(user, 'findmnt -no SOURCE,OPTIONS --target %s | head -1'
                           % polydir)
            out = res.stdout.strip()
            self.assertIn(want_src, out,
                          '%s is not the per-account instance: %s'
                          % (polydir, out))
            for opt in want_opts:
                self.assertIn(opt, out,
                              '%s missing %s: %s' % (polydir, opt, out))

    def test_4_noexec_enforced(self):
        for polydir in ('/tmp', '/dev/shm'):
            res = login_sh(USERS[0],
                           'p=%s/x.sh; printf "#!/bin/sh\\necho RAN\\n" > "$p"; '
                           'chmod +x "$p"; "$p"' % polydir)
            self.assertNotEqual(res.returncode, 0,
                                '%s/x.sh executed - noexec NOT enforced' % polydir)
            self.assertNotIn('RAN', res.stdout)

    def test_5_cross_account_isolation(self):
        login_sh(USERS[0], 'umask 077; echo secret > /tmp/isolation-probe')
        res = login_sh(USERS[1], 'test -e /tmp/isolation-probe && echo LEAK || echo isolated')
        self.assertIn('isolated', res.stdout,
                      '%s saw %s /tmp file - not isolated' % (USERS[1], USERS[0]))

    def test_6_systemd_user_shares_instance(self):
        """The whole point of the 'user' method: the systemd --user manager and
        the login session agree on /tmp (no split)."""
        user = USERS[0]
        uid = _uid(user)
        self.assertEqual(sh('loginctl enable-linger %s' % user).returncode, 0)
        ## wait for user@<uid>.service to come up
        up = sh('for i in $(seq 1 30); do '
                'systemctl is-active user@%s.service >/dev/null 2>&1 && exit 0; '
                'sleep 1; done; exit 1' % uid)
        self.assertEqual(up.returncode, 0, 'user@%s.service did not start' % uid)
        ## a file written in the login session's /tmp must be visible to the
        ## systemd --user manager's /tmp (same per-account instance). Check each
        ## probe command FIRST, so a failed write/systemd-run is reported as the
        ## command error it is, not misdiagnosed as a namespace split.
        wrote = login_sh(user, 'echo manager-visible > /tmp/split-check')
        self.assertEqual(wrote.returncode, 0,
                         'login write to /tmp/split-check failed: %s'
                         % wrote.stderr)
        seen = sh('systemd-run --user --machine %s@ --pipe --quiet --wait '
                  'cat /tmp/split-check' % user)
        self.assertEqual(seen.returncode, 0,
                         'systemd-run --user probe failed (rc=%d): %s'
                         % (seen.returncode, seen.stderr))
        self.assertIn('manager-visible', seen.stdout,
                      'systemd --user sees a DIFFERENT /tmp than the login '
                      'session (split not closed): %r' % seen.stdout)

    def test_7_systemctl_user_management_works(self):
        user = USERS[0]
        uid = _uid(user)
        sh('loginctl enable-linger %s' % user)
        sh('for i in $(seq 1 30); do '
           'systemctl is-active user@%s.service >/dev/null 2>&1 && break; '
           'sleep 1; done' % uid)
        run = sh('systemd-run --user --machine %s@ --unit=sm-e2e-probe '
                 '--quiet /bin/sleep 5' % user)
        self.assertEqual(run.returncode, 0,
                         'systemd-run --user failed: %s' % run.stderr)
        active = sh('systemctl --user --machine %s@ is-active sm-e2e-probe.service'
                    % user)
        self.assertEqual(active.stdout.strip(), 'active',
                         'transient --user unit not active: %s' % active.stdout)
        sh('systemctl --user --machine %s@ stop sm-e2e-probe.service' % user)

    def test_8_elevated_root_gets_system_tmp(self):
        """Option B: root reached by elevation (sudo) must see the SYSTEM /tmp,
        not the calling user's polyinstantiated instance. The pam-config runs a
        second, uid-0-gated `pam_namespace.so unmnt_only` that unmounts the
        inherited per-user binds in the elevated process's fresh namespace;
        without it an unprivileged user could prime a /tmp view that root then
        operates in (a categorical privilege-escalation surface). The documented
        accepted consequence is that a `echo x >/tmp/f; sudo cat /tmp/f` handoff
        no longer works -- which is exactly what this asserts."""
        user = USERS[0]
        with open(ELEV_SUDOERS, 'w', encoding='utf-8') as handle:
            handle.write('%s ALL=(root) NOPASSWD: ALL\n' % user)
        ## sudoers.d requires 0440; a looser mode makes sudo ignore the file.
        os.chmod(ELEV_SUDOERS, 0o440)
        try:
            ## The user writes a sentinel into its OWN polyinstantiated /tmp.
            wrote = login_sh(
                user, 'umask 077; echo elevated-secret > /tmp/elev-probe && echo OK')
            self.assertIn('OK', wrote.stdout,
                          'user write to its poly /tmp failed: %s' % wrote.stderr)
            ## Root reached by sudo FROM that user session must NOT see the file:
            ## it operates in the system /tmp. Check sudo itself worked first, so
            ## a broken sudo grant is reported as such, not as a false pass.
            probe = login_sh(
                user, 'sudo --non-interactive sh -c '
                "'id -u; cat /tmp/elev-probe 2>&1 || true'")
            self.assertEqual(probe.returncode, 0,
                             'sudo elevation failed: %s' % probe.stderr)
            self.assertTrue(probe.stdout.lstrip().startswith('0'),
                            'sudo did not elevate to uid 0: %r' % probe.stdout)
            self.assertNotIn('elevated-secret', probe.stdout,
                             'elevated root saw the caller user poly /tmp file - '
                             'Option B unmnt_only NOT effective: %r' % probe.stdout)
            ## The elevated root /tmp must resolve to the SYSTEM /tmp. Capture the
            ## system source OUTSIDE any login session (the test's own root
            ## context runs no pam_namespace), then require the elevated probe to
            ## resolve to that SAME source. Equality -- not merely "not the
            ## caller's tmp-inst" -- also rejects any OTHER per-account instance
            ## (e.g. a tmp-inst/root), which a caller-only exclusion would pass.
            system_src = sh('findmnt -no SOURCE --target /tmp')
            self.assertEqual(system_src.returncode, 0,
                             'could not read system /tmp source: %s'
                             % system_src.stderr)
            self.assertTrue(system_src.stdout.strip(),
                            'system /tmp source came back empty')
            ## No `| head` pipeline: head exits 0 even when findmnt fails, which
            ## would feed an EMPTY source into the comparison and pass vacuously.
            ## Require rc 0 and nonempty output before comparing.
            probe_src = login_sh(
                user, 'sudo --non-interactive findmnt -no SOURCE --target /tmp')
            self.assertEqual(probe_src.returncode, 0,
                             'elevated findmnt failed: %s' % probe_src.stderr)
            self.assertTrue(probe_src.stdout.strip(),
                            'elevated /tmp source came back empty')
            self.assertEqual(
                probe_src.stdout.strip(), system_src.stdout.strip(),
                'elevated root /tmp is not the system instance (got %r, system %r)'
                % (probe_src.stdout.strip(), system_src.stdout.strip()))
        finally:
            if os.path.exists(ELEV_SUDOERS):
                os.remove(ELEV_SUDOERS)


if __name__ == '__main__':
    unittest.main()
