#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Audit-mode verification for security-misc's remount-secure --check.

remount-secure hardens filesystem mount options (nosuid/nodev/noexec plus the
read-only hardening) per a built-in per-mountpoint level policy. Its --check
mode audits the EFFECTIVE options against that same policy read-only -- no
remount, no root, no run-once markers -- and exits nonzero on any deviation.
systemcheck's check_mount_options surfaces that verdict; this test exercises the
authority (the audit itself).

The REAL remount-secure script is driven with a stub `findmnt` on PATH (canned
option strings, or a forced failure) and NEWROOT pointed at a temp tree, so
per-mountpoint existence is deterministic for the NEWROOT-prefixed mountpoints
(/boot, /var/log, ...).

CANARY: a non-compliant option set MUST make --check go red (exit 1 plus a
DEVIATION line). Covered three ways so a weakened matcher cannot pass:
- FULL compliance (every intended option present) -> exit 0.
- NO compliance (none present) -> deviation.
- PARTIAL compliance (some present, some missing) -> deviation; an audit that
  passed on ANY single match (OR instead of AND) would wrongly go green here.
A forced findmnt failure must fail CLOSED (deviation), never silently pass.
"""

import glob
import os
import subprocess
import tempfile
import unittest

REPO = os.environ.get("SECURITY_MISC_REPO", "").strip()

## genmkfile ships every source file with a '#<pkg>-shared' suffix that the glob
## absorbs; on an installed system the suffix is stripped.
RELGLOB = "usr/bin/remount-secure*"

## Contains every intended hardening option for every mountpoint the level-3
## policy covers (nosuid, nodev, noexec); extra live options are allowed.
COMPLIANT_OPTIONS = "rw,nosuid,nodev,noexec,relatime"

## Carries none of them -> every audited mountpoint must deviate.
NONCOMPLIANT_OPTIONS = "rw,relatime"

## Carries SOME (nodev) but not all -> /boot (wants nosuid,nodev,noexec) must
## still deviate on the missing nosuid+noexec.
PARTIAL_OPTIONS = "rw,nodev,relatime"


def _resolve_remount_secure():
    if not REPO:
        ## style-ok: allow-skip: --check is a checkout-only feature not yet in a
        ## release; mirrors test_hardening_flags_no_drift's SECURITY_MISC_REPO gate.
        raise unittest.SkipTest("SECURITY_MISC_REPO unset")
    matches = sorted(glob.glob(os.path.join(REPO, RELGLOB)))
    if len(matches) > 1:
        raise AssertionError("ambiguous remount-secure match: %r" % matches)
    if not matches:
        ## REPO set but the script absent is a broken checkout, not optional.
        raise AssertionError("remount-secure missing under SECURITY_MISC_REPO=%s" % REPO)
    return matches[0]


class RemountSecureCheckAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.remount_secure = _resolve_remount_secure()

    def _run_check(self, newroot: str, findmnt_options: str, findmnt_fail: bool = False):
        """Run `remount-secure --check 3` with a stub findmnt (returning
        findmnt_options for every query, or failing when findmnt_fail), and
        NEWROOT prefixing the policy's mount folders onto the temp tree."""
        stub_dir = os.path.join(newroot, "_stub_bin")
        os.makedirs(stub_dir, exist_ok=True)
        stub_findmnt = os.path.join(stub_dir, "findmnt")
        if findmnt_fail:
            stub_body = "exit 1"
        else:
            stub_body = 'printf \'%%s\\n\' "%s"' % findmnt_options
        with open(stub_findmnt, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/bash\n%s\n" % stub_body)
        ## 0o700 (not 0o755): owner-executable only keeps the Bandit B103 gate quiet.
        os.chmod(stub_findmnt, 0o700)

        env = dict(os.environ)
        env["PATH"] = stub_dir + os.pathsep + env.get("PATH", "")
        env["NEWROOT"] = newroot
        return subprocess.run(
            [self.remount_secure, "--check", "3"],
            capture_output=True, text=True, env=env, timeout=30, check=False)

    def test_compliant_options_pass(self) -> None:
        with tempfile.TemporaryDirectory() as newroot:
            os.makedirs(os.path.join(newroot, "boot"))
            result = self._run_check(newroot, COMPLIANT_OPTIONS)
            self.assertEqual(
                result.returncode, 0,
                "compliant options must exit 0:\n%s%s"
                % (result.stdout, result.stderr))
            self.assertNotIn("DEVIATION:", result.stdout)

    def test_noncompliant_options_flag_deviation(self) -> None:
        with tempfile.TemporaryDirectory() as newroot:
            boot = os.path.join(newroot, "boot")
            os.makedirs(boot)
            result = self._run_check(newroot, NONCOMPLIANT_OPTIONS)
            self.assertEqual(
                result.returncode, 1,
                "non-compliant options must exit 1:\n%s%s"
                % (result.stdout, result.stderr))
            self.assertIn("DEVIATION: '%s' missing" % boot, result.stdout)

    def test_partial_compliance_flags_deviation(self) -> None:
        ## Some intended options present, some missing: the matcher must require
        ## ALL (AND), not any (OR). /boot wants nosuid,nodev,noexec.
        with tempfile.TemporaryDirectory() as newroot:
            boot = os.path.join(newroot, "boot")
            os.makedirs(boot)
            result = self._run_check(newroot, PARTIAL_OPTIONS)
            self.assertEqual(
                result.returncode, 1,
                "partial compliance must exit 1:\n%s%s"
                % (result.stdout, result.stderr))
            boot_line = next(
                (ln for ln in result.stdout.splitlines()
                 if ln.startswith("DEVIATION: '%s'" % boot)), "")
            self.assertIn("missing", boot_line)
            self.assertIn("nosuid", boot_line)
            self.assertIn("noexec", boot_line)

    def test_findmnt_failure_fails_closed(self) -> None:
        ## An existing mountpoint whose options cannot be read must be a
        ## deviation (fail closed), never a silent pass.
        with tempfile.TemporaryDirectory() as newroot:
            boot = os.path.join(newroot, "boot")
            os.makedirs(boot)
            result = self._run_check(newroot, COMPLIANT_OPTIONS, findmnt_fail=True)
            self.assertEqual(
                result.returncode, 1,
                "a findmnt read failure must exit 1:\n%s%s"
                % (result.stdout, result.stderr))
            self.assertIn("DEVIATION: '%s' mount options unreadable" % boot, result.stdout)

    def test_absent_mountpoint_reported_na_not_deviation(self) -> None:
        with tempfile.TemporaryDirectory() as newroot:
            os.makedirs(os.path.join(newroot, "boot"))
            ## deliberately do NOT create <newroot>/var/log
            var_log = os.path.join(newroot, "var/log")
            result = self._run_check(newroot, COMPLIANT_OPTIONS)
            self.assertIn("N/A: '%s'" % var_log, result.stdout)
            self.assertNotIn("DEVIATION: '%s'" % var_log, result.stdout)


if __name__ == '__main__':
    unittest.main()
