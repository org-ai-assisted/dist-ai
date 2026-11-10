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

The REAL remount-secure script is driven with a stub `findmnt` on PATH whose
output rows and exit code are controlled per scenario, so the audit's handling
of the kernel mount table is tested hermetically (no root, no real mounts).

CANARY: a non-compliant option set MUST make --check go red (exit 1 plus a
DEVIATION line). Covered so a weakened audit cannot pass:
- FULL compliance -> exit 0.
- NO / PARTIAL compliance -> deviation (the matcher needs ALL options, not any).
- STACKED mounts -> the EFFECTIVE (topmost) mount is findmnt's LAST row; a secure
  shadowed lower row must NOT mask an insecure effective mount.
- findmnt "no mount" (exit 1) -> N/A, never a deviation.
- findmnt unreadable (exit >= 2) -> fail CLOSED (deviation), never a silent pass.
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
COMPLIANT = "rw,nosuid,nodev,noexec,relatime"
## None of them -> every audited mountpoint deviates.
NONCOMPLIANT = "rw,relatime"
## Some (nodev) but not all -> /boot (wants nosuid,nodev,noexec) must deviate.
PARTIAL = "rw,nodev,relatime"


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
    remount_secure: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.remount_secure = _resolve_remount_secure()

    def _run_check(self, rows, findmnt_rc: int = 0):
        """Run `remount-secure --check 3` against a stub findmnt that, for every
        --target query, prints each option string in `rows` (one line per stacked
        mount, topmost LAST) and exits findmnt_rc."""
        with tempfile.TemporaryDirectory() as stub_dir:
            stub = os.path.join(stub_dir, "findmnt")
            body = "".join("printf '%%s\\n' \"%s\"\n" % r for r in rows)
            with open(stub, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/bash\n%sexit %d\n" % (body, findmnt_rc))
            ## 0o700 (not 0o755): owner-executable only keeps the Bandit B103 gate quiet.
            os.chmod(stub, 0o700)
            env = dict(os.environ)
            env["PATH"] = stub_dir + os.pathsep + env.get("PATH", "")
            return subprocess.run(
                [self.remount_secure, "--check", "3"],
                capture_output=True, text=True, env=env, timeout=30, check=False)

    def _deviation_lines(self, stdout):
        return [ln for ln in stdout.splitlines() if ln.startswith("DEVIATION:")]

    def test_compliant_options_pass(self) -> None:
        result = self._run_check([COMPLIANT])
        self.assertEqual(
            result.returncode, 0,
            "compliant options must exit 0:\n%s%s" % (result.stdout, result.stderr))
        self.assertNotIn("DEVIATION:", result.stdout)

    def test_noncompliant_options_flag_deviation(self) -> None:
        result = self._run_check([NONCOMPLIANT])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(self._deviation_lines(result.stdout))

    def test_partial_compliance_flags_deviation(self) -> None:
        ## Some intended options present, some missing: the matcher must require
        ## ALL (AND), not any (OR).
        result = self._run_check([PARTIAL])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        boot = next((ln for ln in self._deviation_lines(result.stdout)
                     if "'/boot'" in ln), "")
        self.assertIn("missing", boot)
        self.assertIn("nosuid", boot)
        self.assertIn("noexec", boot)

    def test_stacked_mount_uses_effective_topmost_row(self) -> None:
        ## A secure shadowed LOWER mount must not mask an insecure EFFECTIVE
        ## (topmost) mount -- findmnt lists the effective mount LAST.
        result = self._run_check([COMPLIANT, NONCOMPLIANT])
        self.assertEqual(
            result.returncode, 1,
            "effective (last) row is non-compliant; must deviate:\n%s%s"
            % (result.stdout, result.stderr))
        ## the flagged "have:" must be the effective (last) row, not the shadow.
        self.assertTrue(
            any("have: '%s'" % NONCOMPLIANT in ln
                for ln in self._deviation_lines(result.stdout)),
            "deviation must report the effective row's options:\n%s" % result.stdout)

    def test_absent_mount_reported_na_not_deviation(self) -> None:
        ## findmnt exit 1 = no mount for this path -> N/A, never a deviation.
        result = self._run_check([], findmnt_rc=1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("N/A:", result.stdout)
        self.assertNotIn("DEVIATION:", result.stdout)

    def test_unreadable_mount_fails_closed(self) -> None:
        ## findmnt exit >= 2 (e.g. missing/usage error) must fail CLOSED.
        result = self._run_check([], findmnt_rc=2)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(
            any("unreadable" in ln for ln in self._deviation_lines(result.stdout)),
            result.stdout)


if __name__ == '__main__':
    unittest.main()
