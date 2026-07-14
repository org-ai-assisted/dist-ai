#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Bubblewrap-isolated scenario tests for check_secure_boot (check_secure_boot.bsh).

check_secure_boot is gated on the absolute-path directory /sys/firmware/efi and
sources three sibling scripts by absolute path, so it can only be steered inside
a mount namespace with those sibling functions stubbed:

  * The EFI guard `[ -d /sys/firmware/efi ]` is neutralized by overlaying
    /sys/firmware with an empty tmpfs and re-creating (or omitting) the efi
    subdirectory. /sys is a read-only sysfs, so the efi subdir cannot be mounted
    directly; it is mkdir'd inside the writable tmpfs from the stub preamble.
  * check_secure_boot_enabled (secure_boot_enabled_check.bsh) drives the top
    branch; its exit code (0/1/2) selects Enabled / Disabled / Unknown. Its
    stdout is also captured by the check, so the stub prints a line too.
  * dkms_mok_variables_set (shim-signed-mok-setup) sets dkms_mok_public_file,
    dkms_mok_private_file, shim_mok_public_file, shim_mok_private_file. The stub
    points them at /nonexistent so the key-presence checks take their simplest
    (Absent / No) branch and never reach `leaprun mokutil-test-key`.

Only check_secure_boot is exercised here; check_build_mok_keys is out of scope.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario_isolated,
)

FILE = "check_secure_boot.bsh"

## dkms_mok_variables_set is sourced from shim-signed-mok-setup; stub it to point
## every MOK key file at /nonexistent so `[ -f ... ]` is false everywhere. This
## makes the DKMS-keys branch "No" and the shim-keys branch "Absent", and keeps
## the check away from the leaprun/mokutil-test-key sub-branch.
DKMS_STUB = (
    "dkms_mok_variables_set() {\n"
    "  dkms_mok_public_file=/nonexistent\n"
    "  dkms_mok_private_file=/nonexistent\n"
    "  shim_mok_public_file=/nonexistent\n"
    "  shim_mok_private_file=/nonexistent\n"
    "}\n"
)

## Ensure `command -v mokutil` succeeds (mokutil_present='y') independent of the
## host, and neutralize leaprun in case any sub-branch reaches it.
MOKUTIL_STUB = "mokutil() { :; }\nleaprun() { return 1; }\n"

## For the EFI-present scenarios: /sys/firmware is overlaid with an empty tmpfs
## (hide_dirs), then the efi subdir is created inside it so `[ -d ... ]` is TRUE.
MKDIR_EFI = "mkdir -p /sys/firmware/efi\n"


class TestSecureBootIsolatedScenarios(ScenarioTestBase):

    def _run_efi_present(self, sbe_rc: int, sbe_stdout: str = "debug line"):
        """Run check_secure_boot with EFI present and check_secure_boot_enabled
        returning sbe_rc (0 Enabled, 1 Disabled, 2 Unknown)."""
        sbe_stub = (
            "check_secure_boot_enabled() {\n"
            f"  echo {sbe_stdout!r}\n"
            f"  return {sbe_rc}\n"
            "}\n"
        )
        stubs = MKDIR_EFI + sbe_stub + DKMS_STUB + MOKUTIL_STUB
        return run_check_scenario_isolated(
            self.check(FILE), "check_secure_boot",
            env_setup="verbose=1", stubs=stubs,
            hide_dirs=["/sys/firmware"])

    ## -- scenario 1: not booted in EFI mode -------------------------------
    def test_not_efi_reports_unavailable(self) -> None:
        r = run_check_scenario_isolated(
            self.check(FILE), "check_secure_boot",
            env_setup="verbose=1",
            stubs="check_secure_boot_enabled() { return 0; }\n"
                  + DKMS_STUB + MOKUTIL_STUB,
            hide_dirs=["/sys/firmware"])
        self.assertIn(">Unavailable<", r.joined())
        self.assertTrue(r.has_severity("info"))
        self.assertEqual(r.exit_code, "0")

    ## -- scenario 2: Secure Boot Enabled ----------------------------------
    def test_secure_boot_enabled(self) -> None:
        r = self._run_efi_present(0)
        self.assertIn(">Enabled<", r.joined())
        self.assertNotIn(">Disabled<", r.joined())
        self.assertTrue(r.has_severity("info"))
        self.assertEqual(r.exit_code, "0")

    ## -- scenario 3: Secure Boot Disabled ---------------------------------
    def test_secure_boot_disabled(self) -> None:
        r = self._run_efi_present(1)
        self.assertIn(">Disabled<", r.joined())
        self.assertNotIn(">Enabled<", r.joined())
        self.assertTrue(r.has_severity("info"))
        self.assertEqual(r.exit_code, "0")

    ## -- scenario 4: Secure Boot state Unknown ----------------------------
    def test_secure_boot_unknown(self) -> None:
        r = self._run_efi_present(2, sbe_stdout="mokutil exploded")
        self.assertIn(">Unknown<", r.joined())
        self.assertTrue(r.has_severity("info"))
        self.assertEqual(r.exit_code, "0")

    ## -- mokutil-installed verbose line (reachable via the stub) ----------
    def test_mokutil_installed_yes_line(self) -> None:
        ## With mokutil present (command -v mokutil succeeds) the verbose
        ## "mokutil installed ... Yes" status line is emitted.
        r = self._run_efi_present(0)
        self.assertIn(">Yes<", r.joined())


if __name__ == "__main__":
    unittest.main()
