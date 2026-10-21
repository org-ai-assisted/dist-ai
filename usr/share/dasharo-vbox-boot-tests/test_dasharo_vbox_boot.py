#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit tests for the pure helpers of the Dasharo-in-VBox boot driver: argument
## building and the serial / VBox.log assertions. These carry no VirtualBox
## dependency and run in the generic CI container; the boot orchestration itself
## is exercised only on a host with the patched VBox (the bash entrypoint SKIPs).

import importlib.machinery
import importlib.util
import os

import pytest

_HERE = os.path.dirname(os.path.realpath(__file__))


def _load_driver():
    ## The driver is an extensionless executable, so an explicit source loader
    ## is needed (spec_from_file_location cannot infer one without a .py suffix).
    path = os.path.join(_HERE, "dasharo-vbox-boot-test")
    loader = importlib.machinery.SourceFileLoader("dasharo_vbox_boot_test", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


drv = _load_driver()


def test_modifyvm_args_carry_the_five_tweaks():
    args = drv.build_modifyvm_args("vm0", 2345, 2048)
    assert args[0] == "modifyvm" and args[1] == "vm0"
    pairs = list(zip(args, args[1:]))
    assert ("--firmware", "efi") in pairs
    assert ("--chipset", "piix3") in pairs
    assert ("--hpet", "on") in pairs
    assert ("--memory", "2048") in pairs
    ## COM1 as a TCP server on the chosen port, so the test can send `reset -s`.
    assert "--uartmode1" in args
    assert args[args.index("--uartmode1") + 1] == "tcpserver"
    assert args[args.index("--uartmode1") + 2] == "2345"


def test_cpuid_override_reports_36_physical_bits():
    args = drv.cpuid_set_args("vm0")
    assert args == ["modifyvm", "vm0", "--cpuid-set",
                    "0x80000008", "0x00003024", "0x791ef257",
                    "0x0000400f", "0x00010000"]
    ## EAX low byte 0x24 = 36 physical address bits; this is the fix for the
    ## 48-bit identity-map page-table hang.
    assert drv.CPUID_PHYS36[1][-2:] == "24"


def test_extradata_keys_are_the_corebootrom_cfgm_keys():
    assert drv.EFIROM_KEY == "VBoxInternal/Devices/efi/0/Config/EfiRom"
    assert drv.COREBOOTROM_KEY == "VBoxInternal/Devices/efi/0/Config/CorebootRom"


def test_uefi_shell_detected_only_on_the_banner():
    assert drv.uefi_shell_reached("... UEFI Interactive Shell v2.2\nShell>\n")
    assert not drv.uefi_shell_reached("coreboot ramstage ...\nJumping to boot code\n")
    assert not drv.uefi_shell_reached("")


def test_s5_detected_only_on_a_real_power_down():
    assert drv.s5_shutdown_happened("00:00:34 ACPI: Entering S5 power state (power down)")
    ## coreboot's harmless boot-time arm-S0 write is NOT an S5 line.
    assert not drv.s5_shutdown_happened("ACPIDBG: PM1aCtl write u32=0x1401 slp_typ=0x5 slp_en=0")
    assert not drv.s5_shutdown_happened("")


def test_main_skips_without_a_rom():
    ## No --rom and no DASHARO_COREBOOT_ROM env -> SKIP (77), never a boot attempt.
    env_rom = os.environ.pop("DASHARO_COREBOOT_ROM", None)
    try:
        assert drv.main(["--rom", ""]) == drv.SKIP
    finally:
        if env_rom is not None:
            os.environ["DASHARO_COREBOOT_ROM"] = env_rom


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
