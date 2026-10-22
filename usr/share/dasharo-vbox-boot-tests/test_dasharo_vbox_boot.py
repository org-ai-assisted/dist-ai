#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Thin contract smoke test for the dasharo-vbox-boot-tests entrypoint.

The boot logic now lives in the shared dm-smbios-reader-vbox backend (the 'firmware'
subcommand), whose full pure-logic suite is dm-smbios-reader-vbox-tests. This guards
only the contract THIS lane depends on: the backend is present and exposes the
coreboot plan builder + the firmware verdict predicates, byte-shaped as the entrypoint
expects. A drift here (a renamed builder, a changed extradata key) would otherwise fail
only on a real OVH boot, far from the change.

Loaded via SourceFileLoader because the backend is an executable with no .py extension.
"""

import importlib.machinery
import importlib.util
from pathlib import Path

## usr/share/dasharo-vbox-boot-tests/ -> usr/share/dm-smbios-reader-boot-tests/
BACKEND = (Path(__file__).resolve().parent.parent
           / 'dm-smbios-reader-boot-tests' / 'dm-smbios-reader-vbox')


def _load():
    loader = importlib.machinery.SourceFileLoader('dm_vbox_backend', str(BACKEND))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_backend_is_present():
    assert BACKEND.is_file(), 'the dm-smbios-reader-vbox backend must ship beside this lane'
    M = _load()
    for name in ('build_coreboot_vm_plan', 'build_coreboot_rom_argv',
                 'uefi_shell_reached', 's5_shutdown_happened',
                 'run_firmware_boot_test'):
        assert hasattr(M, name), 'backend lost %r -- the lane entrypoint depends on it' % name


def test_coreboot_plan_contract():
    ## The exact shape the entrypoint relies on: Other_64 EFI VM, the coreboot ROM
    ## wired via the EfiRom/CorebootRom extradata, a COM1 server socket for serial.
    M = _load()
    plan = M.build_coreboot_vm_plan('dasharo-vbox-boot', '/home/admin/cb.rom',
                                    uart_socket='/run/cb.sock')
    flat = [tok for argv in plan for tok in argv]
    assert 'Other_64' in flat and 'efi' in flat
    assert 'VBoxInternal/Devices/efi/0/Config/EfiRom' in flat
    assert 'VBoxInternal/Devices/efi/0/Config/CorebootRom' in flat
    assert '/run/cb.sock' in flat


def test_firmware_predicates_contract():
    M = _load()
    assert M.uefi_shell_reached('UEFI Interactive Shell v2.2')
    assert M.s5_shutdown_happened('Entering S5 power state')
    assert not M.uefi_shell_reached('no shell')
