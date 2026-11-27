#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Importable module (no main); the shebang + executable bit follow the repo-wide
## .py convention and are inert when imported.

"""Single source of the VirtualBox DMI (SMBIOS) override device choice + keys.

The in-image GRUB reader (etc/grub.d/01_smbios-reader) appends the Type-1 system
serial's 'dm-cmdline=' remainder to the kernel line, but ONLY when the Type-1
manufacturer reads 'QEMU' -- so a VBox guest must advertise vendor=QEMU for the
reader to fire.

The DMI override DEVICE differs by firmware and this is NOT cosmetic: the BIOS path
builds SMBIOS via the 'pcbios' device, the EFI path via the 'efi' device. Setting
pcbios keys on an EFI VM force-instantiates the pcbios device, whose init then FAILS
querying BootDevice0 (VERR_CFGM_VALUE_NOT_FOUND), so power-on dies before DMI ever
reaches the guest. VERIFIED on VBox 7.2 (server integration): efi-device keys power an
EFI/efi-secureboot VM on cleanly; pcbios keys refuse it.

Imported by both dm-smbios-reader-vbox (keys off the harness firmware NAME) and
vbox-ctl-local (keys off the live IMachine firmwareType ENUM), so the device choice
and key template live in exactly one place.
"""

DMI_DEVICE_BIOS = 'pcbios'
DMI_DEVICE_EFI = 'efi'

## The reader fires only when the Type-1 manufacturer is this, and reads the kernel
## cmdline from the remainder after this serial prefix.
DMI_VENDOR = 'QEMU'
DM_CMDLINE_PREFIX = 'dm-cmdline='


def dmi_device(is_efi):
    """DMI override device name for the firmware: 'efi' for any EFI variant, else 'pcbios'."""
    return DMI_DEVICE_EFI if is_efi else DMI_DEVICE_BIOS


def dmi_keys(device):
    """(vendor_key, serial_key) extradata paths for the DMI override DEVICE."""
    base = 'VBoxInternal/Devices/%s/0/Config/' % device
    return base + 'DmiSystemVendor', base + 'DmiSystemSerial'
