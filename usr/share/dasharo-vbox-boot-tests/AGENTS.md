# dasharo-vbox firmware port (coreboot + UefiPayload in VirtualBox)

Boots a coreboot.rom (UefiPayloadPkg) inside a patched VirtualBox 7.2.20 so the
firmware renders GRAPHICALLY on the VBox framebuffer. The lane attaches no boot
media: it verifies the interactive UEFI shell on COM1 and a clean ACPI S5, and
captures the rendered framebuffer. Booting a full OS through the firmware is a
separate experiment, not what this lane checks. All work is on the OVH server.

## Patched VirtualBox

- `/home/admin/vbox-src/VirtualBox-7.2.20/out/linux.amd64/release/bin/VBoxManage`.
- Source build: run VM start as `--user root` (hardening needs `/dev/vboxdrv`;
  `--user admin` gets `VERR_VM_DRIVER_NOT_ACCESSIBLE`). Loaded distro vboxdrv
  matches, so concurrent VMs are fine. Hold `dm-vm-lock acquire --class work`.
- DevEFI `CorebootRom` patch: loads `EfiRom` as a coreboot image, not OVMF.
  DevACPI `SLP_EN` patch: makes `reset -s` (ACPI S5) actually power the VM off.

## VM config (proven working)

Other_64; `--firmware efi --chipset piix3 --hpet on --graphicscontroller vboxvga
--vram 32`; `--cpuid-set 0x80000008 0x00003024 0x791ef257 0x0000400f 0x00010000`
(36-bit phys-addr leaf the UefiPayload needs); extradata under
`VBoxInternal/Devices/efi/0/Config/`: `EfiRom` = ROM abspath, `CorebootRom` = 1.
`build_coreboot_vm_plan` in `../dm-smbios-reader-boot-tests/dm-smbios-reader-vbox`
emits exactly this.

## The three graphics patches (archived at `/home/admin/dasharo-patches/`)

coreboot drives VBox's VGA as bochs-dispi; the UefiPayload GOP then paints the
framebuffer. Each patch script is idempotent.

1. `bochs.c` (coreboot `src/drivers/emulation/qemu/`): add the VBox VGA PCI id
   (`80ee:beef`) as a `qemu_graph_ops` driver, and set the VBE data-port offset to
   base+1 (`0x1cf`, not QEMU's base+2 `0x1d0`). Build config: `LINEAR_FRAMEBUFFER`
   (not `VGA_TEXT_FRAMEBUFFER`), `QEMU_XRES=1024`/`YRES=768`.
   -- `dasharo-bochs-dataoff.py`, `dasharo-bochs-patch-build.sh`.
2. `UefiPayloadPkg/GraphicsOutputDxe/GraphicsOutput.c`: VBox's VGA is never
   connected to the GOP PCI DriverBinding (Start never runs). So publish the GOP
   DIRECTLY from `gEfiGraphicsInfoHobGuid` (the coreboot framebuffer HOB) onto a
   standalone handle in the entry point (`VBoxDirectPublishGop`).
   -- `gop-direct-publish.py`.
3. `UefiPayloadPkg/Library/PlatformBootManagerLib/PlatformConsole.c`: the standalone
   GOP is not a child of the PCI VGA, so `DetectAndPreparePlatformPciDevicePaths`
   never adds it to ConOut (black firmware). In `PlatformConsoleInit`, locate every
   GOP and `EfiBootManagerUpdateConsoleVariable(ConOut, ...)` -- makes the graphics
   console an active ConOut so firmware/boot-menu render on screen.
   -- `conout-patch.py`.

## Build

- Payload source lives in coreboot's own checkout:
  `coreboot/payloads/external/edk2/workspace/mrchromebox/` (repo mrchromebox/edk2,
  `origin/uefipayload_2608`), NOT `/home/admin/*-edk2`.
- `gop-rebuild.sh` forces the payload repackage (touch the source, rm
  `build/UEFIPAYLOAD.fd` + `build/coreboot.rom`, `make`), verifies the `.efi`
  recompiled, copies to `/home/admin/cb-uefi-gfx.rom`. Run it as a durable job:
  `server-exec --login --cmd 'sudo -iu admin -- bash /home/admin/gop-rebuild.sh'`
  (a durable job cannot be `--user admin` -- it cannot reach the staged script).
- EDK2 RELEASE strips `DEBUG()`, so trace via `SerialPortWrite` markers (`GOPDBG:*`
  in GraphicsOutput.c). A DEBUG payload build is a DEAD END (TcgPhysicalPresenceLib
  HII assert at boot). STRIP the GOPDBG markers before any upstream/land.

## Verify

- `dasharo-shellprobe.sh`: boot headless, drive COM1 (`dh -p GraphicsOutput`,
  `mode`, `connect -r`), screenshot. A working build shows handle `55: ConsoleOut
  SimpleTextOut ... GraphicsOutput` and the UEFI shell rendered on the framebuffer
  (not black). `screenshotpng` "Unsupported resolution 0x0" = framebuffer not up.
- Firmware boot is FAST (~seconds to the shell). The host MUST drain COM1 from
  power-on: the firmware floods the 16550, and an undrained host UART blocks the
  guest (THRE poll) and wedges the boot before the GOP comes up (0x0 forever).

## Status / known gaps

- DONE: graphics (GOP on the VBox linear framebuffer, firmware renders) + ACPI S5
  (`reset -s` powers off). The lane verifies both.
- DONE -- PCI enumeration FIXED + an OS BOOTS THROUGH the firmware. The earlier
  zero-PCI state: VBox's piix3/i440fx has NO ECAM (legacy 0xCF8/0xCFC only; coreboot
  `NO_ECAM_MMCONF_SUPPORT=y`), coreboot emits no `CB_TAG_RB_INFO`, so
  `PciHostBridgeGetRootBridges` fell back to `ScanForRootBridges` doing ECAM MMIO reads
  that always returned 0xFFFFFFFF -> no root bridge -> nothing enumerated (also why the
  GOP PCI binding never fired -- sidestepped with direct-GOP-publish). FIX (in the ROM
  now): DSC `PCIE_BASE_SUPPORT=FALSE` (-> `PciLib=BasePciLibCf8`) + `PciSegmentLib` ->
  `MdePkg/Library/BasePciSegmentLibPci/BasePciSegmentLibPci.inf` -- ALL PCI config
  access is then legacy CF8, which piix3 decodes. (An earlier CF8 attempt "hung" with
  no payload serial -- that was a STALE partial rebuild; a CLEAN recompile boots fine.
  Always force a clean payload rebuild on a DSC lib-mapping change.)
- With CF8 the firmware: renders a GRAPHICAL Setup menu (Boot Manager / System Config /
  Reboot -- richer than VBox's own EFI); enumerates PCI; finds the SATA disk; and BOOTS
  IT -- grub loads from the ESP and the Linux kernel starts (verified: BRIGHTEN the
  near-black OS frame ~6x and the kernel dmesg is there). The dasharo port's core goal
  -- an OS boots through the firmware -- is demonstrated.
- DONE -- Kicksecure FULLY BOOTS to a login prompt through the firmware. The dracut
  root-timeout was `ACPI: No LAPIC entries present`: coreboot's qemu-i440fx board reads
  the CPU count from QEMU `fw_cfg` (`.get_cpu_count = fw_cfg_max_cpus`), but VBox has NO
  fw_cfg ("firmware config interface not found"), so `fw_cfg_max_cpus()` returned 0 -> 0
  CPU devices -> the common MADT (`CONFIG_ACPI_COMMON_MADT_LAPIC=y`) emitted NO LAPIC ->
  the guest kernel had no APIC -> AHCI interrupts dead -> root I/O timed out. FIX (in the
  coreboot ROM now): `src/drivers/emulation/qemu/fw_cfg.c` `fw_cfg_max_cpus()` returns 1
  (the BSP) when `!fw_cfg_present()`. Boot the VM with `--ioapic on` so the MADT IOAPIC
  matches hardware. VERIFIED: coreboot logs `LAPIC 0x0 in XAPIC mode` + `IOAPIC: ... on
  fec00000`, and the guest serial (add `console=ttyS0,115200n8`) reaches
  `Welcome to Kicksecure (TM)! / localhost login:`.
- OPEN -- only the VISIBLE GUI on the framebuffer. The OS boots to a console login, but
  the on-screen framebuffer stays the dead simpledrm console (`simple-framebuffer: Unable
  to acquire aperture: -16` -- the vboxvga BAR 0xfc000000 is a claimed PCI resource). This
  is an OS display-driver matter (vboxvideo must bind the vboxvga PCI device and evict
  simpledrm), NOT a firmware blocker.
- RESUME (OVH, root, dm-vm-lock --class work):
  * VISIBLE GUI: check whether the Kicksecure kernel loads `vboxvideo` (drivers/gpu/drm/
    vboxvideo, PCI 80ee:beef); if not auto-bound, the GUI has no DRM device. Try booting
    with `fbcon=map:0` / a modeset cmdline, or confirm the GUI target started (serial
    `console=ttyS0` + drop `quiet loglevel=0`). Firmware-side option: reserve the GOP
    framebuffer in the EFI memory map so simpledrm is not evicted.
  * `/home/admin/cb-uefi-gfx.rom` is the CF8 build (boots an OS) but carries PCIDBG/
    GOPDBG SerialPortWrite debug markers + the instrument patches -- STRIP them before
    any land. ECAM pre-CF8 ROM archived at
    `/home/admin/dasharo-patches/cb-uefi-gfx-GRAPHICS-WORKING.rom`.
  * Test loop: `os-boot.sh` (screenshot boot), `interrupt-boot.sh` + `nav-bootmgr.sh`
    (reach the Setup/Boot menu via Down-spam then Up/Enter scancodes), `osboot-diag.sh`
    (shell map/bcfg). A near-black OS frame is usually the kernel console -- BRIGHTEN 6x.
