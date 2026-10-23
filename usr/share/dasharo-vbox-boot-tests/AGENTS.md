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

## Chipset: piix3 (i440fx) vs ich9 -- why i440fx is the base (SETTLED)

- VBox has only two chipsets: `piix3` (default, i440fx) and `ich9` (added in VBox 4.0). There is
  NO q35 machine type and none on the roadmap.
- `piix3` has NO PCIe ECAM/MMCONFIG and NO fw_cfg -> that is what drove the CF8-only PciLib + the
  MCFG-suppress patch.
- `ich9` DOES expose real ECAM + an ACPI MCFG table. VERIFIED two ways: VBox source
  (ConsoleImplConfigX86.cpp sets McfgBase/McfgLength for ChipsetType_ICH9; DevPciIch9.cpp maps the
  ECAM MMIO window per PCIe 7.2.2; DevACPI.cpp plants the MCFG table) AND empirically (boot
  `--chipset ich9`: /proc/iomem shows `dc000000-dfffffff : PCI ECAM 0000 [bus 00-3f]`, MCFG table
  present, kernel uses ECAM). Window: base ~0xdc000000 (= 4G - RAM-hole, config-dependent),
  length 0x4000000 = 64 buses (00-3f).
- BUT ich9 is NOT a real Q35: it is an i440fx-class host bridge with ECAM BOLTED ON. No Q35 MCH
  (host-bridge dev is `#if 0`'d out in VBox), no programmable PCIEXBAR (ECAM base is
  hypervisor-fixed), and NO SMM (VBox has never implemented it).
- So coreboot's `qemu-q35` board -- and Dasharo's q35 config (CONFIG_CPU_QEMU_X86_TSEG_SMM=y) --
  do NOT fit: they program Q35 MCH/PAM/TSEG, build+validate PCIEXBAR (halt on mismatch), and
  expect ECAM at 0xb0000000 / 256 buses plus SMM -- none present on VBox ich9. A q35 base would
  trade the 2 small i440fx patches (CF8 + MCFG-suppress) for a LARGER, fragile de-Q35 patch set.
- CONCLUSION: base on `qemu-i440fx` (VM on `piix3`). Move to `ich9` ONLY if ECAM is specifically
  needed, and then keep the i440fx board + ADD an ECAM window at VBox's actual MCFG base -- do NOT
  adopt the q35 board. For the Dasharo port: author a Dasharo i440fx `vbox_uefi` config (sovereign
  boot + the setup menus are payload-level, so they port), not the q35 config.

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
- CLEANUP -- GOP now uses the STOCK GraphicsOutputDxe PCI DriverBinding, not the earlier
  direct-publish + ConOut hacks. The direct-publish existed ONLY because PCI did not
  enumerate; CF8 fixed that, so stock `GraphicsOutputDxe` binds the vboxvga PCI handle and
  publishes the GOP as its CHILD (`dh -p GraphicsOutput` -> `Pci(0x2,0x0)/AcpiAdr(..)`,
  ConsoleOut). Reverted GraphicsOutput.c / PlatformConsole.c / PciHostBridgeLib markers to
  stock in the mrchromebox tree (kept CF8 DSC + coreboot bochs/fw_cfg). Net LESS code; the
  firmware shell + Setup menu still render.
- DONE -- VISIBLE LXQt DESKTOP renders through the firmware; the full port goal incl. graphics
  is met. VERIFIED on the patched ROM: `/proc/iomem` shows the vboxvga BAR with NO `Coreboot
  Framebuffer` child reservation; `modprobe vboxvideo` -> `/dev/dri/card0`; dmesg `[drm]
  Initialized vboxvideo 1.0.0 ... on minor 0` + `vboxvideodrmfb (fb0) is primary device` (no
  `-16`); a normal unedited-image boot renders the full Kicksecure LXQt desktop (panel, icons,
  Setup Wizard), stable across the whole screenshot window (~8800 colours/frame vs 2 when black).
  Root cause + fix mechanics below.
- FIX DETAIL (implemented in UefiPayloadPkg/BlSupportDxe, VERIFIED):
  * ROOT CAUSE (VERIFIED, not theorized -- two init=/bin/bash boots + /proc/iomem):
    `/proc/iomem` shows the vboxvga BAR `fc000000-fdffffff : 0000:00:02.0` with a child
    `fc000000-fc2fffff : Coreboot Framebuffer`. That child is a HARD reserved region the GUEST
    KERNEL creates from coreboot's `LB_TAG_FRAMEBUFFER` (its coreboot_table driver registers a
    `simple-framebuffer` platform device whose mem resource reserves the region). It sits INSIDE
    the BAR, so EVERY DRM driver fails `request_region` on the BAR with `-16 (EBUSY)`: `vboxvideo
    0000:00:02.0: probe ... failed with error -16`, same for `simpledrm`. No /dev/dri -> the
    Wayland/LXQt GUI cannot start -> black. efifb (legacy fbdev, no DRM) binds and gives the
    firmware console, which is why text renders but no desktop.
  * REFUTED (do NOT retry): it is NOT efifb holding the aperture. Booting with
    `video=efifb:off video=simplefb:off video=vesafb:off` REMOVES efifb/simplefb from
    /proc/iomem but the `Coreboot Framebuffer` reservation PERSISTS and `vboxvideo` STILL fails
    `-16`. So no OS display-driver / kernel-cmdline fb toggle frees the aperture -- the blocker is
    the coreboot-table simple-framebuffer reservation itself.
  * The coreboot table is NOT installed as a UEFI config table; both the payload (CbParseLib
    scans mem 0~4KB then high mem) and the guest kernel independently find it by signature scan.
    The payload NEEDS `LB_TAG_FRAMEBUFFER` (CbParseLib.c:569) to build its GOP, so simply not
    emitting it kills firmware graphics. coreboot does NOT itself reserve the fb (no reserved_ram/
    mmio for it) -- the reservation is purely the guest kernel's doing.
  * FIX (operator ruled: FIRMWARE ONLY, NO guest kernel-config change). A late UefiPayload DXE
    step (ReadyToBoot / EndOfDxe, after the GOP is built) retags the coreboot framebuffer entry
    so the guest kernel's scan skips it and falls back to the EVICTABLE EFI GOP fb (sysfb/aperture
    framework), which vboxvideo can evict -> binds -> /dev/dri -> desktop. Mechanics (all confirmed
    in CbParseLib + commonlib/coreboot_tables.h):
      - `GetParameterBase()` -> full table (follows CB_TAG_FORWARD); `FindCbTag(LB_TAG_FRAMEBUFFER
        == 0x0012)` -> the record.
      - set `record->tag = LB_TAG_UNUSED (0x0000)` (unknown/unused tags are iterated past).
      - recompute `Header->table_checksum = CbCheckSum16(entries, table_bytes)` THEN
        `Header->header_checksum` (table_checksum is a field INSIDE the header, so the header sum
        must be redone after). Both are validated (CbParseLib IsValidCbTable); a wrong sum makes
        the guest drop the WHOLE table (acceptable, but do it right).
      - Payload needs the tag at GOP-build time, so retag LATE, never remove it from coreboot.
    Rejected: guest kernel disable of CONFIG_GOOGLE_COREBOOT_TABLE/FRAMEBUFFER_COREBOOT (operator:
    no kernel-config changes -- it touches the shipped image).
    Verify: re-run the aperture probe -- /dev/dri/card0 appears and `vboxvideo ... probe` succeeds
    instead of `-16`.
  * Reproduce the fix (all under `/home/admin`, `dasharo-patches/` for the patch):
    `dasharo-patches/cbfb-retag-patch.sh` (idempotent source patch) -> `cbfb-rebuild.sh` (CLEAN
    payload rebuild -- the .inf adds a `BlParseLib` LibraryClass, so a stale partial build
    misreports) -> `aperture-test.sh` (DRM/vboxvideo check) / `os-desktop-test.sh` (desktop
    screenshots; brighten only needed for a near-black kernel console).
  * Working ROM `/home/admin/cb-uefi-gfx.rom` is CLEAN (0 GOPDBG/PCIDBG markers; GOP is stock).
    Archived: `/home/admin/dasharo-patches/cb-uefi-desktop-WORKING.rom`; pre-patch rollback at
    `/home/admin/cb-uefi-gfx.rom.prefbretag`.
