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

## Chipset: two working paths -- i440fx and the q35 port, both boot the Kicksecure desktop

VBox ships two chipsets: `piix3` (default, i440fx) and `ich9`. There is no upstream q35 machine
type. Two bring-up paths now exist, and BOTH boot the full Kicksecure LXQt desktop end to end:

### i440fx (`--chipset piix3`) -- the original OS path

- Legacy host bridge, NO PCIe ECAM/MMCONFIG, NO fw_cfg -> drove the CF8-only PciLib + the
  MCFG-suppress patch.
- Kicksecure LXQt desktop boots end-to-end through the coreboot/UefiPayload fork ROM.
- `ich9` (stock) also exposes real ECAM (McfgBase ~0xdc000000 = 4G - RAM-hole, 64 buses) + an ACPI
  MCFG, but stock ich9 is an i440fx-class bridge with ECAM bolted on: no Q35 MCH, no programmable
  PCIEXBAR, no SMM.

### q35 -- ported into VBox (`--chipset ich9` + the opt-in `Q35Chipset` device config)

VBox was extended (org-ai-assisted/virtualbox-coreboot@ai, `DevPciIch9.cpp`) with an opt-in
`Q35Chipset` mode (CFGM `VBoxInternal/Devices/ich9pci/0/Config/Q35Chipset 1`, default OFF so legacy
ich9 is byte-for-byte unchanged). It adds the two PCI devices coreboot `qemu-q35` needs:

- Q35 MCH host bridge at 00:00.0 (vendor 0x8086 dev 0x29c0). A config-access intercept treats a
  PCIEXBAR (reg 0x60/0x64) write like a real MCH: it relocates the ECAM/MMCONFIG MMIO window to the
  firmware-programmed base (coreboot programs 0xb0000000). So coreboot's `mainboard_machine_check`
  (PCIEXBAR readback) passes and ECAM lands where the q35 board expects it.
- ICH9 SMBus stub at 00:1f.3 (vendor 0x8086 dev 0x2930, SMBus class). Presence-only: coreboot
  i82801ix `enable_smbus()` die()s if no Intel device answers there; qemu-q35 issues no real SMBus
  transaction (no SPD read on the emulated board), so no I/O backend is needed.
- Needs `cMaxPciDevices=2` on the ich9pci DEVREG (host bridge + SMBus slots) -- an R0-visible change
  (see the ring-0 gotcha below).

coreboot q35 ROM: switch the board to `emulation/qemu-q35` and force NO_SMM
(`CONFIG_CPU_QEMU_X86_NO_SMM=y` -- VBox has no SMRAM/TSEG), keep the UefiPayload. Build script:
`/home/admin/deploy-q35-build.sh` -> `/home/admin/cb-q35-fork.rom`.

- VERIFIED (serial via `--uartmode file`): coreboot q35 boots bootblock -> romstage (past
  `enable_smbus`) -> ramstage ("QEMU Northbridge q35", PCI enum) -> ECAM window at
  `b0000000-bfffffff` -> writes ACPI/SMBIOS/coreboot tables -> loads UefiPayload -> "Jumping to boot
  code" (hands to edk2). The firmware bring-up works.
- REGRESSION VERIFIED: stock VBox EFI (no coreboot, `Q35Chipset` off) still boots the Kicksecure
  desktop (1280x800, ~8900 colours) with the rebuilt VBoxDD.so -- the default firmware is unbroken.
- MILESTONE 2 VERIFIED: the full Kicksecure LXQt desktop boots end to end through the q35 ROM
  (1024x768, 8815 colours, same as the i440fx path) after two further fixes:
  1. PMBASE (coreboot): the edk2 payload binds `AcpiTimerLib`, so `MicroSecondDelay` (used by
     CpuDxe MP-init's AP wait) polls the FADT ACPI PM-timer I/O port.  coreboot q35's i82801ix put
     PMBASE at 0x600 -> PM timer 0x608, but VBox's emulated ACPI PM block is fixed at 0x4000 and is
     NOT relocated by an ICH9 LPC PMBASE write (the i440fx/piix4 path IS relocated, which is why
     i440fx at 0xE408 worked).  edk2 then spun forever on a dead 0x608 timer -> BSP wedged right
     after `AP Vector ... 87000`.  Fix: i82801ix q35 `DEFAULT_PMBASE` 0x600 -> 0x4000
     (org-ai-assisted/coreboot@ai), so the FADT PM timer (0x4008) matches VBox's live timer.
  2. Build EDK2 as RELEASE, not DEBUG: a DEBUG payload halts at a benign `DXE_ASSERT` in
     `DxeTcgPhysicalPresenceLib` (no TPM present) at BdsDxe; RELEASE skips asserts and boots.
     `deploy-q35-build.sh` forces `CONFIG_EDK2_RELEASE`.
- The proper long-term fix for #1 is VBox-side (wire the ICH9 LPC PMBASE write to
  `acpiR3UpdatePmHandlers` so VBox relocates its ACPI PM block like the piix4 path); the coreboot
  PMBASE workaround is what is currently shipped and verified.

### Which to use

- Both work now: i440fx/piix3 (the original path) and q35/ich9 (`Q35Chipset` on) both boot the
  Kicksecure desktop. For the Dasharo port, a Dasharo q35 `vbox_uefi` config now has a working
  VBox target; a Dasharo i440fx config is the alternative (sovereign boot + setup menus are
  payload-level, so they port either way).
- Upstreamable VBox chipset work: the q35 port above (separable from the CorebootRom/SLP_EN patches;
  gated, legacy-safe).

### Ring-0 gotcha when testing a self-built VBox on a host with the packaged VBox

- A self-built VBox and the apt VBox share `/dev/vboxdrv`; supdrv caches ring-0 modules by name, so
  if a packaged-VBox VM is running it has already loaded the stock `VMMR0.r0`/`VBoxDDR0.r0` and the
  self-built VBox silently REUSES them (its R3 runs against the stock R0). An R0-visible change
  (e.g. `cMaxPciDevices`) then fails `VERR_INCOMPATIBLE_CONFIG` (`cMaxPciDevices 0x2 vs 0x1`).
- To load our modified R0: stop every packaged-VBox VM (savestate is reversible) AND build our own
  ring-0 set -- `kmk VMMR0` once, plus `VBoxDDR0` (the rebuild script `deploy-rebuild-vbox.sh` now
  builds `VBoxDD VBoxDDR0`). Then our full R0 loads.
- All VBox VMs on the test server run as ROOT: the vboxdrv open handler EPERMs non-root on the
  restricted `/dev/vboxdrv` node regardless of its 0666 mode.

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
