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
