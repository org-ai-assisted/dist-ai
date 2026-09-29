# dm-grub-menu-render-tests: interactive EFI/BIOS GRUB menu render test

Proves the platform-gated entries of the derivative-maker ISO GRUB menu
(`iso-build-data/grub-config/grub.cfg`) actually RENDER on real firmware -- the
observation the boot-test harness (`dm-image-boot-tests`) cannot make, because it
injects `set timeout=0` to autoboot past the menu and never enters a submenu.

## What it checks

The "UEFI Firmware Settings" (`fwsetup`) entry lives in the `Utilities...` submenu
and is gated on `[ "x${grub_platform}" = "xefi" ]`, so it MUST render under EFI and
MUST NOT render under BIOS. A dropped `x` on the RHS (`"efi"`) makes the test always
false and the entry never renders on EFI -- the exact bug this suite guards against.

## How it works (composes with the existing harness)

- `build-grub-test-image` -- `grub-mkrescue` a minimal hybrid ISO (BIOS + EFI) that
  sources the REAL grub-config verbatim (renamed `realgrub.cfg`) plus a thin wrapper
  that redirects console I/O to serial and holds the menu. Menu rendering depends
  only on the grub config + modules + theme, never the rootfs, so this needs no
  ~1h image build and `${grub_platform}` is still set by the real platform.
- `grub-menu-nav` -- gets qemu argv from the REAL `dm-qemu --emit-argv` (correct
  OVMF/SeaBIOS wiring per `--firmware`), spawns it under pexpect, enters the submenu
  via its GRUB hotkey, and reads to the submenu's last entry so the entry under test
  is deterministically in `child.before`.
- `dm-grub-menu-render-tests` -- entrypoint: gates the e2e runtime, builds the image
  once, runs the EFI (expect present) + BIOS (expect absent) legs.

## Run

    DERIVATIVE_MAKER_DIR=~/derivative-maker dm-grub-menu-render-tests

Or via the orchestrator (heavy lane): `dist-ai-tests-all --integration`.

Needs qemu-system-x86, ovmf, grub-mkrescue (grub-pc-bin + grub-efi-amd64-bin),
xorriso, mtools, python3-pexpect. Absent -> SKIP 77 (e2e-only runtime). Run in the
sandbox VM under TCG per the standing test rules.
