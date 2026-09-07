# Porting derivative-maker off live-build to dm-raw-to-iso

Enumeration of every live-build feature derivative-maker relies on, how
dm-raw-to-iso reimplements it, and the port steps. dracut-based only; porting the
initramfs to initramfs-tools is prohibited.

## How derivative-maker uses live-build today

Sole consumer: `build-steps.d/3600_convert-raw-to-iso` (`create-live-build-image`),
guarded by `dist_build_iso=true`. It builds a Kicksecure live-build fork (git
submodule) into a .deb in `1400_local-dependencies` (`live_build_installation`),
then drives `lb config/bootstrap/chroot/binary`. The rootfs is NOT bootstrapped by
live-build: the already-built raw VM rootfs is seeded into live-build's
`cache/bootstrap` (`help-steps/lb-seed-rootfs-cache`), so `lb bootstrap`/`lb chroot`
are no-ops and only `lb binary` does real work.

## Feature map (live-build -> dm-raw-to-iso)

| live-build feature | dm-raw-to-iso reimplementation |
|---|---|
| `lb binary` squashfs of the seeded rootfs | mount the raw's root partition (kpartx -r), copy rootfs out, `mksquashfs` -> `/live/filesystem.squashfs` |
| `--initramfs dracut-live` initrd | `chroot dracut --no-hostonly --add dmsquash-live` -> `/live/initrd.img` (force-add: hardened images suppress auto-inclusion) |
| kernel staging | copy `/boot/vmlinuz-*` (refuse a symlink) -> `/live/vmlinuz` |
| `--binary-image iso-hybrid` (BIOS+UEFI hybrid) | one `xorriso -as mkisofs` pass with `--grub2-mbr boot_hybrid.img` (BIOS USB) + `-b grub_eltorito` (BIOS CD) + `-eltorito-alt-boot -e efi.img` (UEFI CD) + `-efi-boot-part`/`-isohybrid-gpt-basdat` (UEFI USB GPT ESP) |
| `--bootloaders grub-pc` (BIOS) | `grub-mkimage -O i386-pc ... biosdisk iso9660` + `cdboot.img` -> `grub_eltorito`; modules copied to `/boot/grub/i386-pc` |
| `--bootloaders grub-efi` (EFI ESP) | build the FAT ESP (`mkfs.msdos`/`mmd`/`mcopy`) with grub EFI cores; per-arch platforms |
| UEFI Secure Boot (auto) | shim (`shim<arch>.efi.signed`) -> `BOOT<arch>.EFI`; distro-signed `gcd<arch>.efi.signed` -> `grub<arch>.efi`; monolithic+MokManager fallback |
| loopback.cfg | ship `/boot/grub/loopback.cfg` (sources grub.cfg); live entry carries `iso-scan/filename=${iso_path}` |
| `--bootappend-live` (boot=live, rd.live.*, root=live:CDLABEL=) | `--bootappend` + baked live cmdline; `--label` = CDLABEL = volume id (validated) |
| SMBIOS cmdline reader (config.cfg) + USER/SYSMAINT/UNRESTRICTED boot-role menu | `--grub-config-append <file>`: the caller (3600) supplies the reader + menu, so the tool ships no consumer-specific config |
| `--iso-volume` / `--iso-application` / `--iso-preparer` | `-volid` (+ xorriso `-A`/`-p`/`-publisher` when wired) |
| `--checksums md5` / `implantisomd5` (rd.live.check) | `implantisomd5` when present |
| reproducible efi.img (SOURCE_DATE_EPOCH) | `--source-date-epoch` drives squashfs times, FAT volid, mtimes, ISO date |
| Rock Ridge + Joliet | `-R -r -J -joliet-long` |
| disk rootfs -> live (fstab/crypttab) | neutralize `/etc/fstab` + `/etc/crypttab` (disk mounts break `local-fs.target` -> emergency mode) |

## Architectures (match live-build)

amd64 (BIOS + x64 EFI + ia32 EFI + Secure Boot), i386 (BIOS + ia32 EFI), arm64
(aa64 EFI, no BIOS), armhf (arm EFI, no BIOS). Same platform/efi-name mapping as
live-build's `efi-image`.

## Port steps

1. `dm-raw-to-iso` lives at `derivative-maker/help-steps/dm-raw-to-iso` (+ static
   config templates beside it). Tests + this doc stay in dist-ai.
2. Rewrite `3600_convert-raw-to-iso`: call `help-steps/dm-raw-to-iso` on the raw
   from `3200`, passing `--label "${dist_build_type_short}"`, `--arch`,
   `--serial-console` (when set), and `--grub-config-append` with the SMBIOS reader
   + boot-role menu (so `dm-boot-test`'s SMBIOS injection keeps working). No `lb`.
3. Delete: `live-build-data/`, `help-steps/lb-seed-rootfs-cache`,
   `help-steps/unmount-lb`, `live_build_installation` in `1400`, and any
   live-build-only build deps.
4. Remove ALL remaining live-build / `lb` mentions (comments, buildconfig, docs,
   FIXMEs) across the tree.
5. Do NOT remove the `live-build` submodule gitlink -- human-only (gitlink safety).

## Verification

Build a raw with `--flavor kicksecure-ci-tiny-do-not-use --target raw` (or reuse a
Kicksecure raw), run the ported `3600`, and boot the ISO across bios/efi/
efi-secureboot to a `login:` prompt via `dm-boot-test`.
