# Porting derivative-maker off live-build to dm-raw-to-iso

Enumeration of every live-build feature derivative-maker relies on, how
dm-raw-to-iso reimplements it, and the port steps. dracut-based only; porting the
initramfs to initramfs-tools is prohibited.

## How derivative-maker used live-build (before this port)

Sole consumer: `build-steps.d/3600_convert-raw-to-iso` (`create-live-build-image`),
guarded by `dist_build_iso=true`. It built a Kicksecure live-build fork (git
submodule) into a .deb in `1400_local-dependencies` (`live_build_installation`),
then drove `lb config/bootstrap/chroot/binary`. The rootfs was NOT bootstrapped by
live-build: the already-built raw VM rootfs was seeded into live-build's
`cache/bootstrap` (`help-steps/lb-seed-rootfs-cache`), so `lb bootstrap`/`lb chroot`
were no-ops and only `lb binary` did real work.

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
| USER/SYSMAINT/UNRESTRICTED boot-role menu + custom GRUB theme + memtest + kb-layout submenu + SMBIOS reader | `--grub-overlay <dir>` (menu/theme/fonts/kb_layouts staged into `/boot/grub`, `@APPEND_LIVE@` substituted with the base live cmdline) + `--live-overlay <dir>` (memtest binary, package manifest staged into `/live`): the caller (3600) supplies all consumer-specific menu + theme, so the tool ships none of its own |
| `--iso-volume` / `--iso-application` / `--iso-preparer` | `-volid` (+ xorriso `-A`/`-p`/`-publisher` when wired) |
| `--checksums md5` / `implantisomd5` (rd.live.check) | `implantisomd5` when present |
| reproducible efi.img (SOURCE_DATE_EPOCH) | `--source-date-epoch` drives squashfs times, FAT volid, mtimes, ISO date |
| Rock Ridge + Joliet | `-R -r -J -joliet-long` |
| disk rootfs -> live (fstab/crypttab) | neutralize `/etc/fstab` + `/etc/crypttab` (disk mounts break `local-fs.target` -> emergency mode) |

## Architectures (match live-build)

amd64 (BIOS + x64 EFI + ia32 EFI + Secure Boot), i386 (BIOS + ia32 EFI), arm64
(aa64 EFI, no BIOS), armhf (arm EFI, no BIOS). Same platform/efi-name mapping as
live-build's `efi-image`.

## Port steps (DONE -- feature-preserving)

The port keeps EVERY feature the live-build ISO shipped; the generic tool was
extended (not the ISO downgraded) to express them:

1. `dm-raw-to-iso` (at `derivative-maker/help-steps/dm-raw-to-iso`, static config
   templates beside it) gained `--grub-overlay <dir>` (copies a consumer
   `/boot/grub` tree -- menu, theme, fonts, kb_layouts -- on top of the baseline,
   substituting `@APPEND_LIVE@`) and `--live-overlay <dir>` (copies extra `/live`
   files). It also pins all staged mtimes to `SOURCE_DATE_EPOCH`. Tests + this doc
   stay in dist-ai.
2. The custom GRUB menu + theme moved to `derivative-maker/iso-build-data/grub-config/`
   (config.cfg, a static `grub.cfg` menu with the three boot-role entries + Utilities
   submenu, theme.cfg, live-theme/, splash.svg, smbios-reader.cfg), de-`lb`-named and
   reworked off live-build's `@LINUX_LIVE@` expansion. The ISO extra package lists
   moved to `iso-build-data/package-list-{live,kicksecure}`.
3. `3600_convert-raw-to-iso` was rewritten to: mount the raw (chroot lifecycle),
   strip the ISO build markers, generate kb_layouts (`set-grub-keymap` + `44_kb_layout`)
   and the package manifest, rasterize `splash.png`, assemble the GRUB + `/live`
   overlays (SMBIOS reader + `${dm_smbios_extra}` placeholder only under
   `--smbios-reader`; serial only under `--serial-console-enable`), then call
   `dm-raw-to-iso` with `--raw/--output/--arch/--label/--source-date-epoch/--bootappend
   /--grub-overlay/--live-overlay`. No `lb`.
4. Deleted: `live-build-data/`, `help-steps/lb-seed-rootfs-cache`,
   `help-steps/unmount-lb`, `live-build_installation` in `1400`, the `unmount_lb`
   exception path in `help-steps/pre`, and the live-build-only build deps; added the
   host-side ISO deps (grub-*-bin/-signed, shim-signed, librsvg2-bin, memtest86+).
5. Remaining live-build / `lb` mentions removed (comments, buildconfig, docs). The
   `live-build` submodule gitlink is NOT removed -- human-only (gitlink safety).

## Verification

- Static (no root): `dm-iso-grub-menu-tests` guards the menu's boot-role entries +
  cmdlines + Utilities entries; `dm-grub-smbios-tests` guards the SMBIOS reader
  drift + opt-in gating; `dm-raw-to-iso-tests` arg tier covers the new options.
- Integration: `dm-raw-to-iso-tests` build+boot tier (opt-in: root + a raw image +
  qemu/OVMF) builds an ISO with sample overlays, asserts they land + `@APPEND_LIVE@`
  is substituted, and boots bios/efi/efi-secureboot.
- End to end: the derivative-maker `local-boot-test.yml` lane builds the ISO via the
  ported `3600` and boots it across bios/efi/efi-secureboot x user/sysmaint to a
  `login:` prompt (the sysmaint leg exercises the SYSMAINT boot-role path).
