# dm-raw-to-iso

Convert a bootable raw disk image into a **highly boot-compatible hybrid Debian
ISO**, using only tools from packages.debian.org -- the same approach Debian's
`live-build` uses, reimplemented without live-build.

The tool is **`derivative-maker/help-steps/dm-raw-to-iso`** (its static GRUB config
templates live in `dm-raw-to-iso.d/` beside it); the tests and this doc stay in
dist-ai. This document is the reference for the exact command sequence it runs and
why, so the recipe is usable independently of the script.

## Key properties (learned)

- **dracut only.** The live initramfs is built with dracut; porting it to
  initramfs-tools is prohibited.
- **Force the live module:** `dracut --no-hostonly --add dmsquash-live`. Its check()
  is include-on-demand and a hardened image (Kicksecure security-misc) suppresses it;
  without it dracut FATALs on `root=live:CDLABEL=` and powers the guest off.
- **Neutralize the input's `/etc/fstab` + `/etc/crypttab`.** A disk rootfs mounts its
  own partitions there (root-by-UUID, `/boot/efi`, swap) -- none exist in a live boot,
  so `local-fs.target` fails and the guest drops to emergency mode (no login).
- **Static config, never auto-generated:** the grub configs come from templates in
  `dm-raw-to-iso.d/` (copy + substitute `@TIMEOUT@` / `@APPEND_LIVE@`).
- **Architectures:** amd64, i386, arm64, armhf -- the same set as live-build.
- **No `/boot` vs `/live` duplication:** kernel/initrd/squashfs only under `/live`;
  `/boot/grub` holds only grub config + images.
- **Fast iteration:** reuse an existing bootable raw (e.g. a built Kicksecure raw in
  `binary_mnt`) as the fixed input and rebuild only the ISO + boot legs -- no full dm
  image rebuild per change.

Verified against a real Kicksecure-CLI raw: the ISO boots to a `login:` prompt under
BIOS (and boots the kernel+systemd under UEFI and UEFI Secure Boot).

## What "highly boot-compatible" means

The output ISO boots in every one of these situations, matching what live-build
produces:

| # | Situation | Mechanism |
|---|-----------|-----------|
| 1 | Legacy BIOS, optical (CD/DVD) | El Torito no-emulation boot image (a GRUB `i386-pc` core) with a boot-info-table |
| 2 | Legacy BIOS, USB/HDD | GRUB2 hybrid MBR (`boot_hybrid.img`) written into the ISO's system area so a BIOS treats the stick as a bootable disk |
| 3 | UEFI, optical | El Torito **alternative** boot entry (platform EFI) pointing at a FAT EFI System Partition image `efi.img` holding `/EFI/BOOT/BOOT<arch>.EFI` |
| 4 | UEFI, USB/HDD | the same `efi.img` also exposed as a real GPT "basic data" partition, so a firmware ESP scan finds it on a block device |
| 5 | UEFI Secure Boot | the ESP holds the Microsoft-CA-signed **shim** as `BOOT<arch>.EFI`; shim chainloads the distro-signed `grub<arch>.efi`; GRUB's `shim_lock` verifier then requires a signed kernel |
| 6 | 32-bit UEFI (amd64) | an extra `/EFI/BOOT/BOOTIA32.EFI` in the same ESP, added when a signed grub is present (live-build parity) |
| 7 | Apple/Mac EFI | NOT provided: an Apple Partition Map only maps an HFS+ partition, and this ISO ships none, so `-isohybrid-apm-hfsplus` would emit nothing (and is dropped by the grub2-mbr system area on amd64) |
| 8 | Loop-mounted `.iso` file | `/boot/grub/loopback.cfg` (sources the main `grub.cfg`); the live entry carries `iso-scan/filename=${iso_path}` / `findiso=` so the initramfs finds the ISO file on the host partition |
| 9 | Any OS reading the filesystem | ISO9660 + Rock Ridge (`-R -r`) + Joliet (`-J -joliet-long`) |

Why not `grub-mkrescue`: it embeds a self-generated **unsigned** GRUB EFI core and
has no way to install the shim -> signed-grub chain, so it cannot produce a
Secure-Boot ISO. Debian's own release media use `xorriso` plus a hand-assembled
ESP, which is what this tool does.

## Input

A bootable raw disk image as produced by derivative-maker's
`build-steps.d/3200_create-raw-image` (grml-debootstrap `--vmefi`): a GPT disk
whose root filesystem carries a full Debian/Kicksecure install, including a
kernel in `/boot` and `dracut` + `dracut-live` installed. The tool copies the
rootfs out and never modifies the input image.

## Debian packages used

Arch-agnostic (host): `xorriso grub-common mtools dosfstools squashfs-tools
isomd5sum kpartx safe-rm`.

Arch-specific (host, for the target arch):
- amd64: `grub-pc-bin` (BIOS core + `boot_hybrid.img`), plus the signed EFI loaders
  `grub-efi-amd64-signed` + `shim-signed`.
- arm64: the signed EFI loaders `grub-efi-arm64-signed` + `shim-signed`. (No legacy
  BIOS on arm.)

The EFI side ships ONLY Debian's signed shim + signed grub -- no unsigned GRUB EFI
core is built, so `grub-efi-*-bin` is not needed. The signed shim boots UEFI whether
Secure Boot is on or off, so one loader covers plain UEFI and Secure Boot. The
SUPPORTED EFI platform for the arch (x64 on amd64, aa64 on arm64) is required: a
missing signed dependency there is a hard error. OPTIONAL platforms (32-bit UEFI)
auto-skip when their signed pair is absent.

The live initramfs is built by the **rootfs's own** `dracut` inside a chroot, so
the host needs no dracut; `dracut` + `dracut-live` must be present in the input
image.

## Command sequence

Let `RAW` be the input image, `ISO` the output, `LABEL` the ISO volume label
(must equal the `root=live:CDLABEL=<LABEL>` value), and a staging tree `binary/`.

### 1. Mount the raw and copy the rootfs out
```
kpartx -a -s -v RAW                      # map partitions to /dev/mapper/loopNpM
mount --read-only /dev/mapper/<root> mnt # the grml --vmefi root is the last partition
cp --archive --one-file-system mnt/. rootfs/
umount mnt ; kpartx -d -s RAW            # release the image; operate on the copy
```

### 2. Build the live (dracut-live) initramfs and stage the kernel
```
mount --bind {/dev,/dev/pts,/proc,/sys,/run} rootfs/...   # so dracut can run in the chroot
kver=<newest /boot/vmlinuz-*>
chroot rootfs dracut --no-hostonly --kver "$kver" --force --reproducible /boot/initrd.img-live "$kver"
cp rootfs/boot/vmlinuz-$kver          binary/live/vmlinuz
cp rootfs/boot/initrd.img-live        binary/live/initrd.img
umount {.../run,.../sys,.../proc,.../dev/pts,.../dev}
```
`--no-hostonly` makes a portable initramfs; the `dmsquash-live` module comes from
`dracut-live` in the rootfs and dracut adds it automatically.

### 3. Pack the rootfs into a reproducible squashfs
```
mksquashfs rootfs binary/live/filesystem.squashfs -noappend -comp xz \
   -wildcards -e "dev/*" "run/*" "tmp/*"
```
`/dev` is repopulated by devtmpfs at boot; `/run` and `/tmp` are runtime tmpfs.
Reproducible timestamps come from the exported `SOURCE_DATE_EPOCH` (mksquashfs honors
it); do NOT also pass `-all-time`/`-mkfs-time` -- mksquashfs rejects using both at once.

### 4. Boot-medium marker
```
printf '...' > binary/.disk/info      # the GRUB EFI cores 'search --file /.disk/info' for this
```

### 5. BIOS GRUB El Torito core (amd64 only)
```
grub-mkimage -d /usr/lib/grub/i386-pc -o core.img -O i386-pc --prefix=/boot/grub biosdisk iso9660
cat /usr/lib/grub/i386-pc/cdboot.img core.img > binary/boot/grub/grub_eltorito
cp -a /usr/lib/grub/i386-pc/*.mod *.lst binary/boot/grub/i386-pc/   # runtime modules
```
`cdboot.img` prepended makes the core an El Torito no-emulation image; `biosdisk`
+ `iso9660` are enough to reach `/boot/grub` on the medium, the rest load from
`i386-pc/`.

### 6. EFI System Partition: signed shim + signed grub (per platform of the arch)
For each `(platform:efi_name)` -- amd64: `x86_64-efi:x64` then `i386-efi:ia32`;
arm64: `arm64-efi:aa64` -- install ONLY the Debian-signed loaders into `EFI/boot/`
(uppercase `EFI` for TianoCore firmware). No unsigned GRUB EFI core is built.
```
cp --dereference /usr/lib/shim/shim<efi>.efi.signed      EFI/boot/boot<efi>.efi   # MS-signed shim (loaded first)
cp /usr/lib/grub/<platform>-signed/gcd<efi>.efi.signed   EFI/boot/grub<efi>.efi   # distro-signed grub
cp /usr/lib/shim/mm<efi>.efi.signed                      EFI/boot/mm<efi>.efi     # MokManager (if present)
```
The `gcd*` (removable-media) signed grub variant is used, not `grub*` (hard disk).
The signed shim boots UEFI with Secure Boot on OR off, so this one path is EFI and
Secure Boot. The supported platform (x64/aa64) errors if its signed pair is missing;
optional platforms (32-bit UEFI) auto-skip. No embedded configuration files: the signed grub carries
its own embedded config (Debian's, not built or controlled here), and it reads the
menu from the real `grub.cfg` on the medium.

```
# 6c. ESP-redirect grub.cfg (some firmware sets root to the ESP itself):
#     search --set=root --file /.disk/info ; set prefix=($root)/boot/grub ; configfile ($root)/boot/grub/grub.cfg
# 6d. pack a minimal FAT ESP:
mkfs.msdos -C binary/boot/grub/efi.img <blocks> -i <volid-from-SOURCE_DATE_EPOCH>
mmd   -i efi.img ::EFI ::EFI/boot ::boot ::boot/grub
mcopy -m -o -i efi.img EFI/boot/*.efi ::EFI/boot
mcopy -m -o -i efi.img esp-grub.cfg   ::boot/grub/grub.cfg
cp -a EFI binary/EFI                   # plain-file copy on the ISO too (USB/loopback reach)
```

### 7. Main grub.cfg + config.cfg + loopback.cfg
```
# binary/boot/grub/config.cfg : timeout, gfxterm/serial setup (sourced first)
# binary/boot/grub/grub.cfg   : sources config.cfg, one live menuentry:
#   linux  /live/vmlinuz boot=live components ... root=live:CDLABEL=<LABEL> \
#          rd.live.dir=live rd.live.squashimg=filesystem.squashfs iso-scan/filename=${iso_path}
#   initrd /live/initrd.img
echo "source /boot/grub/grub.cfg" > binary/boot/grub/loopback.cfg
```
`${iso_path}` stays literal for GRUB to expand at loop-boot (empty on direct boot).

### 8. Assemble the hybrid ISO in one xorriso pass
```
xorriso -as mkisofs -R -r -J -joliet-long -l -cache-inodes -iso-level 3 \
   -volid LABEL --modification-date=<SOURCE_DATE_EPOCH-derived> \
   --grub2-boot-info --grub2-mbr /usr/lib/grub/i386-pc/boot_hybrid.img \  # amd64 only
   -efi-boot-part --efi-boot-image \                                      # amd64 only
   -no-emul-boot -boot-load-size 4 -boot-info-table -b boot/grub/grub_eltorito \  # amd64 only
   -eltorito-alt-boot \                                                   # amd64 only
   -e boot/grub/efi.img -no-emul-boot \
   -isohybrid-gpt-basdat \
   -o ISO binary
implantisomd5 ISO                       # optional: enables GRUB/dracut rd.live.check
touch -d@$SOURCE_DATE_EPOCH ISO          # reproducibility
```
On arm64 the BIOS-only options are omitted (EFI El Torito + GPT ESP only). The GPT
partition for UEFI-USB comes from `-efi-boot-part`/`-isohybrid-gpt-basdat`; no
`-append_partition` and no isolinux `isohdpfx.bin` are used (this is the GRUB-only
path, not the syslinux path).

## Reproducibility

Pass `--source-date-epoch` (or set `SOURCE_DATE_EPOCH`); the squashfs timestamps,
the FAT volume id, all staged mtimes and the ISO modification date derive from it.
The **packaging** step is deterministic: given a fixed staging tree, the grub
cores, ESP, and xorriso output are byte-identical across runs.

Full byte-for-byte reproducibility of two complete `--raw` -> ISO runs is NOT
guaranteed by this tool alone: each run re-runs `dracut` on a fresh copy of the
rootfs, and an identical result additionally requires normalizing the rootfs
(debconf ownership, symlink mtimes, clearing `/run`) and a reproducible
initramfs -- the work derivative-maker's `3600` does around live-build. Do that
normalization in the caller if bit-identical output matters.

## Verification

- Structure: `xorriso -indev ISO -report_el_torito plain` (expect a BIOS + an EFI
  entry on amd64), and the presence of `EFI/boot/boot<arch>.efi`,
  `EFI/boot/grub<arch>.efi`, `boot/grub/loopback.cfg`.
- Boot: the dist-ai `dm-image-boot-tests` harness boots the ISO under QEMU across
  `bios`, `efi`, and `efi-secureboot` (OVMF with Microsoft keys), driven headless.
- Companion suite: `dm-raw-to-iso-tests` (run via `dist-ai-tests-all`).

## Relationship to derivative-maker

This is the reference for porting derivative-maker's `4310_convert-raw-to-iso`
off live-build. The port itself (editing derivative-maker) is a separate,
human-reviewed change; this tool and doc do not modify derivative-maker. A
consumer that needs extra GRUB config on the ISO (for example derivative-maker's
SMBIOS kernel-cmdline reader used by the boot-test harness) supplies it with
`--grub-config-append`, so this tool ships no consumer-specific config of its own.
