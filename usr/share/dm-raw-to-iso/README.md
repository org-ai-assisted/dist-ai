# dm-raw-to-iso

Convert a bootable raw disk image into a **highly boot-compatible hybrid Debian
ISO**, using only tools from packages.debian.org -- the same approach Debian's
`live-build` uses, reimplemented without live-build.

The tool is `usr/bin/dm-raw-to-iso`. This document is the reference for the exact
command sequence it runs and why, so the recipe is usable independently of the
script.

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
| 7 | Apple/Mac EFI | an Apple Partition Map entry (`-isohybrid-apm-hfsplus`) alongside the GPT |
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
- amd64: `grub-pc-bin` (BIOS core + `boot_hybrid.img`), `grub-efi-amd64-bin`,
  `grub-efi-ia32-bin`, and for Secure Boot `grub-efi-amd64-signed` + `shim-signed`.
- arm64: `grub-efi-arm64-bin`, and for Secure Boot `grub-efi-arm64-signed` +
  `shim-signed`. (No legacy BIOS on arm.)

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

### 6. EFI GRUB cores + FAT ESP (per platform of the arch)
For each `(platform:efi_name)` -- amd64: `x86_64-efi:x64` then `i386-efi:ia32`;
arm64: `arm64-efi:aa64`:
```
# 6a. memdisk skeleton config: find the medium, source the platform config on it
#     search --file --set=root /.disk/info ; set prefix=($root)/boot/grub ; source $prefix/<platform>/grub.cfg
# 6b. platform config on the ISO: insmod partition modules unless Secure-Boot lockdown, then main grub.cfg
grub-mkimage -O <platform> -m memdisk.tar -o boot<efi>.efi -p '(memdisk)/boot/grub' \
   search iso9660 configfile normal memdisk tar <part_*> fat
cp -a /usr/lib/grub/<platform>/*.mod binary/boot/grub/<platform>/   # runtime modules (grub-cpmodules equiv.)
# 6c. Secure Boot overlay into EFI/boot/ (uppercase EFI for TianoCore):
cp /usr/lib/grub/<platform>-signed/gcd<efi>.efi.signed   EFI/boot/grub<efi>.efi   # distro-signed grub
cp --dereference /usr/lib/shim/shim<efi>.efi.signed      EFI/boot/boot<efi>.efi   # MS-signed shim (loaded first)
#     shim-only fallback: signed shim + unsigned monolithic gcd<efi>.efi + mm<efi>.efi (MokManager)
```
The `gcd*` (removable-media) signed grub variant is used, not `grub*` (hard disk).

```
# 6d. ESP-redirect grub.cfg (some firmware sets root to the ESP itself):
#     search --set=root --file /.disk/info ; set prefix=($root)/boot/grub ; configfile ($root)/boot/grub/grub.cfg
# 6e. pack a minimal FAT ESP:
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
   -isohybrid-gpt-basdat -isohybrid-apm-hfsplus \
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

This is the reference for porting derivative-maker's `3600_convert-raw-to-iso`
off live-build. The port itself (editing derivative-maker) is a separate,
human-reviewed change; this tool and doc do not modify derivative-maker. A
consumer that needs extra GRUB config on the ISO (for example derivative-maker's
SMBIOS kernel-cmdline reader used by the boot-test harness) supplies it with
`--grub-config-append`, so this tool ships no consumer-specific config of its own.
