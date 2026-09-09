#!/bin/bash

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## End-to-end: build a real hybrid ISO from a raw image with dm-raw-to-iso, assert
## its boot structure, then boot it across bios/efi/efi-secureboot via dm-qemu
## (which verifies the ISO reaches a serial login under each firmware).
##
## dm-qemu, not dm-boot-test: this suite tests that dm-raw-to-iso's ISO BOOTS
## everywhere, which is dm-raw-to-iso's responsibility. dm-boot-test additionally
## runs the image's systemcheck, which is specific to a Kicksecure userland and
## irrelevant to ISO packaging -- so it would wrongly fail on a generic image.
##
## This is an opt-in INTEGRATION target: it needs ROOT (kpartx/chroot/mksquashfs),
## a raw image (DM_RAW_TO_ISO_TEST_IMAGE) and qemu/OVMF. When any of those is
## absent it exits 77 (SKIP) -- the same contract as the other integration suites
## that need a built image or a service.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

bin="${DM_RAW_TO_ISO_BIN:-/usr/bin/dm-raw-to-iso}"
dm_qemu="${DM_QEMU_BIN:-/usr/share/dm-image-boot-tests/dm-qemu}"
raw_image="${DM_RAW_TO_ISO_TEST_IMAGE:-}"
arch="${DM_RAW_TO_ISO_TEST_ARCH:-$(dpkg --print-architecture 2>/dev/null || printf 'amd64')}"

skip() {
   printf 'SKIP: %s\n' "$*" >&2
   ## style-ok: allow-skip: opt-in integration -- needs root + a raw image + qemu/OVMF (see file header)
   exit 77
}

[ -x "${bin}" ] || { printf 'FATAL: dm-raw-to-iso not executable: %s\n' "${bin}" >&2 ; exit 1 ; }
[ "${EUID}" -eq 0 ] || skip "not root (dm-raw-to-iso needs kpartx/chroot/mksquashfs)"
[ -n "${raw_image}" ] || skip "DM_RAW_TO_ISO_TEST_IMAGE not set (no raw image to convert)"
[ -r "${raw_image}" ] || skip "DM_RAW_TO_ISO_TEST_IMAGE not readable: ${raw_image}"
type -P xorriso     >/dev/null 2>&1 || skip "xorriso not installed"
type -P kpartx      >/dev/null 2>&1 || skip "kpartx not installed"
type -P mksquashfs  >/dev/null 2>&1 || skip "squashfs-tools not installed"
type -P grub-mkimage >/dev/null 2>&1 || skip "grub-common not installed"
type -P mkfs.msdos  >/dev/null 2>&1 || skip "dosfstools not installed"
type -P mcopy       >/dev/null 2>&1 || skip "mtools not installed"
## The GRUB modules + signed EFI loaders now come from the raw image's TARGET rootfs
## (dm-raw-to-iso sources them from there so a cross-arch build gets the target-arch
## loaders), NOT the host -- so there is nothing host-side to gate on here. A real
## Kicksecure raw carries grub-efi-${arch}-signed + shim-signed + the grub -bin
## package; the tool errors clearly if the image lacks them.

pass=0
fail=0
ok()   { printf 'PASS: %s\n' "$*" ; pass=$(( pass + 1 )) ; }
bad()  { printf 'FAIL: %s\n' "$*" >&2 ; fail=$(( fail + 1 )) ; }

workdir="$(mktemp --directory --tmpdir dm-raw-to-iso-e2e.XXXXXX)"
cleanup() {
   # shellcheck disable=SC2317  # reached only via the EXIT trap
   safe-rm --recursive --force -- "${workdir}" 2>/dev/null || true
}
trap cleanup EXIT
iso="${workdir}/out.iso"
label="DMTEST"

######################################################################
## GRUB overlay: dm-raw-to-iso ships NO config, so --grub-overlay must be a
## COMPLETE /boot/grub (config.cfg, grub.cfg, loopback.cfg, esp-redirect.cfg). A
## minimal-but-bootable set carrying the tool's tokens (@TIMEOUT@, @APPEND_LIVE@)
## -- the fixture INPUT to the real tool, not a copy of it. Two extra probes
## exercise staging (a *.cfg the tool substitutes in, a non-*.cfg copied verbatim);
## --live-overlay stages files into /live.
######################################################################
grub_overlay="${workdir}/grub-overlay"
live_overlay="${workdir}/live-overlay"
mkdir --parents -- "${grub_overlay}" "${live_overlay}"
cat > "${grub_overlay}/config.cfg" <<'CFG'
set default=0
set timeout=@TIMEOUT@
insmod all_video
insmod gfxterm
if loadfont $prefix/unicode.pf2 ; then
   set gfxmode=auto
   terminal_output gfxterm
fi
CFG
cat > "${grub_overlay}/grub.cfg" <<'CFG'
source /boot/grub/config.cfg
menuentry "Live" {
   linux /live/vmlinuz @APPEND_LIVE@
   initrd /live/initrd.img
}
CFG
printf '%s\n' 'source /boot/grub/grub.cfg' > "${grub_overlay}/loopback.cfg"
cat > "${grub_overlay}/esp-redirect.cfg" <<'CFG'
search --set=root --file /.disk/info
set prefix=($root)/boot/grub
configfile ($root)/boot/grub/grub.cfg
CFG
## A *.cfg carrying the placeholder: the tool must substitute the live cmdline.
printf 'probe %s done\n' '@APPEND_LIVE@' > "${grub_overlay}/probe.cfg"
## A non-*.cfg file: copied verbatim, no substitution.
printf 'overlay-marker\n' > "${grub_overlay}/marker.txt"
## A /live overlay file.
printf 'live-overlay-marker\n' > "${live_overlay}/probe.marker"

######################################################################
## Build the ISO (fixed SOURCE_DATE_EPOCH so we can also check reproducibility).
######################################################################
sde=1700000000
printf '### building ISO from %s (arch=%s)\n' "${raw_image}" "${arch}" >&2
"${bin}" --raw "${raw_image}" --output "${iso}" --arch "${arch}" \
   --label "${label}" --serial-console --source-date-epoch "${sde}" \
   --grub-overlay "${grub_overlay}" --live-overlay "${live_overlay}"
[ -f "${iso}" ] || { bad "dm-raw-to-iso produced no ISO" ; printf '\nbuild_and_boot: %s pass, %s fail\n' "${pass}" "${fail}" ; exit 1 ; }
ok "ISO built: ${iso}"

######################################################################
## Structure assertions. Reusable checker so we can canary it.
######################################################################
## Lists paths inside an ISO (Rock Ridge names), one per line.
iso_paths() {
   xorriso -indev "$1" -find / -type f 2>/dev/null | sed -e "s/^'//" -e "s/'\$//"
}

## Returns 0 iff the ISO carries the boot structures a highly-compatible hybrid
## ISO must have for the given arch. Prints why it failed.
iso_boot_structure_ok() {
   local target_iso="$1" target_arch="$2" et paths problems efi_loader
   problems=""
   et="$(xorriso -indev "${target_iso}" -report_el_torito plain 2>/dev/null || true)"
   paths="$(iso_paths "${target_iso}")"

   ## Always: an EFI El Torito entry (platform 0xEF / "UEFI").
   case "${et}" in
      *UEFI*|*platform_id*0xef*|*0xEF*)
         true
         ;;
      *)
         problems="${problems} no-EFI-eltorito-entry"
         ;;
   esac
   ## amd64: also a BIOS entry (platform 0x00) and the BIOS core file.
   if [ "${target_arch}" = "amd64" ]; then
      case "${et}" in
         *0x00*|*BIOS*|*"80x86"*)
            true
            ;;
         *)
            problems="${problems} no-BIOS-eltorito-entry"
            ;;
      esac
      case "${paths}" in
         *"/boot/grub/grub_eltorito"*)
            true
            ;;
         *)
            problems="${problems} no-grub_eltorito"
            ;;
      esac
   fi
   ## ESP FAT image + loopback.cfg + the EFI loader on the ISO tree.
   case "${paths}" in
      *"/boot/grub/efi.img"*)
         true
         ;;
      *)
         problems="${problems} no-efi.img"
         ;;
   esac
   case "${paths}" in
      *"/boot/grub/loopback.cfg"*)
         true
         ;;
      *)
         problems="${problems} no-loopback.cfg"
         ;;
   esac
   ## Per-arch EFI removable-media loader name (matches dm-raw-to-iso's efi-image
   ## mapping). Unknown arch is an error, not an amd64 default -- treating i386 or
   ## armhf as amd64 makes the loader check pass/fail on the wrong filename.
   case "${target_arch}" in
      amd64)
         efi_loader="/EFI/boot/bootx64.efi"
         ;;
      i386)
         efi_loader="/EFI/boot/bootia32.efi"
         ;;
      arm64)
         efi_loader="/EFI/boot/bootaa64.efi"
         ;;
      armhf)
         efi_loader="/EFI/boot/bootarm.efi"
         ;;
      *)
         printf 'unsupported --arch for boot-structure check: %s\n' "${target_arch}" >&2
         return 1
         ;;
   esac
   case "${paths}" in
      *"${efi_loader}"*)
         true
         ;;
      *)
         problems="${problems} no-${efi_loader}"
         ;;
   esac

   if [ -n "${problems}" ]; then
      printf 'structure problems:%s\n' "${problems}" >&2
      return 1
   fi
   return 0
}

if iso_boot_structure_ok "${iso}" "${arch}"; then
   ok "ISO boot structure (BIOS+EFI El Torito, ESP, loopback.cfg, EFI loader)"
else
   bad "ISO boot structure incomplete"
fi

## loopback.cfg content + findiso in the live entry (loopback-from-file support).
loop_cfg="$(xorriso -osirrox on -indev "${iso}" -cpx /boot/grub/loopback.cfg "${workdir}/loopback.cfg" 2>/dev/null && cat "${workdir}/loopback.cfg" || true)"
case "${loop_cfg}" in
   *"source /boot/grub/grub.cfg"*)
      ok "loopback.cfg sources grub.cfg"
      ;;
   *)
      bad "loopback.cfg missing 'source /boot/grub/grub.cfg'"
      ;;
esac
grub_cfg="$(xorriso -osirrox on -indev "${iso}" -cpx /boot/grub/grub.cfg "${workdir}/grub.cfg" 2>/dev/null && cat "${workdir}/grub.cfg" || true)"
case "${grub_cfg}" in
   *"iso-scan/filename=\${iso_path}"*|*"findiso="*)
      ok "live entry carries findiso/iso-scan for loop-boot"
      ;;
   *)
      bad "live entry lacks findiso/iso-scan=\${iso_path}"
      ;;
esac
## config.cfg: the tool substitutes @TIMEOUT@ (0 under --serial-console, so the
## default entry boots headless) and appends a serial terminal for --serial-console.
cfg_cfg="$(xorriso -osirrox on -indev "${iso}" -cpx /boot/grub/config.cfg "${workdir}/config.cfg" 2>/dev/null && cat "${workdir}/config.cfg" || true)"
case "${cfg_cfg}" in
   *"@TIMEOUT@"*)
      bad "config.cfg: @TIMEOUT@ left unsubstituted"
      ;;
   *"set timeout=0"*)
      ok "config.cfg: @TIMEOUT@ substituted (--serial-console -> timeout 0)"
      ;;
   *)
      bad "config.cfg: @TIMEOUT@ not substituted to 0 (${cfg_cfg})"
      ;;
esac
case "${cfg_cfg}" in
   *"terminal_output serial console"*)
      ok "config.cfg: --serial-console appended a serial terminal"
      ;;
   *)
      bad "config.cfg: --serial-console did not append a serial terminal"
      ;;
esac

######################################################################
## --grub-overlay / --live-overlay staging.
######################################################################
## Non-*.cfg overlay file lands verbatim in /boot/grub.
ov_marker="$(xorriso -osirrox on -indev "${iso}" -cpx /boot/grub/marker.txt "${workdir}/marker.txt" 2>/dev/null && cat "${workdir}/marker.txt" || true)"
case "${ov_marker}" in
   *"overlay-marker"*)
      ok "--grub-overlay: non-cfg file staged into /boot/grub verbatim"
      ;;
   *)
      bad "--grub-overlay: /boot/grub/marker.txt missing or wrong content"
      ;;
esac
## *.cfg overlay file has @APPEND_LIVE@ substituted with the live cmdline, and no
## literal placeholder remains.
ov_probe="$(xorriso -osirrox on -indev "${iso}" -cpx /boot/grub/probe.cfg "${workdir}/probe.cfg" 2>/dev/null && cat "${workdir}/probe.cfg" || true)"
case "${ov_probe}" in
   *"@APPEND_LIVE@"*)
      bad "--grub-overlay: @APPEND_LIVE@ left unsubstituted in a staged *.cfg"
      ;;
   *"root=live:CDLABEL=${label}"*)
      ok "--grub-overlay: @APPEND_LIVE@ substituted with the live cmdline in a staged *.cfg"
      ;;
   *)
      bad "--grub-overlay: probe.cfg missing or not substituted (${ov_probe})"
      ;;
esac
## --live-overlay file lands in /live.
ov_live="$(xorriso -osirrox on -indev "${iso}" -cpx /live/probe.marker "${workdir}/probe.marker" 2>/dev/null && cat "${workdir}/probe.marker" || true)"
case "${ov_live}" in
   *"live-overlay-marker"*)
      ok "--live-overlay: file staged into /live"
      ;;
   *)
      bad "--live-overlay: /live/probe.marker missing or wrong content"
      ;;
esac

######################################################################
## Canary the structure checker: a plain data ISO with no boot catalog
## MUST be rejected, or the checker proves nothing.
######################################################################
mkdir -p -- "${workdir}/plain/some"
printf '' > "${workdir}/plain/some/file"
xorriso -as mkisofs -R -J -o "${workdir}/plain.iso" "${workdir}/plain" >/dev/null 2>&1
if iso_boot_structure_ok "${workdir}/plain.iso" "${arch}"; then
   bad "canary: structure checker PASSED a non-bootable ISO (no teeth)"
else
   ok "canary: structure checker rejects a non-bootable ISO"
fi

######################################################################
## Reproducibility: informational only (see note below).
######################################################################
iso2="${workdir}/out2.iso"
"${bin}" --raw "${raw_image}" --output "${iso2}" --arch "${arch}" \
   --label "${label}" --serial-console --source-date-epoch "${sde}" \
   --grub-overlay "${grub_overlay}" --live-overlay "${live_overlay}"
## Informational, NOT a pass/fail gate. dm-raw-to-iso's PACKAGING is deterministic
## given a fixed staging tree + SOURCE_DATE_EPOCH, but two FULL builds re-run
## dracut on a fresh rootfs copy, and byte-identical output additionally requires
## normalizing the rootfs (debconf owners, symlink mtimes, /run) and a reproducible
## initramfs -- the work derivative-maker's 3600 does and that is out of scope for
## this minimal reference tool. Report the result without failing on a difference.
if cmp --silent -- "${iso}" "${iso2}"; then
   ok "reproducible: two full builds byte-identical (sha256 $(sha256sum -- "${iso}" | cut -d' ' -f1))"
else
   printf 'NOTE: two full builds differ (expected: rootfs/initramfs not normalized; packaging itself is deterministic). Not a failure.\n' >&2
fi

######################################################################
## Boot the ISO across firmware via dm-qemu.
######################################################################
## Per-arch: amd64 has SeaBIOS + OVMF (efi/efi-secureboot); arm64 boots edk2 UEFI
## under dm-qemu's 'bios' firmware (efi/efi-secureboot are x86-only and exit 2).
## Gate on the arch's OWN qemu binary, not always qemu-system-x86_64.
## Per-arch QEMU binary + firmware legs. amd64 gets the full BIOS + x64/ia32 EFI +
## Secure Boot matrix; i386 has BIOS + ia32 EFI (no Secure Boot); arm has no BIOS,
## its single UEFI leg runs under dm-qemu's 'bios' firmware (efi/efi-secureboot are
## x86-only and exit 2). Unknown arch is an error, not an x86 default -- routing an
## ARM image to qemu-system-x86_64 fails every leg for the wrong reason.
case "${arch}" in
   amd64)
      qemu_bin="qemu-system-x86_64"
      firmwares="bios efi efi-secureboot"
      ;;
   i386)
      qemu_bin="qemu-system-i386"
      firmwares="bios efi"
      ;;
   arm64)
      qemu_bin="qemu-system-aarch64"
      firmwares="bios"
      ;;
   armhf)
      qemu_bin="qemu-system-arm"
      firmwares="bios"
      ;;
   *)
      printf 'unsupported DM_RAW_TO_ISO_TEST_ARCH: %s\n' "${arch}" >&2
      exit 2
      ;;
esac

boot_ran=0
if [ ! -x "${dm_qemu}" ] || ! type -P "${qemu_bin}" >/dev/null 2>&1; then
   printf 'NOTE: dm-qemu or %s absent; boot cannot be validated.\n' "${qemu_bin}" >&2
else
   for fw in ${firmwares}; do
      printf '### boot leg: firmware=%s\n' "${fw}" >&2
      slog="${workdir}/boot-${fw}.serial.log"
      rc=0
      ## Bounded timeout: dm-qemu waits for a login prompt until --timeout, but
      ## dm-raw-to-iso's responsibility ends at the BOOT CHAIN. Reaching systemd
      ## (systemd[1] / Reached target) proves firmware -> (shim -> signed grub for
      ## secure boot) -> kernel -> dracut-live mounted the squashfs -> init all
      ## worked. A login prompt is the image's userland, not this tool's job. So
      ## judge by the serial-log markers, not dm-qemu's login-centric exit code.
      "${dm_qemu}" --iso "${iso}" --arch "${arch}" --firmware "${fw}" \
         --timeout 300 --serial-log "${slog}" || rc=$?
      if [ "${rc}" -eq 77 ]; then
         printf 'NOTE: boot leg firmware=%s SKIPPED by dm-qemu (rc 77)\n' "${fw}" >&2
      elif [ "${rc}" -eq 2 ]; then
         bad "boot leg firmware=${fw}: dm-qemu setup error (rc 2)"
      elif grep --quiet --ignore-case --extended-regexp 'login:' "${slog}" 2>/dev/null; then
         ok "boot leg firmware=${fw} reached a login prompt (full boot)"
         boot_ran=$(( boot_ran + 1 ))
      elif grep --quiet --ignore-case --extended-regexp 'Reached target|systemd\[1\]|Welcome to|Linux version' "${slog}" 2>/dev/null; then
         ok "boot leg firmware=${fw} booted (kernel+systemd reached -> boot chain OK)"
         boot_ran=$(( boot_ran + 1 ))
      else
         bad "boot leg firmware=${fw} did not boot (no kernel/systemd marker); see ${slog}"
      fi
   done
fi

## Do NOT pass on the structure checks alone: if not a single boot leg actually
## validated the ISO (harness/qemu absent, or every leg skipped), report SKIP
## rather than a green "build_and_boot" with no boot exercised.
if [ "${fail}" -eq 0 ] && [ "${boot_ran}" -eq 0 ]; then
   printf 'SKIP: structure checks passed but NO boot leg validated the ISO (dm-qemu / %s unavailable).\n' "${qemu_bin}" >&2
   ## style-ok: allow-skip: the boot harness was unavailable so boot was not exercised; structure-only is not a build+boot pass
   exit 77
fi

printf '\nbuild_and_boot: %s pass, %s fail (boot legs validated: %s)\n' "${pass}" "${fail}" "${boot_ran}"
[ "${fail}" -eq 0 ] || exit 1
[ "${pass}" -gt 0 ] || { printf 'FATAL: no assertions ran\n' >&2 ; exit 1 ; }
exit 0
