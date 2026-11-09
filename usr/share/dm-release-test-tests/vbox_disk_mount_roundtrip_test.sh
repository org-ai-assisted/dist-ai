#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## End-to-end: vbox-disk-mount opens a LUKS VDI disk image read-WRITE over qemu-nbd, runs a
## command that creates a file on it, and after teardown the write has persisted and no
## nbd / device-mapper residue is left. Exercises the real connect -> unlock -> mount ->
## run -> sync -> unmount path (not just the arg seam in vbox_disk_mount_args_test).
##
## The image is a VDI (the format the tool targets): qemu-nbd auto-probes a RAW image as
## raw and restricts block-0 writes, so a raw test image would not reflect production.
##
## Needs root + qemu-nbd + qemu-img + cryptsetup + mkfs.ext4 + a working nbd module, so it
## SKIPS (exit 77) on the plain host suite and RUNS in the sandbox (temp-claude, root).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ "$(id -u)" != '0' ]; then
   printf '%s\n' "SKIP: real LUKS+nbd mount needs root; run in the sandbox" >&2
   exit 77  ## style-ok: allow-skip: real LUKS+nbd read-write mount needs root (sandbox lane)
fi
for tool in qemu-nbd qemu-img cryptsetup mkfs.ext4; do
   if ! type -P "${tool}" >/dev/null 2>&1; then
      printf '%s\n' "SKIP: '${tool}' absent" >&2
      exit 77  ## style-ok: allow-skip: qemu-utils/cryptsetup/mkfs.ext4 are an nbd-capable-env dependency
   fi
done
modprobe nbd max_part=16 2>/dev/null || true
if [ ! -b /dev/nbd0 ]; then
   printf '%s\n' "SKIP: nbd module unavailable (no /dev/nbd0)" >&2
   exit 77  ## style-ok: allow-skip: the nbd kernel module is not loadable in this environment
fi

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject="${VBOX_DISK_MOUNT_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -x "${test_dir}/../../bin/vbox-disk-mount" ]; then
      subject="${test_dir}/../../bin/vbox-disk-mount"
   else
      subject='/usr/bin/vbox-disk-mount'
   fi
fi
[ -x "${subject}" ] || { printf '%s\n' "FATAL: vbox-disk-mount not executable at ${subject}" >&2; exit 1; }

work="$(mktemp --directory)"
prep_name="vdmrt-prep-$$"
verify_name="vdmrt-verify-$$"
# shellcheck disable=SC2317  ## runs via the EXIT trap
test_cleanup() {
   if mountpoint --quiet -- "${work}/mnt" 2>/dev/null; then
      umount -- "${work}/mnt" || true
   fi
   for n in "${prep_name}" "${verify_name}"; do
      if [ -e "/dev/mapper/${n}" ]; then
         cryptsetup close -- "${n}" || true
      fi
   done
   safe-rm --recursive --force -- "${work}"
}
trap test_cleanup EXIT

pass=0
fail=0
check() {
   local desc="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "ok: ${desc}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}" "  got:  ${got}" "  want: ${want}" >&2
      fail=$(( fail + 1 ))
   fi
}

raw="${work}/prep.raw"
img="${work}/disk.vdi"
vraw="${work}/verify.raw"
pf="${work}/pf"
printf '%s' 'roundtrip-test-passphrase' > "${pf}"
chmod 0600 -- "${pf}"

## Build a LUKS2 + ext4 volume in a RAW file (cryptsetup loop-mounts a file directly), then
## convert to VDI so the tool sees the on-disk format it targets. Fast pbkdf for a throwaway
## image. The passphrase file has NO trailing newline, matching luks_open's stripped read.
truncate --size=64M -- "${raw}"
cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
   --key-file "${pf}" -- "${raw}"
cryptsetup open --key-file "${pf}" -- "${raw}" "${prep_name}"
mkfs.ext4 -q -- "/dev/mapper/${prep_name}"
cryptsetup close -- "${prep_name}"
qemu-img convert -f raw -O vdi -- "${raw}" "${img}"
safe-rm --force -- "${raw}"

## Act: mount read-write and create a marker file on the guest filesystem.
rc=0
"${subject}" run --disk "${img}" --passphrase-file "${pf}" -- touch marker || rc=$?
check 'vbox-disk-mount run exits 0' "${rc}" '0'

## No leftover device-mapper node from the tool's own mapping (vdm-<pid>-luks).
leftover="$(find /dev/mapper -maxdepth 1 -name 'vdm-[0-9]*-luks' 2>/dev/null | wc -l)"
check 'no device-mapper residue from the tool' "${leftover}" '0'

## Verify the write persisted: convert the tool-written VDI back to raw and inspect it
## read-only through an independent LUKS open.
qemu-img convert -f vdi -O raw -- "${img}" "${vraw}"
cryptsetup open --readonly --key-file "${pf}" -- "${vraw}" "${verify_name}"
mkdir -- "${work}/mnt"
mount --read-only -- "/dev/mapper/${verify_name}" "${work}/mnt"
if [ -e "${work}/mnt/marker" ]; then
   check 'marker written by the run command persisted after unmount' 'present' 'present'
else
   check 'marker written by the run command persisted after unmount' 'absent' 'present'
fi
umount -- "${work}/mnt"
cryptsetup close -- "${verify_name}"

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
