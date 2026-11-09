#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## End-to-end: image-mount opens a GPT-partitioned LUKS VDI disk image read-WRITE over
## qemu-nbd, runs a command that creates a file on it, and after teardown the write has
## persisted and no nbd / device-mapper residue is left. Exercises the real connect ->
## settle-partitions -> unlock -> mount -> run -> sync -> unmount path (not just the arg
## seam in image_mount_args_test). Also proves a real vdi passes the uniform self-containment
## gate (nbd_connect now probes every format, including vdi, before opening).
##
## The image is PARTITIONED (LUKS on partition 1) and a VDI -- the layout the Calamares
## install produces and the format the tool targets. The partition table also exercises
## settle_partitions waiting for the partition node rather than returning on the whole-disk
## PTTYPE signature. A raw image would trip qemu-nbd's raw-probe block-0 write restriction.
##
## Needs root + qemu-nbd + qemu-img + cryptsetup + mkfs.ext4 + parted + a working nbd
## module, so it SKIPS (exit 77) on the plain host suite and RUNS in the sandbox (root).

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
for tool in qemu-nbd qemu-img cryptsetup mkfs.ext4 parted losetup; do
   if ! type -P "${tool}" >/dev/null 2>&1; then
      printf '%s\n' "SKIP: '${tool}' absent" >&2
      exit 77  ## style-ok: allow-skip: qemu-utils/cryptsetup/mkfs.ext4/parted are an nbd-capable-env dependency
   fi
done
modprobe nbd max_part=16 2>/dev/null || true
if [ ! -b /dev/nbd0 ]; then
   printf '%s\n' "SKIP: nbd module unavailable (no /dev/nbd0)" >&2
   exit 77  ## style-ok: allow-skip: the nbd kernel module is not loadable in this environment
fi

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject="${IMAGE_MOUNT_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -x "${test_dir}/../../bin/image-mount" ]; then
      subject="${test_dir}/../../bin/image-mount"
   else
      subject='/usr/bin/image-mount'
   fi
fi
[ -x "${subject}" ] || { printf '%s\n' "FATAL: image-mount not executable at ${subject}" >&2; exit 1; }

work="$(mktemp --directory)"
prep_name="vdmrt-prep-$$"
verify_name="vdmrt-verify-$$"
loop_devs=()
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
   local d
   for d in "${loop_devs[@]}"; do
      ## losetup --detach takes NO '--' separator (it rejects it); the device paths are
      ## ours (mktemp work dir), so passing them directly is safe.
      losetup --detach "${d}" 2>/dev/null || true
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

## Expose a raw file's partitions as /dev/loopNp*, waiting for the first node, and record the
## loop device for teardown. Echoes the loop device path.
loop_partscan() {
   local file="$1" dev i
   dev="$(losetup --find --partscan --show -- "${file}")"
   loop_devs+=( "${dev}" )
   for ((i = 0; i < 40; i++)); do
      udevadm settle 2>/dev/null || true
      if [ -b "${dev}p1" ]; then
         break
      fi
      sleep 0.25
   done
   printf '%s' "${dev}"
}

raw="${work}/prep.raw"
img="${work}/disk.vdi"
vraw="${work}/verify.raw"
pf="${work}/pf"
printf '%s' 'roundtrip-test-passphrase' > "${pf}"
chmod 0600 -- "${pf}"

## Build a GPT disk with one partition holding a LUKS2 + ext4 volume, then convert to VDI so
## the tool sees the on-disk format it targets. Fast pbkdf for a throwaway image. The
## passphrase file has NO trailing newline, matching luks_open's stripped read.
truncate --size=128M -- "${raw}"
parted --script -- "${raw}" mklabel gpt mkpart primary 1MiB 100%
prep_loop="$(loop_partscan "${raw}")"
cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
   --key-file "${pf}" -- "${prep_loop}p1"
cryptsetup open --key-file "${pf}" -- "${prep_loop}p1" "${prep_name}"
mkfs.ext4 -q -- "/dev/mapper/${prep_name}"
cryptsetup close -- "${prep_name}"
losetup --detach "${prep_loop}"
qemu-img convert -f raw -O vdi -- "${raw}" "${img}"

## Act: mount read-write and create a marker file on the guest filesystem.
rc=0
"${subject}" run --disk "${img}" --format vdi --passphrase-file "${pf}" -- touch marker || rc=$?
check 'image-mount run exits 0' "${rc}" '0'

## No leftover device-mapper node from the tool's own mapping (im-<pid>-luks).
leftover="$(find /dev/mapper -maxdepth 1 -name 'im-[0-9]*-luks' 2>/dev/null | wc -l)"
check 'no device-mapper residue from the tool' "${leftover}" '0'

## Verify the write persisted: convert the tool-written VDI back to raw and inspect it
## read-only through an independent LUKS open on the partition.
qemu-img convert -f vdi -O raw -- "${img}" "${vraw}"
verify_loop="$(loop_partscan "${vraw}")"
cryptsetup open --readonly --key-file "${pf}" -- "${verify_loop}p1" "${verify_name}"
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
