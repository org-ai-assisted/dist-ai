#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-disk-mount runs the caller's command as ROOT with CWD inside the guest filesystem. A
## hostile guest symlink (e.g. a file that points at a host path) must NOT let that root command
## write out of the mount -- the mount carries 'nosymfollow', so following any guest symlink
## fails. End-to-end: build a GPT+ext4 VDI holding a symlink 'evil' -> a HOST sentinel, run a
## command that writes through 'evil', and assert the sentinel is UNCHANGED.
##
## Needs root + qemu-nbd/qemu-img/mkfs.ext4/parted/losetup + the nbd module, so it SKIPS (77) on
## the plain host suite and RUNS in the sandbox (root).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ "$(id -u)" != '0' ]; then
   printf '%s\n' "SKIP: real nbd+mount needs root; run in the sandbox" >&2
   exit 77  ## style-ok: allow-skip: real nbd+mount symlink-escape check needs root (sandbox lane)
fi
for tool in qemu-nbd qemu-img mkfs.ext4 parted losetup; do
   if ! type -P "${tool}" >/dev/null 2>&1; then
      printf '%s\n' "SKIP: '${tool}' absent" >&2
      exit 77  ## style-ok: allow-skip: qemu-utils/mkfs.ext4/parted are an nbd-capable-env dependency
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
loop_devs=()
# shellcheck disable=SC2317  ## runs via the EXIT trap
test_cleanup() {
   if mountpoint --quiet -- "${work}/bmnt" 2>/dev/null; then
      umount -- "${work}/bmnt" || true
   fi
   local d
   for d in "${loop_devs[@]}"; do
      losetup --detach "${d}" 2>/dev/null || true
   done
   safe-rm --recursive --force -- "${work}"
}
trap test_cleanup EXIT

pass=0
fail=0
check() {
   if [ "$2" = "$3" ]; then
      printf '%s\n' "ok: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1" "  got:  $2" "  want: $3" >&2
      fail=$(( fail + 1 ))
   fi
}

sentinel="${work}/host-sentinel"
printf '%s' 'ORIGINAL' > "${sentinel}"

raw="${work}/prep.raw"
img="${work}/disk.vdi"
truncate --size=64M -- "${raw}"
parted --script -- "${raw}" mklabel gpt mkpart primary 1MiB 100%
loop="$(losetup --find --partscan --show -- "${raw}")"
loop_devs+=( "${loop}" )
for ((i = 0; i < 40; i++)); do
   udevadm settle 2>/dev/null || true
   [ -b "${loop}p1" ] && break
   sleep 0.25
done
mkfs.ext4 -q -- "${loop}p1"
mkdir -- "${work}/bmnt"
mount -- "${loop}p1" "${work}/bmnt"
## Plant a hostile guest symlink pointing at the HOST sentinel (absolute path).
ln --symbolic -- "${sentinel}" "${work}/bmnt/evil"
umount -- "${work}/bmnt"
losetup --detach "${loop}"
loop_devs=()
qemu-img convert -f raw -O vdi -- "${raw}" "${img}"

## Act: a root command tries to write THROUGH the guest symlink. With nosymfollow the open
## fails (ELOOP), so the command fails and the host sentinel is untouched.
"${subject}" run --disk "${img}" -- sh -c 'echo PWNED > evil' >/dev/null 2>&1 || true

check 'host sentinel NOT written through the guest symlink (nosymfollow blocks the escape)' \
   "$(cat -- "${sentinel}")" 'ORIGINAL'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
