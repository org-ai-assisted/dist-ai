#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-nbd-cleanup mount-release.
##
## TWO bugs it guards:
##
## (A) CONFUSED-DEPUTY (security). dm-nbd-cleanup runs sudo umount. An unprivileged
##     user can mount FUSE with fsname=/dev/nbd0, so the /proc/mounts source string
##     is attacker-controlled. dm-nbd-cleanup accepts a mount as nbd-backed only
##     when the source is an EXACT nbd device name (/dev/nbd<N>[p<M>], NOT a
##     same-prefix name such as /dev/nbd-backup) AND the kernel-set fstype is a
##     real block filesystem (/proc/filesystems without 'nodev'). The fstype-nodev
##     check rejects a forgeable fuse/tmpfs spoof; the exact-name check rejects a
##     same-prefix source. No device numbers are used -- a deliberate design
##     decision in dm-nbd-cleanup.
##
## (B) READ-WHILE-MUTATE SKIP. Unmounting INSIDE 'while read ... < /proc/mounts'
##     reads a file that mutates under the loop, silently skipping later entries.
##     The fix collects ALL nbd mount points first, THEN unmounts from that
##     snapshot.
##
## This test is TWO layers:
##  (1) BEHAVIORAL -- drive the REAL tool (--release) against a /proc/mounts FIXTURE
##      (DM_NBD_CLEANUP_PROC_MOUNTS) with sudo stubbed on PATH, asserting on the
##      RECORDED umount invocations: every nbd-backed mount (including a
##      \040-encoded mount point and an anonymous-superblock btrfs) is unmounted;
##      and NO non-nbd mount is -- neither an ordinary device, a tmpfs, a deputy
##      spoof (source '/dev/nbd0' but fstype fuse.evil), nor a same-prefix source
##      (/dev/nbd-backup). The spoof and same-prefix source are the security teeth.
##  (2) STRUCTURAL BACKSTOP -- the read-while-mutate SKIP (B) is a /proc-specific
##      artifact that only reproduces under real mount namespaces (a regular-file
##      fixture cannot: an open fd pins the inode). Guard the fix by its stable
##      shape: the tool collects into an nbd_mount_points snapshot array and
##      iterates THAT for unmounting.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$(( test_failures + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

rel='packages/kicksecure/developer-meta-files/usr/bin/dm-nbd-cleanup'
subject=""
## Use ':+' so an UNSET DEVELOPER_META_FILES_DIR yields an EMPTY candidate (skipped
## below), not '/usr/bin/dm-nbd-cleanup' -- an empty prefix would collapse to the
## installed copy and shadow the checkout candidate, silently testing a stale
## binary. The installed copy stays a deliberate LAST-resort candidate.
for candidate in "${DM_NBD_CLEANUP:-}" \
   "${DEVELOPER_META_FILES_DIR:+${DEVELOPER_META_FILES_DIR}/usr/bin/dm-nbd-cleanup}" \
   "${dm_checkout}/${rel}" \
   "/usr/bin/dm-nbd-cleanup"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-nbd-cleanup not found (set DM_NBD_CLEANUP)." >&2
   exit 1
fi

## dm-nbd-cleanup sources helper-scripts strings.bsh (default_if_empty). Resolve a
## checkout so the behavioral run can source it; a required dependency, never a skip.
if [ -n "${HELPER_SCRIPTS_PATH:-}" ]; then
   hs_path="${HELPER_SCRIPTS_PATH}"
elif [ -n "${HELPER_SCRIPTS_REPO:-}" ]; then
   hs_path="${HELPER_SCRIPTS_REPO}"
elif [ -r "${dm_checkout}/packages/kicksecure/helper-scripts/usr/libexec/helper-scripts/strings.bsh" ]; then
   hs_path="${dm_checkout}/packages/kicksecure/helper-scripts"
elif [ -r "/usr/libexec/helper-scripts/strings.bsh" ]; then
   hs_path=""
else
   printf '%s\n' "FATAL: helper-scripts strings.bsh not found (set HELPER_SCRIPTS_REPO)." >&2
   exit 1
fi

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
harness="${tool_dir}/../dist-ai-tests-common/stub-path-harness.bash"
if [ ! -r "${harness}" ]; then
   printf '%s\n' "FATAL: stub-path harness not found at '${harness}'" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/stub-path-harness.bash
source "${harness}"

## --- (1) BEHAVIORAL: drive the real tool against a /proc/mounts fixture --------
work_dir="$(mktemp --directory)"
cleanup_handler() {
   stub_path_cleanup
   safe-rm --recursive --force -- "${work_dir}" || true
}
trap cleanup_handler EXIT

## A /proc/mounts-shaped fixture. Fields: device mountpoint fstype opts dump pass.
## - nbd-backed block fs (ext4) directly on an nbd device, MUST be unmounted (one
##   has a \040-encoded space in its mount point; several exercise the snapshot).
## - nbd-backed btrfs: anonymous superblock (no major needed), but the source is
##   an exact nbd device and 'btrfs' is a real block fs -- MUST be unmounted.
## - an ordinary device (/dev/sda1) and a tmpfs: must NOT be.
## - the deputy spoof: source string '/dev/nbd0' but fstype 'fuse.evil' (a 'nodev'
##   type an unprivileged user can forge) -- must NOT be unmounted.
## - same-prefix sources (/dev/nbd-backup, /dev/nbd0-backup): NOT nbd devices --
##   must NOT be unmounted.
mounts_fixture="${work_dir}/mounts"
{
   printf '%s\n' '/dev/nbd0 /mnt/nbd-a ext4 rw,relatime 0 0'
   printf '%s\n' '/dev/sda1 /boot ext4 rw,relatime 0 0'
   printf '%s\n' '/dev/nbd1 /mnt/nbd\040b ext4 rw,relatime 0 0'
   printf '%s\n' 'tmpfs /mnt/plain-tmpfs tmpfs rw 0 0'
   printf '%s\n' '/dev/nbd2 /mnt/nbd-c ext4 rw,relatime 0 0'
   printf '%s\n' '/dev/nbd0 /mnt/spoof fuse.evil rw 0 0'
   printf '%s\n' '/dev/nbd3p1 /mnt/nbd-btrfs btrfs rw,relatime 0 0'
   printf '%s\n' '/dev/nbd-backup /mnt/nbd-backup ext4 rw,relatime 0 0'
   printf '%s\n' '/dev/nbd0-backup /mnt/nbd0-backup ext4 rw,relatime 0 0'
} > "${mounts_fixture}"

## A /proc/filesystems-shaped fixture: 'nodev'-prefixed lines are virtual /
## userspace filesystems (forgeable source), the rest are real block filesystems.
filesystems_fixture="${work_dir}/filesystems"
{
   printf '%s\n' "nodev"$'\t'"sysfs"
   printf '%s\n' "nodev"$'\t'"tmpfs"
   printf '%s\n' "nodev"$'\t'"fuse"
   printf '%s\n' $'\t'"ext4"
   printf '%s\n' $'\t'"btrfs"
   printf '%s\n' $'\t'"xfs"
} > "${filesystems_fixture}"

stub_path_init
## sudo is the only external the --release mount path invokes here (the device
## loop needs real /dev/nbd* block devices, absent on the test host). Record its
## argv; the mount point rides in it.
stub_cmd sudo 0

run_rc=0
DM_NBD_CLEANUP_PROC_MOUNTS="${mounts_fixture}" \
   DM_NBD_CLEANUP_PROC_FILESYSTEMS="${filesystems_fixture}" \
   HELPER_SCRIPTS_PATH="${hs_path}" \
   "${subject}" --release >/dev/null 2>&1 || run_rc=$?
if [ "${run_rc}" -eq 0 ]; then
   pass "behavioral: dm-nbd-cleanup --release ran cleanly against the fixture"
else
   fail "behavioral: dm-nbd-cleanup --release exited ${run_rc} against the fixture"
fi

## Every nbd-backed mount is unmounted -- the \040-encoded space (decoded) and the
## anonymous-superblock btrfs, accepted by exact nbd device name + block fstype.
for want in '/mnt/nbd-a' '/mnt/nbd b' '/mnt/nbd-c' '/mnt/nbd-btrfs'; do
   if stub_called_with sudo umount -- "${want}"; then
      pass "behavioral: nbd-backed mount '${want}' was unmounted"
   else
      fail "behavioral: nbd-backed mount '${want}' was NOT unmounted (skipped or mis-decoded)"
   fi
done

## No non-nbd mount is unmounted -- ordinary device, tmpfs, the deputy spoof, and
## same-prefix source names (/dev/nbd-backup, /dev/nbd0-backup) that are NOT nbd devices.
for unwanted in '/boot' '/mnt/plain-tmpfs' '/mnt/spoof' '/mnt/nbd-backup' '/mnt/nbd0-backup'; do
   if stub_not_called_with sudo umount -- "${unwanted}"; then
      pass "behavioral: non-nbd mount '${unwanted}' was left alone"
   else
      fail "behavioral: non-nbd mount '${unwanted}' was unmounted (exact-name/fstype filtering broken)"
   fi
done

## --- (2) STRUCTURAL BACKSTOP: the snapshot-array shape (read-order guard) -----
## Robust pattern-presence, not a line-number ordering parse: a regression to
## unmount-inside-the-read-loop would drop this collect-then-iterate shape.
# shellcheck disable=SC2016  # literal source-text pattern to grep, not an expansion here
if grep --quiet --extended-regexp -- '^\s*nbd_mount_points=\(\)' "${subject}" \
   && grep --quiet --fixed-strings -- 'for mount_point in "${nbd_mount_points[@]}"' "${subject}"; then
   pass "structural: unmount iterates the collected 'nbd_mount_points' snapshot"
else
   fail "structural: no 'nbd_mount_points' snapshot array iterated for unmounting"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-nbd-cleanup accepts only exact nbd device names with a block fstype and snapshots before unmounting (${pass_count} assertions)."
