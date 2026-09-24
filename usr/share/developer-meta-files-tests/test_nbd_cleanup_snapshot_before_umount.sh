#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-nbd-cleanup mount-release.
##
## TWO bugs it guards:
##
## (A) CONFUSED-DEPUTY (security). dm-nbd-cleanup runs sudo umount. Selecting the
##     mounts to unmount by the SOURCE STRING in /proc/mounts is unsafe: an
##     unprivileged user can mount FUSE with fsname=/dev/nbd0, so the source
##     string is attacker-controlled. dm-nbd-cleanup instead reads
##     /proc/self/mountinfo and accepts a mount as nbd-backed only when the
##     KERNEL-set major (field 3) is NBD_MAJOR (43), OR the source is /dev/nbd*
##     AND the kernel-set fstype is a real block filesystem (/proc/filesystems
##     without 'nodev'). The major covers ext4/xfs directly on nbd; the block-fs
##     fallback covers anonymous-superblock btrfs (major 0) WITHOUT trusting a
##     forgeable fuse/tmpfs spoof (a 'nodev' type), which is rejected.
##
## (B) READ-WHILE-MUTATE SKIP. Unmounting INSIDE 'while read ... < mountinfo'
##     reads a file that mutates under the loop, silently skipping later entries.
##     The fix collects ALL nbd mount points first, THEN unmounts from that
##     snapshot.
##
## This test is TWO layers:
##  (1) BEHAVIORAL -- drive the REAL tool (--release) against a mountinfo FIXTURE
##      (DM_NBD_CLEANUP_PROC_MOUNTINFO) with sudo stubbed on PATH, asserting on the
##      RECORDED umount invocations: every real-nbd mount (major 43, including a
##      \040-encoded mount point) is unmounted; and NO non-nbd mount is -- neither
##      an ordinary device (major 8), a tmpfs (major 0), NOR a deputy spoof whose
##      source string is '/dev/nbd0' but whose backing major is 0. The spoof is
##      the security teeth: source-string selection would unmount it.
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

## --- (1) BEHAVIORAL: drive the real tool against a mountinfo fixture ----------
work_dir="$(mktemp --directory)"
cleanup_handler() {
   stub_path_cleanup
   safe-rm --recursive --force -- "${work_dir}" || true
}
trap cleanup_handler EXIT

## A /proc/self/mountinfo-shaped fixture. Fields: 1 id, 2 parent, 3 major:minor,
## 4 root, 5 mount point, 6 opts, ... - fstype source superopts.
## - major 43 (NBD_MAJOR): block fs directly on nbd, MUST be unmounted (one
##   \040-encoded).
## - nbd-backed btrfs: anonymous superblock so major is 0, but source is /dev/nbd*
##   and fstype 'btrfs' is a real block fs -- MUST be unmounted (keying on major
##   alone would skip it and disconnect the device under a live mount).
## - major 8 / tmpfs: ordinary device and tmpfs, must NOT be.
## - the deputy spoof: source string '/dev/nbd0' but fstype 'fuse.evil' (a 'nodev'
##   type an unprivileged user can forge) -- must NOT be unmounted.
mountinfo_fixture="${work_dir}/mountinfo"
{
   printf '%s\n' '36 35 43:0 / /mnt/nbd-a rw,relatime shared:1 - ext4 /dev/nbd0 rw'
   printf '%s\n' '37 35 8:1 / /boot rw,relatime shared:2 - ext4 /dev/sda1 rw'
   printf '%s\n' '38 35 43:1 / /mnt/nbd\040b rw,relatime shared:3 - ext4 /dev/nbd1 rw'
   printf '%s\n' '39 35 0:44 / /mnt/plain-tmpfs rw shared:4 - tmpfs tmpfs rw'
   printf '%s\n' '40 35 43:2 / /mnt/nbd-c rw,relatime shared:5 - ext4 /dev/nbd2 rw'
   printf '%s\n' '41 35 0:52 / /mnt/spoof rw shared:6 - fuse.evil /dev/nbd0 rw'
   printf '%s\n' '42 35 0:60 / /mnt/nbd-btrfs rw,relatime shared:7 - btrfs /dev/nbd3p1 rw'
   printf '%s\n' '43 35 7:1 / /mnt/nbd-backup rw,relatime shared:8 - ext4 /dev/nbd-backup rw'
   printf '%s\n' '44 35 7:2 / /mnt/nbd0-backup rw,relatime shared:9 - ext4 /dev/nbd0-backup rw'
   ## Optional-field count varies (mountinfo allows zero or many before ' - '):
   ## a real-nbd mount with ZERO and with MULTIPLE optional fields must still parse.
   printf '%s\n' '45 35 43:3 / /mnt/nbd-noopt rw,relatime - ext4 /dev/nbd4 rw'
   printf '%s\n' '46 35 43:4 / /mnt/nbd-multiopt rw,relatime shared:10 master:2 - ext4 /dev/nbd5 rw'
} > "${mountinfo_fixture}"

## A /proc/filesystems-shaped fixture: 'nodev'-prefixed lines are virtual /
## userspace filesystems (forgeable source), the rest are real block filesystems.
filesystems_fixture="${work_dir}/filesystems"
{
   printf 'nodev\t%s\n' 'sysfs'
   printf 'nodev\t%s\n' 'tmpfs'
   printf 'nodev\t%s\n' 'fuse'
   printf '\t%s\n' 'ext4'
   printf '\t%s\n' 'btrfs'
   printf '\t%s\n' 'xfs'
} > "${filesystems_fixture}"

stub_path_init
## sudo is the only external the --release mount path invokes here (the device
## loop needs real /dev/nbd* block devices, absent on the test host). Record its
## argv; the mount point rides in it.
stub_cmd sudo 0

run_rc=0
DM_NBD_CLEANUP_PROC_MOUNTINFO="${mountinfo_fixture}" \
   DM_NBD_CLEANUP_PROC_FILESYSTEMS="${filesystems_fixture}" \
   HELPER_SCRIPTS_PATH="${hs_path}" \
   "${subject}" --release >/dev/null 2>&1 || run_rc=$?
if [ "${run_rc}" -eq 0 ]; then
   pass "behavioral: dm-nbd-cleanup --release ran cleanly against the fixture"
else
   fail "behavioral: dm-nbd-cleanup --release exited ${run_rc} against the fixture"
fi

## Every real-nbd mount is unmounted -- the \040-encoded space (decoded) and the
## anonymous-superblock btrfs whose major is 0 but is genuinely nbd-backed.
for want in '/mnt/nbd-a' '/mnt/nbd b' '/mnt/nbd-c' '/mnt/nbd-btrfs' '/mnt/nbd-noopt' '/mnt/nbd-multiopt'; do
   if stub_called_with sudo umount -- "${want}"; then
      pass "behavioral: real-nbd mount '${want}' was unmounted"
   else
      fail "behavioral: real-nbd mount '${want}' was NOT unmounted (skipped or mis-decoded)"
   fi
done

## No non-nbd mount is unmounted -- ordinary device, tmpfs, the deputy spoof, and
## a same-prefix source name (/dev/nbd-backup, major 7) that is NOT an nbd device.
for unwanted in '/boot' '/mnt/plain-tmpfs' '/mnt/spoof' '/mnt/nbd-backup' '/mnt/nbd0-backup'; do
   if stub_not_called_with sudo umount -- "${unwanted}"; then
      pass "behavioral: non-nbd mount '${unwanted}' was left alone"
   else
      fail "behavioral: non-nbd mount '${unwanted}' was unmounted (major-key filtering broken)"
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
printf '%s\n' "OK: dm-nbd-cleanup keys on the nbd major and snapshots before unmounting (${pass_count} assertions)."
