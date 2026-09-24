#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-nbd-cleanup mount-release.
##
## THE BUG IT GUARDS: /proc/mounts is a live kernel file. A loop that unmounts
## INSIDE 'while read ... < /proc/mounts' reads a file that mutates under it -- the
## read offset lands in regenerated content and later entries are silently SKIPPED.
## A skipped nbd mount then survives while the device loop disconnects its device,
## recreating the stale EIO half-state this tool exists to clear. Measured in a
## user+mount namespace with 200 mounts: unmount-in-loop processed 101 (99 skipped);
## snapshot-then-unmount processed all 200. THE FIX: collect ALL nbd mount points
## first (read the mounts file to completion into an array), THEN unmount from that
## snapshot.
##
## This test is TWO layers:
##  (1) BEHAVIORAL -- drive the REAL tool (--release) against a mounts FIXTURE
##      (DM_NBD_CLEANUP_PROC_MOUNTS) with sudo stubbed on PATH, and assert on the
##      RECORDED umount invocations: every nbd mount (including a \040-encoded one)
##      is unmounted, and no non-nbd mount is. Teeth for parsing, decoding,
##      filtering, argument handling and crash-safety.
##  (2) STRUCTURAL BACKSTOP -- the read-while-mutate SKIP is a /proc-specific
##      artifact that only reproduces under real mount namespaces (a regular-file
##      fixture cannot: an open fd pins the inode), out of scope for this rootless
##      suite. So guard the fix by its stable shape: the tool collects into an
##      nbd_mount_points snapshot array and iterates THAT for unmounting. This is a
##      pattern-presence check, not a brittle line-number ordering parse.
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
for candidate in "${DM_NBD_CLEANUP:-}" \
   "${DEVELOPER_META_FILES_DIR:-}/usr/bin/dm-nbd-cleanup" \
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

## --- (1) BEHAVIORAL: drive the real tool against a mounts fixture ------------
work_dir="$(mktemp --directory)"
cleanup_handler() {
   stub_path_cleanup
   safe-rm --recursive --force -- "${work_dir}" || true
}
trap cleanup_handler EXIT

## A /proc/mounts-shaped fixture: nbd mounts (one with a \040-encoded space) that
## MUST be unmounted, interleaved with non-nbd mounts that must NOT be.
mounts_fixture="${work_dir}/mounts"
{
   printf '%s\n' '/dev/nbd0 /mnt/nbd-a ext4 rw,relatime 0 0'
   printf '%s\n' '/dev/sda1 /boot ext4 rw,relatime 0 0'
   printf '%s\n' '/dev/nbd1 /mnt/nbd\040b ext4 rw,relatime 0 0'
   printf '%s\n' 'tmpfs /mnt/plain-tmpfs tmpfs rw 0 0'
   printf '%s\n' '/dev/nbd2 /mnt/nbd-c ext4 rw,relatime 0 0'
} > "${mounts_fixture}"

stub_path_init
## sudo is the only external the --release mount path invokes here (the device
## loop needs real /dev/nbd* block devices, absent on the test host). Record its
## argv; the mount point rides in it.
stub_cmd sudo 0

run_rc=0
DM_NBD_CLEANUP_PROC_MOUNTS="${mounts_fixture}" HELPER_SCRIPTS_PATH="${hs_path}" \
   "${subject}" --release >/dev/null 2>&1 || run_rc=$?
if [ "${run_rc}" -eq 0 ]; then
   pass "behavioral: dm-nbd-cleanup --release ran cleanly against the fixture"
else
   fail "behavioral: dm-nbd-cleanup --release exited ${run_rc} against the fixture"
fi

## Every nbd mount is unmounted -- including the \040-encoded space, decoded.
for want in '/mnt/nbd-a' '/mnt/nbd b' '/mnt/nbd-c'; do
   if stub_called_with sudo umount -- "${want}"; then
      pass "behavioral: nbd mount '${want}' was unmounted"
   else
      fail "behavioral: nbd mount '${want}' was NOT unmounted (skipped or mis-decoded)"
   fi
done

## No non-nbd mount is unmounted (device-name filtering).
for unwanted in '/boot' '/mnt/plain-tmpfs'; do
   if stub_not_called_with sudo umount -- "${unwanted}"; then
      pass "behavioral: non-nbd mount '${unwanted}' was left alone"
   else
      fail "behavioral: non-nbd mount '${unwanted}' was unmounted (filtering broken)"
   fi
done

## --- (2) STRUCTURAL BACKSTOP: the snapshot-array shape (read-order guard) -----
## Robust pattern-presence, not a line-number ordering parse: a regression to
## unmount-inside-the-read-loop would drop this collect-then-iterate shape.
# shellcheck disable=SC2016  # literal fixture text, not an expansion in this script
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
printf '%s\n' "OK: dm-nbd-cleanup snapshots the mounts before unmounting (${pass_count} assertions)."
