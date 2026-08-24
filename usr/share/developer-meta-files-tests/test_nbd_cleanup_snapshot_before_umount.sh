#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-nbd-cleanup mount-release order.
##
## THE BUG IT GUARDS: /proc/mounts is a live kernel file. A loop that unmounts
## INSIDE 'while read ... < /proc/mounts' reads a file that shrinks under it --
## the read offset lands in regenerated content and later entries are silently
## SKIPPED. A skipped nbd mount then survives while the device loop disconnects
## its device, recreating the stale EIO half-state this tool exists to clear.
## Measured in a user+mount namespace with 200 mounts: unmount-in-loop processed
## 101 (99 skipped); snapshot-then-unmount processed all 200.
##
## THE INVARIANT: collect ALL nbd mount points first (into an array, read to
## completion), THEN unmount from that snapshot -- so no 'umount' may appear at or
## before the line that closes the '< /proc/mounts' collection loop.
##
## Structural, because a faithful behavioural repro needs root + mount namespaces
## (out of scope for a host suite test); this asserts the exact ordering that the
## namespace measurement showed is required. FAILS on the pre-fix tool, whose
## umount sat inside the /proc/mounts read loop.
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

## The line closing the collection loop that reads /proc/mounts.
collect_done_line="$( grep --line-number --extended-regexp -- '^done < /proc/mounts$' "${subject}" | head --lines=1 | cut --delimiter=: --fields=1 )"
## The first umount action.
first_umount_line="$( grep --line-number --fixed-strings -- 'umount' "${subject}" | head --lines=1 | cut --delimiter=: --fields=1 )"

## --- 1. the collection loop reads /proc/mounts and closes cleanly ------------
if [ -n "${collect_done_line}" ]; then
   pass "a '/proc/mounts' collection loop closes with 'done < /proc/mounts'"
else
   fail "no 'done < /proc/mounts' collection loop found (pre-fix tool reads it while unmounting)"
fi

## --- 2. CANARY: the tool actually unmounts (ordering check is not vacuous) ---
if [ -n "${first_umount_line}" ]; then
   pass "canary: the tool contains a umount call"
else
   fail "canary broken: no umount call found; the ordering assertion would be vacuous"
fi

## --- 3. no umount at or before the collection loop closes -------------------
## This is the whole fix: unmount only AFTER /proc/mounts has been fully read.
if [ -n "${collect_done_line}" ] && [ -n "${first_umount_line}" ]; then
   if [ "${first_umount_line}" -gt "${collect_done_line}" ]; then
      pass "unmount happens only AFTER the /proc/mounts snapshot is complete (line ${first_umount_line} > ${collect_done_line})"
   else
      fail "umount at line ${first_umount_line} is inside/before the /proc/mounts read (closes at ${collect_done_line}); entries can be skipped"
   fi
fi

## --- 4. the unmount iterates the snapshot array ----------------------------
if grep --quiet --extended-regexp -- '^\s*nbd_mount_points=\(\)' "${subject}" \
   && grep --quiet --fixed-strings -- 'for mount_point in "${nbd_mount_points[@]}"' "${subject}"; then
   pass "unmount iterates the collected 'nbd_mount_points' snapshot"
else
   fail "no 'nbd_mount_points' snapshot array iterated for unmounting"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-nbd-cleanup snapshots /proc/mounts before unmounting (${pass_count} assertions)."
