#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The fail-closed filesystem-type guard in build-steps.d/4350_reimage-raw-reproducible
## runs before the partition is blkdiscard'd and rebuilt as ext4. It must ACCEPT
## ext4 only and REJECT any other type -- including an EMPTY type: blkid prints
## nothing and exits non-zero when it cannot identify the filesystem, and the
## caller's '|| true' turns that into "", which must fail closed here so a build
## that requested another filesystem is not SILENTLY reformatted.
##
## The guard is an INLINE block (not a function), so this test EXTRACTS the real
## block from the script and evaluates it with a stubbed 'blkid', exercising the
## actual shipped lines. Needs no root, no blkid, no build.

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

reimage_script=""
for candidate in "${DM_REIMAGE_SCRIPT:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/build-steps.d/4350_reimage-raw-reproducible" \
   "${dm_checkout}/build-steps.d/4350_reimage-raw-reproducible"; do
   case "${candidate}" in
      ''|'/build-steps.d/4350_reimage-raw-reproducible')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      reimage_script="${candidate}"
      break
   fi
done
if [ -z "${reimage_script}" ]; then
   printf '%s\n' "FATAL: 4350_reimage-raw-reproducible not found (set DM_REIMAGE_SCRIPT)." >&2
   exit 1
fi

## Extract the real fail-closed guard: from its comment to the closing 'fi'.
guard_block="$(sed -n '/## Fail closed on a non-ext4 root\./,/^   fi/p' -- "${reimage_script}")"
if [ -z "${guard_block}" ]; then
   printf '%s\n' "FATAL: could not extract the ext4 fail-closed guard from ${reimage_script}." >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## Run the extracted guard with 'blkid' stubbed to report ${STUB_FS_TYPE}. The
## guard reads the TYPE into fs_type via '${SUDO_TO_ROOT} blkid ... || true' and
## returns non-zero unless it is exactly 'ext4'.
run_guard() {
   ## dev_mapper_device + fs_type are written/read by the eval'd guard block below,
   ## which shellcheck does not parse.
   # shellcheck disable=SC2034
   local dev_mapper_device=/dev/stub fs_type
   # shellcheck disable=SC2034  # emptied so 'blkid' resolves to the stub function
   local SUDO_TO_ROOT=""
   # shellcheck disable=SC2317  # invoked indirectly by the eval'd guard block
   blkid() { printf '%s\n' "${STUB_FS_TYPE}"; }
   # shellcheck disable=SC1090
   eval "${guard_block}"
}

check_accept() {
   STUB_FS_TYPE="$1"
   if run_guard >/dev/null 2>&1; then
      pass "accepts filesystem type '$1'"
   else
      fail "expected filesystem type '$1' accepted, was refused"
   fi
}
check_reject() {
   STUB_FS_TYPE="$1"
   if run_guard >/dev/null 2>&1; then
      fail "expected non-ext4 type '$1' refused, was accepted (silent reformat)"
   else
      pass "refuses non-ext4 type '$1'"
   fi
}

## --- accepted: ext4 only ---------------------------------------------------
check_accept ext4

## --- refused: every other type, near-miss, and empty -----------------------
## ext2/ext3 are no longer accepted -- the reimage rebuilds an ext4 root and the
## guard is deliberately narrowed to ext4.
check_reject ext2
check_reject ext3
check_reject xfs
check_reject btrfs
check_reject vfat
check_reject ext4dev
check_reject ''

## --- CANARY: the guard can actually reject ---------------------------------
## A form treating any non-empty type as acceptable would wrongly accept xfs; the
## '' case proves the blkid-failure path (|| true -> empty) fails closed.
buggy_accepts_xfs=no
buggy_refuses_empty=no
(
   fs_guard() { [ -n "$1" ]; }
   fs_guard xfs
) && buggy_accepts_xfs=yes
(
   fs_guard() { [ -n "$1" ]; }
   fs_guard ''
) || buggy_refuses_empty=yes
if [ "${buggy_accepts_xfs}" = "yes" ] && [ "${buggy_refuses_empty}" = "yes" ]; then
   pass 'canary: a non-empty-only guard would accept xfs (the real ext4-only guard does not)'
else
   fail "canary broken: accepts_xfs=${buggy_accepts_xfs} refuses_empty=${buggy_refuses_empty}"
fi

summary_line="===== reimage ext4 fail-closed guard: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
