#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## require-ext-type (help-steps/build-step-helpers.bsh, used by
## 4350_reimage-raw-reproducible) is the fail-closed guard before the partition is
## blkdiscard'd and rebuilt as ext4. It must ACCEPT ext2/ext3/ext4, REJECT any
## other type so a build that requested another filesystem is not SILENTLY
## reformatted, and REJECT an EMPTY type -- blkid prints nothing and exits
## non-zero when it cannot identify the filesystem, and the caller's '|| true'
## turns that into "", which must fail closed here.
##
## The real function is SOURCED and called directly; the canary redefines a
## non-empty-only form in a subshell. Needs no root, no blkid, no build.

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
lib="${dm_checkout}/help-steps/build-step-helpers.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FAIL: cannot read ${lib}" >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${lib}"

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

check_accept() {
   if require-ext-type "$1" >/dev/null 2>&1; then
      pass "accepts ext type '$1'"
   else
      fail "expected ext type '$1' accepted, was refused"
   fi
}
check_reject() {
   if require-ext-type "$1" >/dev/null 2>&1; then
      fail "expected non-ext type '$1' refused, was accepted"
   else
      pass "refuses non-ext type '$1'"
   fi
}

## --- accepted: the ext family ----------------------------------------------
check_accept ext2
check_accept ext3
check_accept ext4

## --- refused: other, near-miss, and empty ----------------------------------
check_reject xfs
check_reject btrfs
check_reject vfat
check_reject ext4dev
check_reject ''

## --- CANARY: the guard can actually reject ---------------------------------
## A form treating any non-empty type as ext would wrongly accept xfs; the ''
## case proves the blkid-failure path (|| true -> empty) fails closed.
buggy_accepts_xfs=no
buggy_refuses_empty=no
(
   require-ext-type() {
      [ -n "$1" ]
   }
   require-ext-type xfs
) && buggy_accepts_xfs=yes
(
   require-ext-type() {
      [ -n "$1" ]
   }
   require-ext-type ''
) || buggy_refuses_empty=yes
if [ "${buggy_accepts_xfs}" = "yes" ] && [ "${buggy_refuses_empty}" = "yes" ]; then
   pass 'canary: a non-empty-only guard would accept xfs (the real guard does not)'
else
   fail "canary broken: accepts_xfs=${buggy_accepts_xfs} refuses_empty=${buggy_refuses_empty}"
fi

summary_line="===== require-ext-type: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
