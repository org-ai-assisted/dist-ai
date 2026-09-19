#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## source_date_epoch_valid (variables.d/05_lib.bsh) is the canonical gate for the
## build-wide SOURCE_DATE_EPOCH -- resolved in variables.d (10_core.bsh from the
## changelog, 40_upload.bsh from the frozen pin) and consumed by debhelper,
## mmdebstrap and the reproducible image steps. It must ACCEPT a non-negative
## whole number within signed 64-bit range and REFUSE a leading-zero/sign/space
## value, an empty value, and -- the reason a digits-only check is insufficient --
## a value that overflows 64-bit (arithmetic downstream silently wraps: 2^64 -> 0
## -> a 1970 build).
##
## The real function is SOURCED (05_lib.bsh + the strings.bsh is_whole_number it
## reuses); the canary shows is_whole_number alone accepts an overflowing value.

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

## strings.bsh (is_whole_number) sourced as the build does it; it sources its own
## siblings via HELPER_SCRIPTS_PATH, so export it before sourcing.
: "${HELPER_SCRIPTS_PATH:=${dm_checkout}/packages/kicksecure/helper-scripts}"
export HELPER_SCRIPTS_PATH
strings_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh"
if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not found at '${strings_bsh}' (needed for is_whole_number)." >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${strings_bsh}"

lib="${dm_checkout}/variables.d/05_lib.bsh"
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

check_valid() {
   if source_date_epoch_valid "$1"; then
      pass "accepts '$1'"
   else
      fail "expected '$1' accepted, was refused"
   fi
}
check_invalid() {
   if source_date_epoch_valid "$1"; then
      fail "expected '$1' refused, was accepted"
   else
      pass "refuses '$1'"
   fi
}

## --- accepted: non-negative whole numbers in range -------------------------
check_valid 0
check_valid 1700000000
check_valid 9223372036854775807

## --- refused: format and range ---------------------------------------------
check_invalid ''
check_invalid abc
check_invalid -5
check_invalid 5.5
check_invalid '1 700'
## leading zeros (is_whole_number rejects them)
check_invalid 08
check_invalid 0100
## 64-bit overflow: digits-only but silently wraps in arithmetic
check_invalid 9223372036854775808
check_invalid 18446744073709551616
check_invalid 99999999999999999999

## --- CANARY: the range check is load-bearing -------------------------------
## is_whole_number (the format check we reuse) ACCEPTS an overflowing value; a
## gate relying on format alone would let it through and build a 1970 image.
nan_ok=no
if is_whole_number 18446744073709551616 ; then
   nan_ok=yes
fi
if [ "${nan_ok}" = "yes" ] && ! source_date_epoch_valid 18446744073709551616 ; then
   pass 'canary: is_whole_number accepts 2^64; the range check is what refuses it'
else
   fail "canary broken: is_whole_number accepts 2^64 = ${nan_ok}"
fi

summary_line="===== source_date_epoch_valid: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
