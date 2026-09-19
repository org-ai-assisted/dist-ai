#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh: is_integer must accept a DECIMAL integer (optional leading minus),
## nothing else. A 'printf %d' implementation also accepted C integer literals --
## hex (0x1A) and octal (0100) -- which every caller (ip_syntax ports/octets,
## get_os versions, log_run_die timestamps) treats as malformed. The
## distinguishing cases from a printf-based check are exactly 0x.. and 0NN.
##
## Sources the INSTALLED strings.bsh by default; HELPER_SCRIPTS_REPO points it at
## a checkout, which is what the suite runner wires in CI. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   strings_sh_path="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/strings.bsh"
else
   strings_sh_path='/usr/libexec/helper-scripts/strings.bsh'
fi

if [ ! -r "${strings_sh_path}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_sh_path}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

## shellcheck resolves the file statically from dist-ai's own tree, which has no
## helper-scripts copy, so there is nothing to point 'source=' at.
# shellcheck disable=SC1090,SC1091
source "${strings_sh_path}"

if [ ! "$(type -t is_integer)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${strings_sh_path}' defined no 'is_integer' function" >&2
   exit 1
fi

pass_count=0
fail_count=0

check_ok() {
   if is_integer "$1"; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: accepts '$1'"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: expected '$1' accepted, was refused"
   fi
}
check_bad() {
   if is_integer "$1"; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: expected '$1' refused, was accepted"
   else
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: refuses '$1'"
   fi
}

## --- accepted: decimal integers, zero, and negatives ------------------------
check_ok '0'
check_ok '1'
check_ok '42'
check_ok '1000'
check_ok '-1'
check_ok '-42'

## --- refused: non-decimal forms, leading zeros, signs, whitespace, floats ---
check_bad '0x1A'
check_bad '0xff'
check_bad '0100'
check_bad '01'
check_bad '-0'
check_bad '+1'
check_bad '1.5'
check_bad ''
check_bad ' 3'
check_bad '3 '
check_bad 'abc'
check_bad '-'

## --- CANARY: hex/octal are the printf-differential the fix closes -----------
## A 'printf %d'-based is_integer accepts 0x1A (26) and 0100 (64); the decimal
## regex must reject both. If this function reverted to printf, these would pass.
if ! is_integer '0x1A' && ! is_integer '0100'; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: hex 0x1A and octal 0100 are rejected (a printf %d check would accept them)"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary: hex/octal accepted -- is_integer is parsing C integer literals, not decimal"
fi

printf '%s\n' ""
printf '%s\n' "===== is_integer: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
