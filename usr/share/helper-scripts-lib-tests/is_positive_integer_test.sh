#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh: is_positive_integer is is_whole_number PLUS a zero reject, so a
## caller that needs '>= 1' (e.g. derivative-maker --package-jobs) does not have
## to bolt a separate '!= 0' check onto every call site. The distinguishing case
## from is_whole_number is exactly the literal '0'.
##
## Sources the INSTALLED strings.bsh by default; HELPER_SCRIPTS_REPO points it at
## a checkout, which is what the suite runner wires in CI where nothing is
## installed. No root, no network.

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

if [ ! "$(type -t is_positive_integer)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${strings_sh_path}' defined no 'is_positive_integer' function" >&2
   exit 1
fi

pass_count=0
fail_count=0

check_ok() {
   if is_positive_integer "$1"; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: accepts '$1'"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: expected '$1' accepted, was refused"
   fi
}
check_bad() {
   if is_positive_integer "$1"; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: expected '$1' refused, was accepted"
   else
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: refuses '$1'"
   fi
}

## --- accepted: positive integers -------------------------------------------
check_ok '1'
check_ok '42'
check_ok '1000'

## --- refused: zero, plus everything is_whole_number already rejects ---------
check_bad '0'
check_bad '01'
check_bad '-1'
check_bad '-5'
check_bad 'abc'
check_bad ''
check_bad '3 '
check_bad ' 3'
check_bad '1.5'

## --- CANARY: the zero reject is what separates it from is_whole_number ------
## is_whole_number accepts 0; is_positive_integer must not. If this function
## were a bare alias of is_whole_number, this case would wrongly pass.
if is_whole_number '0' && ! is_positive_integer '0'; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: is_whole_number accepts 0 but is_positive_integer rejects it"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary: is_positive_integer did not reject 0 that is_whole_number accepts"
fi

printf '%s\n' ""
printf '%s\n' "===== is_positive_integer: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
