#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh: gpg_bash_lib_function_displaytime turns a seconds count into a
## human duration via '$(( ))' arithmetic.
##
## THE BUG: it validated the input with a plain whole-number check, which accepts
## a value larger than INT64_MAX; that value then WRAPS in the intmax_t '$(( ))'
## arithmetic and yields a garbage-but-plausible duration rather than the safe
## '0 seconds' fallback the function uses for non-numeric input. The fix bounds
## the magnitude (is_whole_number_int64) so an out-of-range value takes the same
## '0 seconds' fallback.
##
## Sources the REAL strings.bsh. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

tree_root="${HELPER_SCRIPTS_REPO:-${HELPER_SCRIPTS_PATH:-}}"
tree_root="${tree_root%/}"
strings_bsh="${tree_root}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO (or HELPER_SCRIPTS_PATH) to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

export HELPER_SCRIPTS_PATH="${tree_root}"

# shellcheck disable=SC1090,SC1091
source "${strings_bsh}"

if [ ! "$(type -t gpg_bash_lib_function_displaytime)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${strings_bsh}' defined no 'gpg_bash_lib_function_displaytime'" >&2
   exit 1
fi

pass_count=0
fail_count=0

check() {
   local description input expected actual
   description="$1"
   input="$2"
   expected="$3"
   actual="$(gpg_bash_lib_function_displaytime "${input}")"
   if [ "${actual}" = "${expected}" ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description} -- expected '${expected}', got '${actual}'" >&2
   fi
}

## The regression: a value above INT64_MAX must fall back to '0 seconds', not a
## wrapped-arithmetic garbage duration. Fails on the old code.
check 'a value above INT64_MAX falls back to 0 seconds' '99999999999999999999999' '0 seconds'
check 'an absurdly long integer falls back to 0 seconds' '999999999999999999999999999999999' '0 seconds'

## Sanity: in-range and non-numeric inputs are unchanged by the magnitude bound.
check 'a normal duration is unchanged' '500' '8 minutes 20 seconds'
check 'INT64_MAX-in-range large value still computes' '50000000' '1 years 213 days 16 hours 53 minutes 20 seconds'
check 'zero' '0' '0 seconds'
check 'non-numeric falls back to 0 seconds' 'not_a_number' '0 seconds'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
