#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## usr/libexec/tor-ctrl/pad.bsh -- the column padding behind the relay tables in
## tor-ctrl-circuit and tor-ctrl-stream.
##
## These exist because R-030 forbids a computed printf width, so the padding is
## hand-rolled and has to reproduce printf's semantics itself. The case that
## matters is the one that is easy to get wrong: a value LONGER than the field is
## printed in FULL, never truncated. Widening a column is cosmetic; silently
## cutting a relay fingerprint in half is not, and it would look like a shorter
## fingerprint rather than like a bug.
##
## No tor, no network, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TOR_CTRL_REPO ] || TOR_CTRL_REPO=""
if [ -n "${TOR_CTRL_REPO}" ]; then
   pad_lib="${TOR_CTRL_REPO}/usr/libexec/tor-ctrl/pad.bsh"
else
   pad_lib="/usr/libexec/tor-ctrl/pad.bsh"
fi

if [ ! -r "${pad_lib}" ]; then
   printf '%s\n' "FATAL: pad.bsh not found at '${pad_lib}'" >&2
   printf '%s\n' "set TOR_CTRL_REPO to a tor-ctrl checkout, or install the package" >&2
   exit 1
fi

# shellcheck disable=SC1090
source "${pad_lib}"

failures=0
checks=0

check() {
   local label="${1}"
   local expected="${2}"
   local actual="${3}"
   checks=$(( checks + 1 ))
   if [ "${expected}" = "${actual}" ]; then
      printf '%s\n' "PASS  ${label}"
   else
      failures=$(( failures + 1 ))
      printf '%s\n' "FAIL  ${label}: expected '${expected}', got '${actual}'"
   fi
}

## Compared against printf itself rather than against a hand-written literal, so
## the assertion cannot drift from the semantics it claims to reproduce.
check_matches_printf_right() {
   local text="${1}"
   local width="${2}"
   check "pad_right '${text}' ${width} matches %-${width}s" \
      "$(printf "%-${width}s" "${text}")" "$(pad_right "${text}" "${width}")"
}

check_matches_printf_left() {
   local text="${1}"
   local width="${2}"
   check "pad_left '${text}' ${width} matches %${width}s" \
      "$(printf "%${width}s" "${text}")" "$(pad_left "${text}" "${width}")"
}

check_matches_printf_right 'abc' 6
check_matches_printf_right 'abc' 3
check_matches_printf_right '' 4
check_matches_printf_left 'abc' 6
check_matches_printf_left 'abc' 3
check_matches_printf_left '' 4

## The truncation guard, stated explicitly rather than only via printf: a value
## wider than the field must come back whole.
long_value='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
check "pad_right does not truncate an over-long value" "${long_value}" "$(pad_right "${long_value}" 5)"
check "pad_left does not truncate an over-long value" "${long_value}" "$(pad_left "${long_value}" 5)"

## Exact widths, so a change to the padding character or count is caught even if
## printf itself were somehow wrong.
check "pad_right pads on the RIGHT" 'ab   ' "$(pad_right 'ab' 5)"
check "pad_left pads on the LEFT" '   ab' "$(pad_left 'ab' 5)"
check "pad_right width 0 returns the value" 'ab' "$(pad_right 'ab' 0)"
check "pad_left width 0 returns the value" 'ab' "$(pad_left 'ab' 0)"

## A field width matching a real relay fingerprint (40) is the actual call site.
fingerprint='0123456789ABCDEF0123456789ABCDEF01234567'
check "40-char fingerprint is unpadded at width 40" "${fingerprint}" "$(pad_right "${fingerprint}" 40)"

printf '%s\n' "" "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
