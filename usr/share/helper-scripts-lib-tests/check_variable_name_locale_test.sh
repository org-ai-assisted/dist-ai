#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh's ASCII-only bash name validators must reject non-ASCII (UTF-8)
## input REGARDLESS of the caller's locale.
##
## THE BUG: a bare [[ =~ ^[A-Za-z_]... ]] bracket range is LOCALE-COLLATION
## dependent. Under a full-collation UTF-8 locale (en_US.utf8) glibc expands
## [A-Za-z] to include accented letters, so an accented value like 'cafe-with-
## accent' PASSES an ASCII-only gate, while a C locale REJECTS it. The fix pins
## LC_ALL=C inside each validator so the ranges are byte/ASCII-deterministic.
##
## Covers the whole class of strings.bsh letter-range name validators:
##   - check_variable_name             (the site fixed alongside this test)
##   - check_valid_linux_user_account_name
##   - check_is_alpha_numeric          (takes a VARIABLE NAME, checks its value)
##
## Sources the REAL strings.bsh and calls each validator in a child shell under
## several locales. No raw non-ASCII in this source: the accented byte sequence
## is built with $'caf\xC3\xA9'. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   repo="${HELPER_SCRIPTS_REPO}"
else
   repo=""
fi

strings_bsh="${repo:-}/usr/libexec/helper-scripts/strings.bsh"
[ -r "${strings_bsh}" ] || strings_bsh='/usr/libexec/helper-scripts/strings.bsh'

if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

helper_scripts_path="${HELPER_SCRIPTS_PATH:-${repo}}"

## Locales to exercise. C.UTF-8's minimal collation does NOT expand ranges, so
## it cannot bite the bug; a full-collation UTF-8 locale (en_US.UTF-8) is the
## only one that would ACCEPT the accented value on pre-fix code. Include it
## only when installed (a minimal CI image may lack it) -- the canary is a true
## regression gate where present and a benign assertion otherwise, never a skip
## of the whole suite.
utf8_locales=( 'C.UTF-8' )
locales_available="$(locale -a 2>/dev/null || true)"
if grep --quiet --ignore-case -- '^en_US.utf' <<<"${locales_available}"; then
   utf8_locales+=( 'en_US.UTF-8' )
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Source strings.bsh in a child shell under locale $1 and run the probe body
## $2 with the candidate string as its $1; echo the validator's exit code.
## The probe reads HELPER_SCRIPTS_PATH so strings.bsh can source its siblings.
run_probe() {
   local locale="$1" probe_body="$2" candidate="$3"
   local full_probe='source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh" >/dev/null 2>&1; '"${probe_body}"
   LC_ALL="${locale}" HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      /usr/bin/bash -c "${full_probe}" _ "${candidate}"
}

## Direct-argument validators: the candidate is passed straight to the function.
probe_cvn='check_variable_name "$1" >/dev/null 2>&1; printf "%s" "$?"'
probe_cvluan='check_valid_linux_user_account_name "$1" >/dev/null 2>&1; printf "%s" "$?"'
## check_is_alpha_numeric takes a VARIABLE NAME whose VALUE it validates, so the
## candidate is assigned to a variable and its name is passed.
probe_cian='probe_value="$1"; check_is_alpha_numeric probe_value >/dev/null 2>&1; printf "%s" "$?"'

unicode_value=$'caf\xC3\xA9'
ascii_name='valid_Name_1'
ascii_sysname='_sysuser'

## Each entry: <label> <probe> <ascii-accept-input>
validators=(
   "check_variable_name|${probe_cvn}|${ascii_name}"
   "check_valid_linux_user_account_name|${probe_cvluan}|${ascii_sysname}"
   "check_is_alpha_numeric|${probe_cian}|${ascii_name}"
)

for loc in "${utf8_locales[@]}" 'C'; do
   for entry in "${validators[@]}"; do
      label="${entry%%|*}"
      rest="${entry#*|}"
      probe="${rest%|*}"
      ascii_input="${rest##*|}"

      rc="$(run_probe "${loc}" "${probe}" "${unicode_value}")"
      if [ "${rc}" = '1' ]; then
         ok "${label}: rejects a non-ASCII value under locale ${loc}"
      else
         notok "${label}: accepted a non-ASCII value under locale ${loc} (rc=${rc}); locale-dependent gate"
      fi

      rc="$(run_probe "${loc}" "${probe}" "${ascii_input}")"
      if [ "${rc}" = '0' ]; then
         ok "${label}: accepts a plain ASCII value under locale ${loc}"
      else
         notok "${label}: rejected a plain ASCII value '${ascii_input}' under locale ${loc} (rc=${rc})"
      fi
   done
done

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
