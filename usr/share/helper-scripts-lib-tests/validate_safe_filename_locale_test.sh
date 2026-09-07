#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh validate_safe_filename() must reject a non-ASCII (UTF-8) filename
## REGARDLESS of the caller's locale.
##
## THE BUG: the charset check used [[ =~ [:alnum:] ]] under the ambient locale.
## Under a UTF-8 locale [:alnum:] treats the bytes of 'cafe-with-accent' as
## letters and ACCEPTS the name, while a C locale REJECTS it -- a locale-
## dependent safe-filename gate. The fix pins LC_ALL=C inside the function so the
## value is validated as bytes.
##
## Sources the REAL strings.bsh and calls validate_safe_filename in a child shell
## under several locales. No raw non-ASCII in this source: the accented byte
## sequence is built with $'caf\xC3\xA9'. No root, no network.

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

## Locales to exercise. C.UTF-8 is always present; en_US.UTF-8 only if installed.
utf8_locales=( 'C.UTF-8' )
locales_available="$(locale -a 2>/dev/null || true)"
if grep --quiet --ignore-case -- '^en_US.utf' <<<"${locales_available}"; then
   utf8_locales+=( 'en_US.UTF-8' )
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Run validate_safe_filename on $2 under locale $1; echo the exit code.
vsf_probe='source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh" >/dev/null 2>&1; candidate="$1"; validate_safe_filename candidate >/dev/null 2>&1; printf "%s" "$?"'
vsf_rc() {
   LC_ALL="$1" HELPER_SCRIPTS_PATH="${helper_scripts_path}" /usr/bin/bash -c "${vsf_probe}" _ "$2"
}

unicode_name=$'caf\xC3\xA9'
safe_name='safe_file-name.txt'

for loc in "${utf8_locales[@]}" 'C'; do
   rc="$(vsf_rc "${loc}" "${unicode_name}")"
   if [ "${rc}" = '1' ]; then
      ok "rejects UTF-8 filename under locale ${loc}"
   else
      notok "accepted UTF-8 filename under locale ${loc} (rc=${rc}); locale-dependent gate"
   fi

   rc="$(vsf_rc "${loc}" "${safe_name}")"
   if [ "${rc}" = '0' ]; then
      ok "accepts a plain ASCII filename under locale ${loc}"
   else
      notok "rejected a plain ASCII filename under locale ${loc} (rc=${rc})"
   fi
done

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
