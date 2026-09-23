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

## Derive HELPER_SCRIPTS_PATH from the SAME strings.bsh that passed the
## readability check above, so the child shell sources the very file this test
## verified exists (strip the well-known suffix -> '' when strings_bsh fell back
## to the installed /usr/libexec tree). An explicit HELPER_SCRIPTS_PATH wins.
## Without this, a HELPER_SCRIPTS_REPO pointing at a checkout that lacks the
## tree passes the check via the installed fallback yet the child sources a
## nonexistent path -> every probe returns 127 and is misreported as a locale
## verdict.
if [ -n "${HELPER_SCRIPTS_PATH:-}" ]; then
   helper_scripts_path="${HELPER_SCRIPTS_PATH}"
else
   helper_scripts_path="${strings_bsh%/usr/libexec/helper-scripts/strings.bsh}"
fi

## The [A-Za-z] collation bug can only manifest under a full-collation UTF-8
## locale; C.UTF-8's minimal collation does NOT expand ranges. Find one; the
## canary is a real regression gate ONLY when such a locale is installed.
full_collation_locale=""
locales_available="$(locale -a 2>/dev/null || true)"
for cand in en_US.UTF-8 en_US.utf8 de_DE.UTF-8; do
   if grep --quiet --ignore-case --line-regexp -- "${cand//UTF-8/utf8}" <<<"${locales_available}"; then
      full_collation_locale="${cand}"
      break
   fi
done

if [ -z "${full_collation_locale}" ]; then
   ## The bug needs a full-collation UTF-8 locale to appear at all; with none
   ## installed there is nothing to exercise, so skip rather than pass hollowly
   ## on C-only assertions that never reach the vulnerable code path.
   printf '%s\n' "SKIP: no full-collation UTF-8 locale (en_US.UTF-8 / de_DE.UTF-8) installed; locale-collation canary not exercised" >&2
   exit 77  ## style-ok: allow-skip: no full-collation UTF-8 locale; the collation bug cannot manifest
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

## Judge a validator's exit code. A validator returns 0 (accept) or 1 (reject);
## ANY other code means it was never invoked (e.g. 127 = source failed / function
## undefined), which is a HARNESS error, NOT a locale verdict -- report it as
## such so a broken environment is never mistaken for the collation regression.
assert_rejects() {
   local label="$1" loc="$2" rc="$3"
   case "${rc}" in
      1)
         ok "${label}: rejects a non-ASCII value under locale ${loc}"
         ;;
      0)
         notok "${label}: accepted a non-ASCII value under locale ${loc}; locale-dependent gate"
         ;;
      *)
         notok "${label}: HARNESS ERROR under ${loc}: validator not invoked (rc=${rc}); check HELPER_SCRIPTS_PATH"
         ;;
   esac
}
assert_accepts() {
   local label="$1" loc="$2" rc="$3" input="$4"
   case "${rc}" in
      0)
         ok "${label}: accepts a plain ASCII value under locale ${loc}"
         ;;
      1)
         notok "${label}: rejected a plain ASCII value '${input}' under locale ${loc}"
         ;;
      *)
         notok "${label}: HARNESS ERROR under ${loc}: validator not invoked (rc=${rc}); check HELPER_SCRIPTS_PATH"
         ;;
   esac
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

## The full-collation locale is the one that bites the bug; C.UTF-8 and C are
## byte-locale sanity (accented bytes rejected, ASCII accepted) under a
## minimal collation.
for loc in "${full_collation_locale}" 'C.UTF-8' 'C'; do
   for entry in "${validators[@]}"; do
      label="${entry%%|*}"
      rest="${entry#*|}"
      probe="${rest%|*}"
      ascii_input="${rest##*|}"

      assert_rejects "${label}" "${loc}" "$(run_probe "${loc}" "${probe}" "${unicode_value}")"
      assert_accepts "${label}" "${loc}" "$(run_probe "${loc}" "${probe}" "${ascii_input}")" "${ascii_input}"
   done
done

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed (full-collation locale: ${full_collation_locale})"
[ "${fail_count}" -eq 0 ]
