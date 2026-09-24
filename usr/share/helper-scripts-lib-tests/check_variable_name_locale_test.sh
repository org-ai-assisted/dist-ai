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

## Single source of truth for the tree under test: HELPER_SCRIPTS_REPO, else
## HELPER_SCRIPTS_PATH, else '' (the installed /usr/libexec tree). BOTH the
## readability check and the child's source path derive from this one value, so
## they can never diverge: a named checkout that lacks strings.bsh is a FATAL
## misconfiguration, never a silent fallback that would test the installed copy
## (or a second path) instead of the artifact the caller asked for.
tree_root="${HELPER_SCRIPTS_REPO:-${HELPER_SCRIPTS_PATH:-}}"
tree_root="${tree_root%/}"
strings_bsh="${tree_root}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO (or HELPER_SCRIPTS_PATH) to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
helper_scripts_path="${tree_root}"

## A real language locale with a UTF-8 charmap has full ISO 14651 collation that
## expands [A-Za-z] to accented letters; C / C.UTF-8 / POSIX do NOT, so they
## cannot expose the bug. Pick the FIRST such locale by its EXACT 'locale -a'
## name (used verbatim as LC_ALL, so glibc actually activates it -- a synthesized
## name might not exist). Any language is fine (fr_FR, de_DE, ...), not a fixed
## shortlist.
full_collation_locale=""
while IFS= read -r loc; do
   case "${loc}" in
      C|C.*|POSIX|POSIX.*)
         continue
         ;;
      *.utf8|*.UTF-8|*.utf-8|*.UTF8)
         full_collation_locale="${loc}"
         break
         ;;
   esac
done < <(locale -a 2>/dev/null || true)

if [ -z "${full_collation_locale}" ]; then
   ## The bug needs a full-collation UTF-8 locale to appear at all; with none
   ## installed there is nothing to exercise, so skip rather than pass hollowly
   ## on C-only assertions that never reach the vulnerable code path.
   printf '%s\n' "SKIP: no full-collation UTF-8 locale installed; locale-collation canary not exercised" >&2
   exit 77  ## style-ok: allow-skip: no full-collation UTF-8 locale; the collation bug cannot manifest
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Source strings.bsh in a child shell under locale $1 and run the probe body
## $2 with the candidate string as its $1; echo the validator's exit code.
## errexit is ON across the source (a caller sources strings.bsh under strict
## mode, so a broken source -- e.g. a missing sibling -- must ABORT here too,
## surfacing as a harness error rather than a silently-masked pass), then OFF
## for the validator call so its 0/1 verdict is captured, not aborted on.
run_probe() {
   local locale="$1" probe_body="$2" candidate="$3"
   # shellcheck disable=SC2016  # single-quoted bash -c payload; $... expands in the inner shell
   local full_probe='set -e; source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh" >/dev/null 2>&1; set +e; '"${probe_body}"
   LC_ALL="${locale}" HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      /usr/bin/bash -c "${full_probe}" _ "${candidate}"
}

## Judge a validator's exit code. A validator returns 0 (accept) or 1 (reject);
## ANY other value (or empty, when the source aborted) means it was never
## invoked -- a HARNESS error (bad tree / missing dependency), NOT a locale
## verdict -- so a broken environment is never mistaken for the regression.
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
         notok "${label}: HARNESS ERROR under ${loc}: validator not invoked (rc='${rc}'); check the tree under test"
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
         notok "${label}: HARNESS ERROR under ${loc}: validator not invoked (rc='${rc}'); check the tree under test"
         ;;
   esac
}

## Direct-argument validators: the candidate is passed straight to the function.
# shellcheck disable=SC2016  # single-quoted probe body; $1/$? expand in the inner shell
probe_cvn='check_variable_name "$1" >/dev/null 2>&1; printf "%s" "$?"'
# shellcheck disable=SC2016  # single-quoted probe body; $1/$? expand in the inner shell
probe_cvluan='check_valid_linux_user_account_name "$1" >/dev/null 2>&1; printf "%s" "$?"'
## check_is_alpha_numeric takes a VARIABLE NAME whose VALUE it validates, so the
## candidate is assigned to a variable and its name is passed.
# shellcheck disable=SC2016  # single-quoted probe body; $1/$? expand in the inner shell
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

## The full-collation locale is the one that bites the bug; C is byte-locale
## sanity (accented bytes rejected, ASCII accepted) and is always present.
for loc in "${full_collation_locale}" 'C'; do
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
