#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh's numeric validators must reject non-ASCII (Unicode) digits
## REGARDLESS of the caller's locale.
##
## THE BUG: a bare [[ =~ ^[0-9]... ]] bracket range is LOCALE dependent. Under a
## UTF-8 locale (en_US.utf8 -- the default on Debian / CI) glibc's [0-9] also
## matches Unicode digits such as Arabic-Indic (U+0661), so a Unicode-digit
## string PASSES the numeric check, while a C locale REJECTS it. Downstream that
## value hits bash arithmetic ('[ x -lt y ]', intmax_t), which errors 'integer
## expression expected' (exit 2); an enclosing 'if' swallows the exit-2 as false
## -- a validation FAIL-OPEN (read_integer_file would return it as validated).
## The fix pins LC_ALL=C inside each validator so [0-9] is byte/ASCII only.
##
## Covers the strings.bsh numeric-range validators:
##   - is_whole_number
##   - is_integer
##   - is_whole_number_int64          (used by read_integer_file)
##
## Sources the REAL strings.bsh and calls each validator in a child shell under
## several locales. No raw non-ASCII in this source: the Unicode digit is built
## with $'\xd9\xa1' (U+0661 ARABIC-INDIC DIGIT ONE). No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

## Single source of truth for the tree under test: HELPER_SCRIPTS_REPO, else
## HELPER_SCRIPTS_PATH, else '' (the installed /usr/libexec tree). A named
## checkout that lacks strings.bsh is a FATAL misconfiguration, never a silent
## fallback to a different tree.
tree_root="${HELPER_SCRIPTS_REPO:-${HELPER_SCRIPTS_PATH:-}}"
tree_root="${tree_root%/}"
strings_bsh="${tree_root}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO (or HELPER_SCRIPTS_PATH) to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
helper_scripts_path="${tree_root}"

## The bug needs a full-collation UTF-8 locale to appear; C / C.UTF-8 / POSIX do
## NOT expand [0-9], so they cannot expose it. Pick the FIRST such locale by its
## EXACT 'locale -a' name (used verbatim as LC_ALL, so glibc actually activates
## it). Any language is fine.
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
   printf '%s\n' "SKIP: no full-collation UTF-8 locale installed; locale canary not exercised" >&2
   exit 77  ## style-ok: allow-skip: no full-collation UTF-8 locale; the collation bug cannot manifest
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Source strings.bsh in a child shell under locale $1 and run probe body $2 with
## the candidate as its $1; echo the validator's exit code. errexit is ON across
## the source (a broken source must abort here as a harness error, never a masked
## pass), then OFF for the validator call so its 0/1 verdict is captured.
run_probe() {
   local locale="$1" probe_body="$2" candidate="$3"
   local full_probe='set -e; source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh" >/dev/null 2>&1; set +e; '"${probe_body}"
   LC_ALL="${locale}" HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      /usr/bin/bash -c "${full_probe}" _ "${candidate}"
}

## A validator returns 0 (accept) or 1 (reject); ANY other value (or empty, when
## the source aborted) means it was never invoked -- a HARNESS error, NOT a
## verdict -- so a broken environment is never mistaken for the regression.
assert_rejects() {
   local label="$1" loc="$2" rc="$3"
   case "${rc}" in
      1)
         ok "${label}: rejects a Unicode digit under locale ${loc}"
         ;;
      0)
         notok "${label}: accepted a Unicode digit under locale ${loc}; locale-dependent numeric gate (fail-open)"
         ;;
      *)
         notok "${label}: HARNESS ERROR under ${loc}: validator not invoked (rc='${rc}'); check the tree under test"
         ;;
   esac
}
assert_accepts() {
   local label="$1" loc="$2" rc="$3"
   case "${rc}" in
      0)
         ok "${label}: accepts a plain ASCII integer under locale ${loc}"
         ;;
      1)
         notok "${label}: rejected a plain ASCII integer under locale ${loc}"
         ;;
      *)
         notok "${label}: HARNESS ERROR under ${loc}: validator not invoked (rc='${rc}'); check the tree under test"
         ;;
   esac
}

probe_iwn='is_whole_number "$1" >/dev/null 2>&1; printf "%s" "$?"'
probe_ii='is_integer "$1" >/dev/null 2>&1; printf "%s" "$?"'
probe_iwn64='is_whole_number_int64 "$1" >/dev/null 2>&1; printf "%s" "$?"'

## U+0661 ARABIC-INDIC DIGIT ONE; a plain ASCII integer for the accept case.
unicode_digit=$'\xd9\xa1'
ascii_int='123'

## Each entry: <label> <probe>
validators=(
   "is_whole_number|${probe_iwn}"
   "is_integer|${probe_ii}"
   "is_whole_number_int64|${probe_iwn64}"
)

## The full-collation locale bites the bug; C is byte-locale sanity (Unicode
## digit rejected, ASCII accepted) and is always present.
for loc in "${full_collation_locale}" 'C'; do
   for entry in "${validators[@]}"; do
      label="${entry%%|*}"
      probe="${entry#*|}"
      assert_rejects "${label}" "${loc}" "$(run_probe "${loc}" "${probe}" "${unicode_digit}")"
      assert_accepts "${label}" "${loc}" "$(run_probe "${loc}" "${probe}" "${ascii_int}")"
   done
done

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed (full-collation locale: ${full_collation_locale})"
[ "${fail_count}" -eq 0 ]
