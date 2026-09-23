#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh's numeric validators must reject non-ASCII (Unicode) digits
## REGARDLESS of the caller's locale.
##
## THE BUG: a bare [[ =~ ^[0-9]... ]] bracket range is LOCALE dependent. Under a
## UTF-8 locale (e.g. en_US.utf8 -- the default on many Debian / CI hosts)
## glibc's [0-9] also matches Unicode digits such as Arabic-Indic (U+0661), so a
## Unicode-digit string PASSES the numeric check, while a C locale REJECTS it.
## Downstream that value hits bash arithmetic ('[ x -lt y ]', intmax_t), which
## errors 'integer expression expected' (exit 2); an enclosing 'if' swallows the
## exit-2 as false -- a validation FAIL-OPEN (read_integer_file would return it
## as validated). The fix pins LC_ALL=C inside each validator so [0-9] is
## byte/ASCII only.
##
## Covers the strings.bsh numeric-range validators:
##   - is_whole_number
##   - is_integer
##   - is_whole_number_int64          (used by read_integer_file)
##
## Whether [0-9] matches a Unicode digit is itself locale-dependent among UTF-8
## locales (en_US.utf8 does; some others do not). So this test does NOT assume
## any UTF-8 locale exposes the bug: it PROBES for a locale under which a bare
## [0-9] actually matches U+0661, and only asserts rejection there -- otherwise
## the bug cannot manifest and it skips. That keeps it from passing hollowly
## (false green) on a host whose UTF-8 locale does not exercise the vulnerable
## path.
##
## Sources the REAL strings.bsh and calls each validator in a child shell under
## the chosen locale. No raw non-ASCII in this source: the Unicode digit is
## built with $'\xd9\xa1' (U+0661 ARABIC-INDIC DIGIT ONE). No root, no network.

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

## U+0661 ARABIC-INDIC DIGIT ONE; a plain ASCII integer for the accept case.
unicode_digit=$'\xd9\xa1'
ascii_int='123'

## Source strings.bsh in a child shell under locale $1 and run probe body $2 with
## the candidate as its $1; echo the child's output. errexit is ON across the
## source (a broken source must abort here as a harness error, never a masked
## pass), then OFF for the probe body so a validator's 0/1 verdict is captured.
run_probe() {
   local locale="$1" probe_body="$2" candidate="$3"
   # shellcheck disable=SC2016
   local full_probe='set -e; source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh" >/dev/null 2>&1; set +e; '"${probe_body}"
   LC_ALL="${locale}" HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      /usr/bin/bash -c "${full_probe}" _ "${candidate}"
}

## Every validator under test must be DEFINED by the sourced library; a missing
## one is a FATAL misconfiguration (e.g. an is_whole_number_int64-less
## helper-scripts checkout), never silently absorbed as a per-case harness
## error. Mirrors the existence guard the sibling lib-tests use.
for fn in is_whole_number is_integer is_whole_number_int64; do
   # shellcheck disable=SC2016
   defined="$(run_probe C 'printf "%s" "$(type -t '"${fn}"')"' '')"
   if [ "${defined}" != 'function' ]; then
      printf '%s\n' "FATAL: sourcing '${strings_bsh}' defined no '${fn}' (got type '${defined}')" >&2
      printf '%s\n' "the numeric-validator locale canary cannot run against a tree missing it" >&2
      exit 1
   fi
done

## Find a UTF-8 locale under which a BARE (unpinned) [0-9] actually matches the
## Unicode digit -- i.e. one that can EXPOSE the bug. C / C.UTF-8 / POSIX never
## expand [0-9]; nor do some language UTF-8 locales. Probe each candidate rather
## than assume, so a rejection assertion is only made where a failure would be
## real signal.
expose_locale=""
while IFS= read -r loc; do
   case "${loc}" in
      C|C.*|POSIX|POSIX.*)
         continue
         ;;
      *.utf8|*.UTF-8|*.utf-8|*.UTF8)
         if LC_ALL="${loc}" /usr/bin/bash -c '[[ "$1" =~ ^[0-9]$ ]]' _ "${unicode_digit}" 2>/dev/null; then
            expose_locale="${loc}"
            break
         fi
         ;;
   esac
done < <(locale -a 2>/dev/null || true)

if [ -z "${expose_locale}" ]; then
   printf '%s\n' "SKIP: no UTF-8 locale under which [0-9] matches a Unicode digit; the locale fail-open cannot manifest here" >&2
   exit 77  ## style-ok: allow-skip: no bug-exposing UTF-8 locale installed; the collation fail-open cannot manifest
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

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

# shellcheck disable=SC2016
probe_iwn='is_whole_number "$1" >/dev/null 2>&1; printf "%s" "$?"'
# shellcheck disable=SC2016
probe_ii='is_integer "$1" >/dev/null 2>&1; printf "%s" "$?"'
# shellcheck disable=SC2016
probe_iwn64='is_whole_number_int64 "$1" >/dev/null 2>&1; printf "%s" "$?"'

## Each entry: <label> <probe>
validators=(
   "is_whole_number|${probe_iwn}"
   "is_integer|${probe_ii}"
   "is_whole_number_int64|${probe_iwn64}"
)

## The exposing locale bites the bug; C is byte-locale sanity (Unicode digit
## rejected, ASCII accepted) and is always present.
for loc in "${expose_locale}" 'C'; do
   for entry in "${validators[@]}"; do
      label="${entry%%|*}"
      probe="${entry#*|}"
      assert_rejects "${label}" "${loc}" "$(run_probe "${loc}" "${probe}" "${unicode_digit}")"
      assert_accepts "${label}" "${loc}" "$(run_probe "${loc}" "${probe}" "${ascii_int}")"
   done
done

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed (exposing locale: ${expose_locale})"
[ "${fail_count}" -eq 0 ]
