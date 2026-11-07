#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- standalone test; does not source helper-scripts.

## Behavioral regression for the single-site gate in usr/bin/website-tests and its fronts
## (website-tests-single / website-tests-all). site-deploy publishes exactly one site, so it gates
## exactly that site -- an unrelated sibling-site regression must not block the publish. The site
## is selected EXPLICITLY (--site <name> / website-tests-single <name>), never via an ambient env
## filter, so a stray sibling _REPO in the environment can neither widen nor abort the run.
##
## Drives the REAL selection path: SOURCE the runner (its guard returns before the suite, leaving
## add_site/add_site_sel defined) and call the real add_site_sel; NO function-body extraction.
## Asserts:
##  - no selector (requested_site empty) adds every site (full family run unchanged);
##  - a selector adds ONLY the matching site and records the match (site_requested);
##  - a NON-matching sibling is dropped even with a non-empty _REPO override (no ambient leak,
##    no abort -- the footgun of an env-filter design);
##  - the two fronts dispatch to the engine (website-tests-single passes --site; -all does not);
##  - website-tests-single rejects wrong argument counts.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
bindir="${test_dir}/../../bin"
runner="${bindir}/website-tests"
[ -r "${runner}" ] || runner='/usr/bin/website-tests'
single="${bindir}/website-tests-single"
[ -x "${single}" ] || single='/usr/bin/website-tests-single'
all_front="${bindir}/website-tests-all"
[ -x "${all_front}" ] || all_front='/usr/bin/website-tests-all'
for f in "${runner}" "${single}" "${all_front}"; do
   if [ ! -r "${f}" ]; then
      printf '%s\n' "FATAL: not found: ${f}" >&2
      exit 1
   fi
done

## A real-looking site checkout so add_root accepts the given path (has index.html).
fixture="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${fixture}"; }
trap cleanup EXIT
touch "${fixture}/index.html"

## Source the runner: its source-able guard returns before the suite body, leaving add_root /
## add_site / add_site_sel defined. Set the globals they read (the execution body that normally
## sets them is below the guard, so it did not run).
# shellcheck disable=SC1090
source "${runner}"
## (read by the sourced add_site/add_root; shellcheck cannot see the cross-function use)
# shellcheck disable=SC2034
home_unset=''
# shellcheck disable=SC2034
WEBSITE_TESTS_SKIP_SITES=''

## 1. No selector: every site is added (the full family run is unchanged).
## (requested_site is read by the sourced add_site_sel; shellcheck cannot see the cross-function use)
# shellcheck disable=SC2034
requested_site=''
site_requested=''
roots=(); root_sites=()
add_site_sel output-lies.github.io "${fixture}" "${fixture}"
add_site_sel org-ai-assisted.github.io "${fixture}" "${fixture}"
if [ "${#roots[@]}" -eq 2 ]; then
   pass 'no selector adds every site (full family run unchanged)'
else
   fail "all-mode: expected 2 roots, got ${#roots[@]} (${root_sites[*]:-})"
fi

## 2. Selector matches: only that site is added, and the match is recorded (site_requested).
# shellcheck disable=SC2034  ## read by the sourced add_site_sel (cross-function)
requested_site='org-ai-assisted.github.io'
site_requested=''
roots=(); root_sites=()
add_site_sel org-ai-assisted.github.io "${fixture}" "${fixture}"
if [ "${#roots[@]}" -eq 1 ] && [ "${root_sites[0]}" = 'org-ai-assisted.github.io' ] && [ "${site_requested}" = 'yes' ]; then
   pass 'selector adds only the matching site and records the match'
else
   fail "single-match: roots=${#roots[@]} root_sites=(${root_sites[*]:-}) site_requested='${site_requested}'"
fi

## 3. A non-matching sibling is dropped even with a non-empty _REPO override -- the ambient-leak
## footgun of an env-filter design does not exist here: an explicit sibling override cannot widen
## the single-site run nor abort it.
# shellcheck disable=SC2034  ## read by the sourced add_site_sel (cross-function)
requested_site='org-ai-assisted.github.io'
site_requested=''
roots=(); root_sites=()
add_site_sel output-lies.github.io "${fixture}" "${fixture}"
if [ "${#roots[@]}" -eq 0 ] && [ "${#root_sites[@]}" -eq 0 ] && [ -z "${site_requested}" ]; then
   pass 'a non-matching sibling with a non-empty override is dropped (no ambient leak, no abort)'
else
   fail "single-drop: roots=${#roots[@]} root_sites=(${root_sites[*]:-}) site_requested='${site_requested}'"
fi

## 4. The fronts dispatch to the engine: -single passes --site, -all does not. Literal source text
## to grep for, not shell to expand -- single quotes are intentional.
# shellcheck disable=SC2016
if grep --quiet --fixed-strings '"${engine}" --site "$1"' "${single}"; then
   pass 'website-tests-single dispatches to the engine with --site'
else
   fail 'website-tests-single does not run the engine with --site'
fi
# shellcheck disable=SC2016
if grep --quiet --extended-regexp '"\$\{engine\}"$' "${all_front}"; then
   pass 'website-tests-all dispatches to the engine with no selector (full family)'
else
   fail 'website-tests-all does not run the engine without a selector'
fi

## 5. website-tests-single rejects a wrong argument count (usage, before any engine run).
none_rc=0
"${single}" >/dev/null 2>&1 || none_rc=$?
two_rc=0
"${single}" a b >/dev/null 2>&1 || two_rc=$?
if [ "${none_rc}" -eq 64 ] && [ "${two_rc}" -eq 64 ]; then
   pass 'website-tests-single rejects 0 or 2 arguments (usage, exit 64)'
else
   fail "single-usage: expected 64/64, got none=${none_rc} two=${two_rc}"
fi

## 6. The engine rejects a malformed selector (exit 64) BEFORE any run, never a silent fall-through
## to the full family gate: an empty --site value, a bare --site=, an unknown flag, and a stray
## operand after -- must all be hard errors (the documented single-site contract).
empty_space_rc=0
"${runner}" --site '' >/dev/null 2>&1 || empty_space_rc=$?
empty_eq_rc=0
"${runner}" --site= >/dev/null 2>&1 || empty_eq_rc=$?
unknown_rc=0
"${runner}" --bogus >/dev/null 2>&1 || unknown_rc=$?
operand_rc=0
"${runner}" -- org-ai-assisted.github.io >/dev/null 2>&1 || operand_rc=$?
if [ "${empty_space_rc}" -eq 64 ] && [ "${empty_eq_rc}" -eq 64 ] \
      && [ "${unknown_rc}" -eq 64 ] && [ "${operand_rc}" -eq 64 ]; then
   pass 'engine rejects empty/bare/unknown/operand selectors with exit 64 (no silent family fall-through)'
else
   fail "arg-contract: want 64 for all, got empty-space=${empty_space_rc} empty-eq=${empty_eq_rc} unknown=${unknown_rc} operand=${operand_rc}"
fi

printf '%s\n' "" "test_website_tests_single: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
