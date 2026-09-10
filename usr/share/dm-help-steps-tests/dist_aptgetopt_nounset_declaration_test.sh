#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the DIST_APTGETOPT nounset-safety guard in
## help-steps/variables.
##
## THE TRAP IT GUARDS: 'variables' runs under 'set -o nounset', and later code
## (the pbuilder APTGETOPT passthrough block) evaluates '${#DIST_APTGETOPT[@]}'.
## On a fully-UNSET array that expansion is not 0 -- it ABORTS with
## "DIST_APTGETOPT: unbound variable". The array is populated only by
## 'aptgetopt_add', whose call sites are all conditional (APPROX_PROXY_ENABLE,
## dist_build_unsafe_io, dist_build_apt_freshness, and buildconfig.d/*.conf). A
## build that trips none of them (e.g. APPROX_PROXY_ENABLE=no with buildconfig.d
## sourcing bypassed) reaches the '${#...[@]}' use with the array never declared
## and crashes on a non-local invariant. Declaring the array up front removes the
## landmine; using '[ -v ]' must NOT clobber a caller-pre-populated array.
##
## Reads the CURRENT help-steps/variables text (no copy, no drift): checks the
## declaration exists, precedes every consumer, and functionally behaves.
##
## No root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

variables_file="${dm_checkout}/help-steps/variables"
if [ ! -r "${variables_file}" ]; then
   printf '%s\n' "FATAL: help-steps/variables not found at '${variables_file}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

## An ACTIVE (uncommented) array declaration -- the first non-'#', non-blank
## token on the line, so a commented-out '#DIST_APTGETOPT=()' does NOT count
## (that commented form is exactly the regression this test catches).
decl_lineno="$(grep -nE '^[[:space:]]*[^#[:space:]].*\bDIST_APTGETOPT=\(\)' -- "${variables_file}" | head -1 | cut -d: -f1 || true)"

if [ -n "${decl_lineno}" ]; then
   pass "help-steps/variables actively declares 'DIST_APTGETOPT=()' (line ${decl_lineno})"
else
   fail "no active 'DIST_APTGETOPT=()' declaration -- a commented-out declaration reintroduces the nounset 'unbound variable' abort"
fi

## The declaration must precede every '${#DIST_APTGETOPT[@]}' consumer, or the
## consumer can still run on an undeclared array.
first_consumer="$(grep -nF '${#DIST_APTGETOPT[@]}' -- "${variables_file}" | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 | cut -d: -f1 || true)"

if [ -z "${first_consumer}" ]; then
   ## No consumer today -> the invariant is not currently exercised. Not a
   ## failure, but surfaced so a silent removal is visible.
   pass "no '\${#DIST_APTGETOPT[@]}' consumer present (invariant not exercised)"
elif [ -n "${decl_lineno}" ] && [ "${decl_lineno}" -lt "${first_consumer}" ]; then
   pass "declaration (line ${decl_lineno}) precedes first '\${#DIST_APTGETOPT[@]}' consumer (line ${first_consumer})"
else
   fail "declaration (line ${decl_lineno:-none}) does not precede first '\${#DIST_APTGETOPT[@]}' consumer (line ${first_consumer})"
fi

## Functional: drive the EXACT declaration statement from the file under
## 'set -o nounset'. On an unset array it must make '${#DIST_APTGETOPT[@]}' safe
## (report empty, not crash); on a pre-populated array it must preserve it.
if [ -n "${decl_lineno}" ]; then
   decl_text="$(sed -n "${decl_lineno}p" -- "${variables_file}")"

   unset_rc=0
   unset_result="$(bash -c 'set -o nounset; '"${decl_text}"'; if [ "${#DIST_APTGETOPT[@]}" -gt 0 ]; then echo NONEMPTY; else echo EMPTY; fi' 2>&1)" || unset_rc="$?"
   if [ "${unset_rc}" = "0" ] && [ "${unset_result}" = "EMPTY" ]; then
      pass "unset array: declaration prevents the nounset abort ('\${#DIST_APTGETOPT[@]}' -> empty)"
   else
      fail "unset array: rc=${unset_rc} result='${unset_result}' (expected rc=0, EMPTY)"
   fi

   prepop_result="$(bash -c 'set -o nounset; DIST_APTGETOPT=(-o Acquire::Foo=bar); '"${decl_text}"'; printf "%s" "${#DIST_APTGETOPT[@]}"' 2>&1)" || prepop_result="ERROR"
   if [ "${prepop_result}" = "2" ]; then
      pass "pre-populated array preserved by the declaration (count=2)"
   else
      fail "declaration clobbered a caller-pre-populated array (count='${prepop_result}', expected 2)"
   fi
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: DIST_APTGETOPT is declared nounset-safe and preserves pre-population."
