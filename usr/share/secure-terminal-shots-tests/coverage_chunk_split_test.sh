#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression + CANARY for the secure-terminal coverage gate's chunk split. Two guarantees,
## both checked by SOURCING the runner's two pure helpers via BEGIN/END-EXTRACT sentinels (reads
## the current script text -> no drift; no suite/coverage run, no work dir, no env-var gate):
##
##   1. TMP-unbound: the chunk/combine work dir is "${TMP}/st-cov-...". TMP (a Windows
##      convention) is unset on the Linux CI runner, so under `set -o nounset` a bare ${TMP}
##      aborted every chunk at startup ("TMP: unbound variable") -- the exact bug that turned
##      all 6 secure-terminal coverage entries red on master. st_cov_shared_work_dir must now
##      tolerate an unset AND an empty TMP, rooting under /tmp either way.
##   2. Chunk partition: the 7 collect chunks (chunk1..chunk7) must partition the 24-suite set
##      the unsplit 'all' tier runs -- no suite dropped (silently shrinking the 100% gate) and
##      none duplicated (silently running a suite twice). The two NEW arms (chunk6 -> cov_qt5,
##      chunk7 -> cov_qt6) are pinned explicitly.
##
## FAILS on the pre-fix runner: an old/unsplit runner has neither sentinel-extracted helper.
##
## A pure function-extraction test (no coverage/PyQt6/checkout dependency), so it runs anywhere.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

runner=''
for cand in \
   "${SECURE_TERMINAL_TESTS_COVERAGE:-}" \
   "${script_dir}/../../bin/secure-terminal-tests-coverage" \
   '/usr/bin/secure-terminal-tests-coverage'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      runner="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${runner}" ]; then
   printf '%s\n' 'FATAL: secure-terminal-tests-coverage not found (set SECURE_TERMINAL_TESTS_COVERAGE)' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3 (got '$1', want '$2')"
      fail=$(( fail + 1 ))
   fi
}

## Extract a helper by sentinel. Absent -> an old runner (pre-split / pre-refactor): FAIL, so
## this is a genuine regression test, not a vacuous pass.
extract_fn() {  ## $1=function name -> writes ${work}/$1.sh; rc 1 if the sentinel/function is absent
   local name="$1" out="${work}/$1.sh"
   sed -n "/## BEGIN-EXTRACT ${name}/,/## END-EXTRACT ${name}/p" -- "${runner}" > "${out}"
   grep --quiet -- "${name}()" "${out}"
}
for fn in st_cov_resolve st_cov_shared_work_dir; do
   if ! extract_fn "${fn}"; then
      printf '%s\n' "FAIL: ${fn} not found in the runner -- old/unsplit runner or the fix is absent" \
         '' '0 pass, 1 fail, 0 skip'
      exit 1
   fi
done
resolve_fn="${work}/st_cov_resolve.sh"
workdir_fn="${work}/st_cov_shared_work_dir.sh"
# shellcheck disable=SC1090  # a runtime-extracted temp file has no static path to follow
source "${resolve_fn}"
# shellcheck disable=SC1090  # a runtime-extracted temp file has no static path to follow
source "${workdir_fn}"

## Resolve a tier's suite list. A subshell isolates st_cov_resolve's global writes AND its
## FATAL `exit` (an unknown tier must not kill this test). ST_COV_TIER is scoped to the subshell
## on purpose (SC2030/SC2031 note the deliberate isolation).
tier_suites() {  ## $1=tier -> stdout: space-separated suite list
   # shellcheck disable=SC2030,SC2031  # ST_COV_TIER is deliberately scoped to this subshell
   ( ST_COV_TIER="$1"; st_cov_resolve; printf '%s' "${suites[*]:-}" )
}

## Exit code of st_cov_resolve for a tier (subshell contains its FATAL exit).
tier_rc() {  ## $1=tier -> rc of st_cov_resolve
   local rc=0
   # shellcheck disable=SC2030,SC2031,SC2034  # ST_COV_TIER is read by the sourced st_cov_resolve
   ( ST_COV_TIER="$1"; st_cov_resolve ) >/dev/null 2>&1 || rc="$?"
   return "${rc}"
}

## ---- 1. TMP regression: unset OR empty TMP must root under /tmp, never abort or hit '/' -----
## The expected paths hardcode /tmp because that is exactly the fallback under test.
## style-ok: no-tmp-hardcode -- asserting the /tmp fallback literally is the point of this test.
tmp_unset="$( unset TMP ST_COV_SHARED_DIR GITHUB_RUN_ID GITHUB_RUN_ATTEMPT
   st_cov_shared_work_dir )"
check "${tmp_unset}" '/tmp/st-cov-local-0' 'an unset TMP falls back to /tmp (no nounset abort)'
tmp_empty="$(
   # shellcheck disable=SC2034  # TMP is consumed by the sourced st_cov_shared_work_dir
   TMP=''
   unset ST_COV_SHARED_DIR GITHUB_RUN_ID GITHUB_RUN_ATTEMPT
   st_cov_shared_work_dir )"
check "${tmp_empty}" '/tmp/st-cov-local-0' 'an empty TMP falls back to /tmp (not the filesystem root)'

## ---- 2a. the two NEW arms map to the expected suite sets ------------------------------------
check "$(tier_suites chunk6)" 'test_tabbar_polish test_core_fixes test_core_fixes_win' \
   'chunk6 -> cov_qt5 (tabbar_polish, core_fixes, core_fixes_win)'
check "$(tier_suites chunk7)" 'test_state_dump test_startup_winsize test_clipboard_watch' \
   'chunk7 -> cov_qt6 (state_dump, startup_winsize, clipboard_watch)'

## ---- 2b. chunk1..chunk7 PARTITION the full set: no drop, no duplicate -----------------------
union=''
for tier in chunk1 chunk2 chunk3 chunk4 chunk5 chunk6 chunk7; do
   union="${union} $(tier_suites "${tier}")"
done
read -r -a union_words <<< "${union}"
## Raw (NON-deduped) slot count catches a DUPLICATE (25) or a DROP (23) that a dedup would hide.
check "${#union_words[@]}" 24 'chunk1..chunk7 hold exactly 24 suite slots (no drop, no duplicate)'
## Explicit duplicate check: a suite in two chunks would run twice with no gate failure.
dups="$(printf '%s\n' "${union_words[@]}" | sort | uniq --repeated | paste --serial --delimiters=',' -)"
check "${dups}" '' 'no suite appears in more than one chunk'
## Set-equality catches a SUBSTITUTION that keeps the count (a wrong suite swapped in).
union_set="$(printf '%s\n' "${union_words[@]}" | sort --unique | paste --serial --delimiters=' ' -)"
all_set="$(tier_suites all | tr ' ' '\n' | sort --unique | paste --serial --delimiters=' ' -)"
check "${union_set}" "${all_set}" 'chunk1..chunk7 UNION == the unsplit "all" suite set'

## ---- 2c. an unknown tier is still FATAL (guards the case default + the range message) -------
bad_rc=0
tier_rc chunk8 || bad_rc="$?"
check "${bad_rc}" 1 'an unknown ST_COV_TIER (chunk8) is FATAL (exit 1)'

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: coverage work dir tolerates unset/empty TMP and chunk1..chunk7 partition the suite set'
