#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression + CANARY for the secure-terminal coverage gate's chunk split. Two guarantees:
##
##   1. TMP-unbound: the chunk/combine work dir is "${TMP}/st-cov-...". TMP (a Windows
##      convention) is unset on the Linux CI runner, so under `set -o nounset` a bare ${TMP}
##      aborted every chunk at startup ("line NNN: TMP: unbound variable") -- the exact bug
##      that turned all 6 secure-terminal coverage entries red on master. A chunk must now
##      start cleanly with TMP unset.
##   2. Chunk membership: the 7 collect chunks (chunk1..chunk7) must partition the same suite
##      set the un-split 'all' tier runs -- no suite dropped (silently shrinking the 100% gate)
##      or duplicated. The two NEW arms (chunk6 -> cov_qt5, chunk7 -> cov_qt6) are pinned
##      explicitly.
##
## Drives the REAL runner via its ST_COV_DRYRUN path (resolves the tier's suites, then exits 0
## WITHOUT running any suite or coverage), so this is fast and needs no Qt/compositor.
##
## FAILS on the pre-fix runner: with TMP unset the DRYRUN call aborts at the work= line (no
## TMP init), and an old runner has neither ST_COV_DRYRUN nor the chunk6/chunk7 arms.
##
## Subject: usr/bin/secure-terminal-tests-coverage. Needs importable coverage + a secure_terminal
## checkout (the DRYRUN path runs the runner's real dep/gated-glob preflight); absent -> exit 1
## (FATAL): a required subject/dep is an environment bug (R-220), never a silent skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## style-ok: allow-python-interpreter -- python3 -c dep probe

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
if ! python3 -c 'import coverage' 2>/dev/null; then
   printf '%s\n' 'FATAL: python3 coverage not importable' >&2
   exit 1
fi

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

## Resolve a tier's suite list via the runner's DRYRUN path. Echoes the space-separated list
## (array order preserved). Returns the runner's rc so a caller can assert startup success.
dryrun_suites() {  ## $1=tier -> stdout: suite list; rc: runner rc
   local out rc=0
   out="$(ST_COV_DRYRUN=1 ST_COV_TIER="$1" "${runner}" 2>/dev/null)" || rc="$?"
   ## The DRYRUN line ends with "suites=<list>"; strip everything up to it.
   printf '%s' "${out##*suites=}"
   return "${rc}"
}

## Order-independent word-set normaliser (sorted, space-joined) for the union invariant.
sort_words() {  ## $1=space-separated words -> stdout: sorted, deduped, space-joined
   # shellcheck disable=SC2086  # deliberate word-split of the suite list (names have no glob/space)
   printf '%s\n' ${1} | sort --unique | paste --serial --delimiters=' ' -
}

## ---- preflight: the 'all' DRYRUN must succeed, or the environment (coverage / ST checkout)
## is broken and every membership check below would be meaningless. FATAL, not a skip. --------
all_rc=0
all_suites="$(dryrun_suites all)" || all_rc="$?"
if [ "${all_rc}" != '0' ]; then
   printf '%s\n' "FATAL: coverage runner DRYRUN failed for tier 'all' (rc ${all_rc}); a secure_terminal checkout + python3-coverage are required" >&2
   exit 1
fi

## ---- 1. TMP-unbound canary: a chunk must start cleanly with TMP unset ---------------------
## env -u TMP -u ST_COV_SHARED_DIR forces the work= branch that expands ${TMP}. On the pre-fix
## runner this aborts (rc != 0) at the work= line; with the fix (`[ -v TMP ] || TMP=/tmp`) the
## DRYRUN reaches its clean exit 0.
tmp_rc=0
env -u TMP -u ST_COV_SHARED_DIR ST_COV_DRYRUN=1 ST_COV_TIER=chunk1 "${runner}" \
   >/dev/null 2>&1 || tmp_rc="$?"
check "${tmp_rc}" 0 'a chunk starts cleanly with TMP unset (no nounset abort at the work= line)'

## ---- 2a. the two NEW arms map to the expected suite sets ----------------------------------
check "$(dryrun_suites chunk6)" 'test_tabbar_polish test_core_fixes test_core_fixes_win' \
   'chunk6 -> cov_qt5 (tabbar_polish, core_fixes, core_fixes_win)'
check "$(dryrun_suites chunk7)" 'test_state_dump test_startup_winsize test_clipboard_watch' \
   'chunk7 -> cov_qt6 (state_dump, startup_winsize, clipboard_watch)'

## ---- 2b. union invariant: chunk1..chunk7 partition == the 'all' tier's suite set ----------
union=''
for tier in chunk1 chunk2 chunk3 chunk4 chunk5 chunk6 chunk7; do
   union="${union} $(dryrun_suites "${tier}")"
done
union_sorted="$(sort_words "${union}")"
all_sorted="$(sort_words "${all_suites}")"
check "${union_sorted}" "${all_sorted}" \
   'chunk1..chunk7 UNION == the unsplit "all" suite set (no suite dropped or duplicated)'
## The un-split gate ran 24 suites; pin the count so a future edit that drops one is caught even
## if it happens to still equal a (wrongly) shrunk 'all'.
read -r -a all_words <<< "${all_sorted}"
check "${#all_words[@]}" 24 'the coverage gate spans exactly 24 suites'

## ---- 2c. an unknown tier is still FATAL (guards the case default + the range message) ------
bad_rc=0
ST_COV_DRYRUN=1 ST_COV_TIER=chunk8 "${runner}" >/dev/null 2>&1 || bad_rc="$?"
check "${bad_rc}" 1 'an unknown ST_COV_TIER (chunk8) is FATAL (exit 1)'

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: coverage chunk split tolerates unset TMP and partitions the full suite set'
