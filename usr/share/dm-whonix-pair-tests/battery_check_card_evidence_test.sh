#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## A PASSING per-check story card must carry the reviewer's evidence: WHAT command ran and WHAT it
## produced -- not a bare "PASS". Canary: the pre-fix wp_story_check pass branch emitted body="PASS"
## with no command and no output, so a human reviewer reading "Release check 4: networking (pass) /
## PASS" could not tell what ran or what the result was. The executor now records the ACTUAL command
## (post lane-substitution) + a bounded output tail into RELEASE_CHECK_LAST_*, and wp_story_check
## embeds them. Drives the REAL dm-whonix-pair wp_story_check + the REAL story_card writer (define-
## only source, no VM/root/network).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${DM_WHONIX_PAIR_BIN:-${here}/../../bin/dm-whonix-pair}"
[ -x "${tool}" ] || { printf '%s\n' "FATAL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
assert() {
   local label="$1"
   shift
   if "$@"; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label}"
   fi
}

work="$(mktemp --directory --tmpdir dm-whonix-pair-check-card.XXXXXX)"
# shellcheck disable=SC2317  ## invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## The sole card for a given check (wp_story_check emits exactly one per call).
card_for() { find "${shot_dir}" -maxdepth 1 -name "*check${1}-*.card.txt" 2>/dev/null | head -n 1; }
## Succeed when <pattern> is ABSENT from <file> (for the negative assertions below).
grep_absent() { ! grep --quiet --fixed-strings -- "$1" "$2"; }

## --- a PASS card carries the ACTUAL command + an output tail (not a bare "PASS") ----------------
shot_dir="${work}/pass"
mkdir --parents -- "${shot_dir}"
## Simulate the executor having recorded this check's evidence (as run_check / the CLI executors do).
release_check_set_evidence 'systemcheck --verbose --leak-tests' \
   "$(printf '%s\n' 'Tor socket: reachable' 'systemcheck result: all tests passed')"
wp_story_check pass 4
card="$(card_for 4)"
assert "a passing check emits exactly one card" test -n "${card}"
assert "the PASS card is NOT a bare 'PASS' (carries the command)" \
   grep --quiet --fixed-strings 'command: systemcheck --verbose --leak-tests' "${card}"
assert "the PASS card carries the check's actual output (what the result was)" \
   grep --quiet --fixed-strings 'systemcheck result: all tests passed' "${card}"
assert "the PASS card labels the output section for a reviewer" \
   grep --quiet --fixed-strings 'check output (last lines)' "${card}"
## The exact black-box the user flagged: a 'pass' body that is ONLY the word PASS, nothing else.
assert "the PASS card body is more than the bare word PASS" \
   test "$(grep --count . "${card}")" -gt 4

## --- a lane-SUBSTITUTED command is shown verbatim (never a misattributed static table value) ----
shot_dir="${work}/substituted"
mkdir --parents -- "${shot_dir}"
## check 3 under --local-repo runs apt-get full-upgrade, not upgrade-nonroot: the card must show the
## command the executor ACTUALLY recorded, so the reviewer is not misled by the static table value.
release_check_set_evidence 'dsudo apt-get -o Dir::Etc::sourceparts=- --update full-upgrade --yes' \
   'Calculating upgrade... 0 upgraded, 0 newly installed'
wp_story_check pass 3
card="$(card_for 3)"
assert "a substituted check shows the REAL command run (apt-get full-upgrade)" \
   grep --quiet --fixed-strings 'command: dsudo apt-get' "${card}"
assert "the substituted check does NOT claim upgrade-nonroot" \
   grep_absent 'command: upgrade-nonroot' "${card}"

## --- no recorded evidence (GA-less OCR pass) -> command/PASS only, never a fabricated result -----
shot_dir="${work}/no-evidence"
mkdir --parents -- "${shot_dir}"
release_check_set_evidence '' ''
wp_story_check pass 5
card="$(card_for 5)"
assert "an evidence-less pass still emits a card" test -n "${card}"
assert "an evidence-less pass shows PASS without a fabricated output section" \
   grep_absent 'check output (last lines)' "${card}"

## --- a ROUTED card never inherits a prior check's command/output --------------------------------
shot_dir="${work}/routed"
mkdir --parents -- "${shot_dir}"
## Leave stale evidence set from a prior pass; the routed branch must not surface it.
release_check_set_evidence 'systemcheck --verbose' 'stale output from a prior check'
RELEASE_CHECK_SKIP_REASON[2]='no sysmaint session over this gate'
wp_story_check routed 2
card="$(card_for 2)"
assert "a routed card states it was not run (ROUTED)" \
   grep --quiet --fixed-strings 'ROUTED' "${card}"
assert "a routed card does NOT leak the prior check's stale output" \
   grep_absent 'stale output from a prior check' "${card}"

## --- a FAIL card still carries its failure reason (unchanged behavior) --------------------------
shot_dir="${work}/fail"
mkdir --parents -- "${shot_dir}"
RELEASE_CHECK_FAILED_REASON='networking (functional, rc=5)'
check_log=''
wp_story_check fail 4
card="$(card_for 4)"
assert "a fail card carries the failure reason" \
   grep --quiet --fixed-strings 'FAILED: networking (functional, rc=5)' "${card}"

## --- the local-build verify card's OK-line extraction must NOT abort the whole run -------------
## Canary: pre-fix, `build_matches="$(... | grep '^OK: ' | ...)"` ran under errexit+pipefail, so a
## verify output with NO 'OK: ' line at column 0 (a single-package run, or a first OK line glued to
## prior no-newline apt output) made grep exit 1 and ABORTED ws_func_verify_local_repo_installed
## before its own ${build_matches:-...} fallback could card the match. Drive the REAL function with a
## stubbed gc_run returning OK-less-but-successful output; it must return 0 and card the fallback.
shot_dir="${work}/verify-no-ok"
mkdir --parents -- "${shot_dir}"
## Observe whether the REAL function aborts under production strict mode via a separate process
## (verify_installed_abort_subject.sh): an errexit abort cannot be seen from inside this shell
## (it would kill the test, or be masked by the errexit-off `if`/`||` context). The `if` captures
## the child's real exit while the child keeps its own errexit live.
verify_rc=0
if bash "${here}/verify_installed_abort_subject.sh" "${tool}" "${shot_dir}"; then
   verify_rc=0
else
   verify_rc=$?
fi
assert "an OK-less (single-package/glued) verify output does NOT abort the run" \
   test "${verify_rc}" -eq 0
verify_card="$(find "${shot_dir}" -maxdepth 1 -name '*local-build-installed*.card.txt' 2>/dev/null | head -n 1)"
assert "the local-build card is still written (fallback), not lost to an abort" test -n "${verify_card}"
assert "the card falls back gracefully when no per-package lines parsed" \
   grep --quiet --fixed-strings 'per-package lines not captured' "${verify_card}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
