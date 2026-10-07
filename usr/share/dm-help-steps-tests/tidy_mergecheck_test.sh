#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-tidy's phase 6 (upstream+trixie mergeability of master) -- the
## read-only, informational check that answers, in-sweep, the dm-mergable-test question:
## can org-ai-assisted master merge once upstream has absorbed arraybolt3/trixie?
##
## WHAT IT GUARDS -- the cry-wolf-avoidance classification, which is the whole point:
##   CLEAN  -> master merges into (upstream+trixie)                     -> "ok ... can merge"
##   BENIGN -> master conflicts, but ONLY because it lacks trixie in its ancestry while ai
##             absorbed trixie AND master's non-gitlink content mirrors ai                 -> "ok (benign ancestry artifact ...)"
##   WARN   -> master conflicts and it is NOT that benign shape (ai has not absorbed trixie)
##                                                                      -> "WARN ... NOT cleanly mergeable"
##   skipped -> a required remote/ref is absent (no network/fixture)    -> "skipped (...)"
## Plus: the phase is INFORMATIONAL -- even a WARN leaves dm-tidy's exit code 0 on an
## otherwise-clean run (it must not turn a benign, by-design state into a failure).
##
## It drives the REAL mergecheck (phases 1-5 stubbed to no-op) against crafted upstream /
## trixie / fork bares, so the real merge-tree + ancestry + content logic is exercised.
## DM_TIDY_BIN points the suite at a deliberately-broken dm-tidy for the canary.

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
test_failures=0

dist_ai_bin="$(cd -- "${test_dir}/../../bin" && pwd)"
tool="${DM_TIDY_BIN:-${dist_ai_bin}/dm-tidy}"
[ -x "${tool}" ] || { printf 'FATAL: dm-tidy not found/executable at %s\n' "${tool}" >&2 ; exit 1 ; }

export GIT_AUTHOR_NAME="test" GIT_AUTHOR_EMAIL="test@example.invalid"
export GIT_COMMITTER_NAME="test" GIT_COMMITTER_EMAIL="test@example.invalid"

workspace="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workspace}"; }
trap cleanup EXIT
export HOME="${workspace}/home"
mkdir --parents -- "${HOME}" "${workspace}/nohooks"

gitq() { git -c core.hooksPath="${workspace}/nohooks" -c protocol.file.allow=always "$@"; }

## no-op stub for phases 0-5: exit 0, ignore args; mergecheck (phase 6) stays REAL.
noop="${workspace}/noop"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${noop}"
chmod +x -- "${noop}"
export DM_TIDY_REMOTES_ENSURE="${noop}" DM_TIDY_SUBMODULE_SYNC="${noop}" \
   DM_TIDY_REMASTER_ALL="${noop}" DM_TIDY_GIT_SYNC="${noop}" DM_TIDY_FSCK="${noop}"

## --- Bares: github-kicksecure (U), ArrayBolt3 (A), org-ai-assisted (O) -----------
U="${workspace}/U.git" ; A="${workspace}/A.git" ; O="${workspace}/O.git"
for b in "${U}" "${A}" "${O}"; do gitq init --quiet --bare -- "${b}"; done

## Author every commit in one scratch repo, then push the refs each bare needs.
sc="${workspace}/scratch"
gitq init --quiet -- "${sc}"
gitq -C "${sc}" checkout --quiet -b base
mkdir --parents -- "${sc}/build-steps.d" "${sc}/help-steps"
printf 'x\n' > "${sc}/build-steps.d/keep" ; printf 'x\n' > "${sc}/help-steps/keep"
printf 'base\n' > "${sc}/shared"
gitq -C "${sc}" add --all ; gitq -C "${sc}" commit --quiet -m base
B="$(gitq -C "${sc}" rev-parse HEAD)"
## upstream master: adds fileU, leaves 'shared' -- disjoint from trixie, so they combine clean.
gitq -C "${sc}" checkout --quiet -b upb "${B}"
printf 'u\n' > "${sc}/fileU" ; gitq -C "${sc}" add fileU ; gitq -C "${sc}" commit --quiet -m up
UP="$(gitq -C "${sc}" rev-parse HEAD)"
## arraybolt3/trixie: changes 'shared' -- this is what master will conflict with in combined.
gitq -C "${sc}" checkout --quiet -b trxb "${B}"
printf 'trx\n' > "${sc}/shared" ; gitq -C "${sc}" commit --quiet -am trx
TRX="$(gitq -C "${sc}" rev-parse HEAD)"
## ours 'master' variants from base.
gitq -C "${sc}" checkout --quiet -b m_clean "${B}"     ## adds fileM only -> merges clean with combined
printf 'm\n' > "${sc}/fileM" ; gitq -C "${sc}" add fileM ; gitq -C "${sc}" commit --quiet -m m_clean
M_CLEAN="$(gitq -C "${sc}" rev-parse HEAD)"
gitq -C "${sc}" checkout --quiet -b m_ours "${B}"      ## changes 'shared' -> conflicts with combined
printf 'ours\n' > "${sc}/shared" ; gitq -C "${sc}" commit --quiet -am m_ours
M_OURS="$(gitq -C "${sc}" rev-parse HEAD)"
## benign ai: master's TREE with TRX as a second parent (trixie absorbed; content == master).
AI_BENIGN="$(gitq -C "${sc}" commit-tree "${M_OURS}^{tree}" -p "${M_OURS}" -p "${TRX}" -m ai-absorbed-trixie)"

gitq -C "${sc}" push --quiet "${U}" "${UP}:refs/heads/master"
gitq -C "${sc}" push --quiet "${A}" "${TRX}:refs/heads/arraybolt3/trixie"

## --- Fixture super: dm-shaped, on 'ai', all three remotes ------------------------
super="${HOME}/derivative-maker"
gitq init --quiet -- "${super}"
gitq -C "${super}" checkout --quiet -b ai
mkdir --parents -- "${super}/build-steps.d" "${super}/help-steps"
printf 'x\n' > "${super}/build-steps.d/keep" ; printf 'x\n' > "${super}/help-steps/keep"
gitq -C "${super}" add --all ; gitq -C "${super}" commit --quiet -m "super base"
gitq -C "${super}" remote add github-kicksecure "file://${U}"
gitq -C "${super}" remote add ArrayBolt3 "file://${A}"
gitq -C "${super}" remote add org-ai-assisted "file://${O}"

## Run dm-tidy (dry-run) and echo the phase-6 verdict text from the summary table.
mergecheck_verdict() {
   "${tool}" --dry-run --dir "${super}" 2>/dev/null \
      | sed -n 's/^  6 mergecheck  *//p' | head -1
}
## Publish the scenario's master + ai to O, then read the verdict.
verdict_for() {   ## $1 master-sha $2 ai-sha
   gitq -C "${sc}" push --quiet --force "${O}" "$1:refs/heads/master" "$2:refs/heads/ai"
   mergecheck_verdict
}

## --- Case: CLEAN ----------------------------------------------------------------
v="$(verdict_for "${M_CLEAN}" "${M_CLEAN}")"
case "${v}" in
   ok\ \(upstream+trixie\ can\ merge\ master\)* )
      pass "CLEAN -> ${v}"
      ;;
   * )
      fail "CLEAN: expected 'ok ... can merge master', got '${v}'"
      ;;
esac

## --- Case: BENIGN (master conflicts; ai absorbed trixie; content mirrored) ------
v="$(verdict_for "${M_OURS}" "${AI_BENIGN}")"
case "${v}" in
   ok\ \(benign\ ancestry\ artifact* )
      pass "BENIGN -> ${v}"
      ;;
   * )
      fail "BENIGN: expected 'ok (benign ancestry artifact ...)', got '${v}'"
      ;;
esac

## --- Case: WARN (master conflicts; ai did NOT absorb trixie) --------------------
v="$(verdict_for "${M_OURS}" "${M_OURS}")"
case "${v}" in
   WARN\ * )
      pass "WARN -> ${v}"
      ;;
   * )
      fail "WARN: expected 'WARN ...', got '${v}'"
      ;;
esac

## --- Case: WARN is INFORMATIONAL -- dm-tidy still exits 0 ------------------------
gitq -C "${sc}" push --quiet --force "${O}" "${M_OURS}:refs/heads/master" "${M_OURS}:refs/heads/ai"
rc=0
"${tool}" --dry-run --dir "${super}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "WARN is informational: dm-tidy still exits 0"
else
   fail "WARN wrongly changed exit code to ${rc}"
fi

## --- Case: skipped when a required remote is absent -----------------------------
gitq -C "${super}" remote remove github-kicksecure
v="$(mergecheck_verdict)"
case "${v}" in
   skipped\ * )
      pass "missing upstream remote -> ${v}"
      ;;
   * )
      fail "missing-remote: expected 'skipped ...', got '${v}'"
      ;;
esac
gitq -C "${super}" remote add github-kicksecure "file://${U}"

## --- Case: no throwaway refs left behind in the checkout ------------------------
_="$(mergecheck_verdict)"
leftover="$(gitq -C "${super}" for-each-ref --format='x' 'refs/dm-tidy-mergecheck/' | wc -l | tr -d ' ')"
if [ "${leftover}" = "0" ]; then
   pass "phase 6 leaves no throwaway refs in the checkout"
else
   fail "phase 6 leaked ${leftover} refs/dm-tidy-mergecheck/* ref(s)"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-tidy phase 6 classifies clean/benign/warn/skipped, stays informational, and leaves no refs."
