#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guard: dist-ai's OWN shell tree stays shellcheck-clean with NO project
## .shellcheckrc. This is what makes the .shellcheckrc removal permanent and
## regression-proof: without it a future file could reintroduce a suppressed
## shellcheck code, or a .shellcheckrc could reappear to blanket-silence one,
## and nobody would notice. Runs the AUTHORITATIVE gate (dist-ai-style --check)
## over the tree and greps for shellcheck [SC....] findings only -- the tree's
## pre-existing non-shellcheck R-debt on files this program never touched is out
## of scope and must not false-fail this guard.
##
## Source-tree test: set DIST_AI_REPO, or run from a checkout. Without one it
## is a FATAL environment error (exit 1), not a skip -- the guard must not go
## silently green when it never checked a tree. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/bin/dist-ai-style" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi
if [ -z "${repo}" ] || [ ! -f "${repo}/usr/bin/dist-ai-style" ]; then
   printf '%s\n' 'FAIL: shellcheck-clean-tree: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

gate="${repo}/usr/bin/dist-ai-style"

## Required deps: fail LOUD (exit 1), never skip -- a vanished gate/shellcheck
## must not silently stop guarding.
if ! type -P shellcheck >/dev/null; then
   printf '%s\n' 'FAIL: shellcheck not on PATH (apt-get install shellcheck); the guard cannot run' >&2
   exit 1
fi

fail=0

## check (1) predicate, SHARED by the live check and canary A -- so the canary
## exercises the REAL detection, not merely that `touch` created a file. Returns
## 0 (true) when the dir has NO .shellcheckrc (ok), non-zero when one is present.
shellcheckrc_absent() {
   [ ! -e "$1/.shellcheckrc" ]
}

## (1) The project .shellcheckrc must NOT exist. Its removal is the whole point;
## a reappearance would blanket-silence the codes this program eliminated.
if ! shellcheckrc_absent "${repo}"; then
   printf '%s\n' "FAIL: a .shellcheckrc reappeared at '${repo}/.shellcheckrc'; the removal must stay permanent" >&2
   fail=1
fi

## (2) No shellcheck code fires anywhere in dist-ai's own shell tree, under the
## authoritative gate (so the absent-sibling SC1091 tolerance + source-path
## resolution match production). Grep the [SC....] findings only; ignore the
## gate's non-zero exit from pre-existing non-shellcheck R-debt on untouched files.
## Run the gate NO-FOLLOW (DIST_AI_SHELLCHECK_NO_FOLLOW=1): '--external-sources' following is
## EXPONENTIAL on the deep helper-scripts graph, so over the whole tree the per-file follow cap
## stacks into a many-minute, output-silent run that wedges this guard -- and following yields NO
## gating signal here anyway (SC1091 is dropped, SC2034/SC2154 are advisory). A DEADLINE backstops
## it: a guard that cannot COMPLETE gates nothing, so a run that ever re-explodes (e.g. the knob
## stops being honored) must fail LOUD (timeout rc 124), never silently hang. Generous default so a
## loaded host does not false-fail the ~5-6min no-follow run; override via DIST_AI_CLEAN_TREE_DEADLINE.
clean_tree_deadline="${DIST_AI_CLEAN_TREE_DEADLINE:-1200}"
gate_rc=0
gate_out="$(
   cd -- "${repo}" || exit 0
   DIST_AI_SHELLCHECK_NO_FOLLOW=1 timeout --kill-after=10 "${clean_tree_deadline}" "${gate}" --check . 2>&1
)" || gate_rc=$?
if [ "${gate_rc}" -eq 124 ]; then
   printf '%s\n' "FAIL: dist-ai-style --check . did not complete within ${clean_tree_deadline}s -- shellcheck '--external-sources' following re-exploded over the whole tree (a guard that cannot finish gates nothing). Is DIST_AI_SHELLCHECK_NO_FOLLOW still honored?" >&2
   fail=1
fi

## Non-vacuous: the gate must actually have run to a verdict. If it errored out
## before checking (empty / no summary), a "no [SC] lines" read would be a false
## green -- fail closed.
if ! grep --quiet --extended-regexp 'check\(s\) (failed|passed)|all static checks passed' <<< "${gate_out}"; then
   printf '%s\n' 'FAIL: dist-ai-style produced no completion summary; the tree was not actually checked' >&2
   printf '%s\n' "${gate_out}" | tail -20 >&2
   fail=1
fi

## Print the [SC....] lines that belong to a gating FAIL block of gate output $1. A
## block starts at a 'dist-ai-style: ' header; a NOTE block (e.g. the timed-out
## following degrade's SC2034/SC2154 advisory) never fails the gate, so its
## findings are not a regression.
gating_sc_lines() {
   local line in_fail=0
   while IFS= read -r line; do
      case "${line}" in
         "dist-ai-style: FAIL "*)
            in_fail=1
            ;;
         "dist-ai-style: "*)
            in_fail=0
            ;;
      esac
      if [ "${in_fail}" -eq 1 ] && [[ "${line}" =~ \[SC[0-9]+\] ]]; then
         printf '%s\n' "${line}"
      fi
   done <<< "$1"
}

sc_lines="$( gating_sc_lines "${gate_out}" )"
if [ -n "${sc_lines}" ]; then
   printf '%s\n' 'FAIL: shellcheck codes fire in dist-ai shell tree (the rc removal is not clean):' >&2
   printf '%s\n' "${sc_lines}" >&2
   fail=1
fi

## --- CANARY (both ways): prove this guard actually CATCHES a regression, not
## just passes on today's clean tree. Run the two checks against throwaway
## fixtures and assert they trip. A guard that never fails guards nothing.

work_dir="$(mktemp --directory -- "${TMP}/shellcheck-clean-tree-canary.XXXXXX")"
# shellcheck disable=SC2317  # invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

## Canary A: check (1)'s predicate must DETECT a planted .shellcheckrc -- prove the
## detection actually trips, not merely that `touch` created a file (the old check
## only asserted the fixture existed, so it exercised check (1) not at all).
touch -- "${work_dir}/.shellcheckrc"
if shellcheckrc_absent "${work_dir}"; then
   printf '%s\n' 'FAIL(canary A): check (1) did NOT detect a planted .shellcheckrc -- the guard would not catch an rc reappearance' >&2
   fail=1
fi

## Canary B: a fresh SC2016 violation in a shell file must be caught by the gate
## (no rc present -> the code fires). Prove the detection, not just the clean tree.
cat > "${work_dir}/canary.sh" <<'CANARY'
#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C
y='value'
printf '%s\n' 'literal $y stays literal'
CANARY
canary_out="$( "${gate}" --check "${work_dir}/canary.sh" 2>&1 || true )"
if ! grep --quiet '\[SC2016\]' <<< "$( gating_sc_lines "${canary_out}" )"; then
   printf '%s\n' 'FAIL(canary B): the gate did NOT flag a planted SC2016 violation -- the guard would not catch a real regression' >&2
   printf '%s\n' "${canary_out}" | tail -10 >&2
   fail=1
fi

## Canary C: an advisory NOTE block's [SC....] lines are not gating, and a FAIL
## block after it still is.
advisory_out="dist-ai-style: following timed out on 'x.sh'; these unused/unassigned-variable findings are ADVISORY:
x.sh:3:1: warning: FOO is referenced but not assigned. [SC2154]
dist-ai-style: FAIL shellcheck: 'y.sh'
y.sh:5:1: info: Expressions don't expand in single quotes. [SC2016]"
canary_c="$( gating_sc_lines "${advisory_out}" )"
if [ "${canary_c}" != "y.sh:5:1: info: Expressions don't expand in single quotes. [SC2016]" ]; then
   printf '%s\n' "FAIL(canary C): gating_sc_lines mis-split advisory vs gating findings: [${canary_c}]" >&2
   fail=1
fi

## Canary D: DIST_AI_SHELLCHECK_NO_FOLLOW actually DISABLES '--external-sources' following -- the
## whole point of running this guard no-follow (following is exponential over the tree and gates
## nothing here). Fast + deterministic on a tiny file with a BROKEN 'source=': with following ON the
## unfollowable source is a gating SC1091 (the tmp file is in no git repo, so the absent-sibling
## tolerance does not apply); with the knob set it is dropped (no-follow drops SC1091). On the OLD
## engine (knob unhonored) SC1091 still fires under the knob, so the second assertion bites -- the
## canary proves the knob the whole-tree run above depends on, without waiting out that ~5-6min run.
cat > "${work_dir}/nofollow.sh" <<'NOFOLLOW'
#!/bin/bash
# shellcheck source=./nope.sh
. ./nope.sh
NOFOLLOW
## Force FOLLOW mode regardless of the caller's environment: if DIST_AI_SHELLCHECK_NO_FOLLOW=1 is
## exported (a dev/CI shell, or this guard's own gate_out run leaking into a sourced context), this
## "follow ON" run would silently go no-follow, drop SC1091, and fail the assertion below with a
## misleading "fixture" message. Unset it so the canary always contrasts follow vs no-follow.
follow_out="$( env --unset=DIST_AI_SHELLCHECK_NO_FOLLOW "${gate}" --check "${work_dir}/nofollow.sh" 2>&1 || true )"
if ! grep --quiet '\[SC1091\]' <<< "$( gating_sc_lines "${follow_out}" )"; then
   printf '%s\n' 'FAIL(canary D): following ON did not flag the broken source= as a gating SC1091 -- the fixture no longer exercises the knob' >&2
   printf '%s\n' "${follow_out}" | tail -10 >&2
   fail=1
fi
nofollow_out="$( DIST_AI_SHELLCHECK_NO_FOLLOW=1 "${gate}" --check "${work_dir}/nofollow.sh" 2>&1 || true )"
if grep --quiet '\[SC1091\]' <<< "$( gating_sc_lines "${nofollow_out}" )"; then
   printf '%s\n' 'FAIL(canary D): DIST_AI_SHELLCHECK_NO_FOLLOW did NOT disable following (SC1091 still gates) -- the whole-tree guard would re-explode' >&2
   printf '%s\n' "${nofollow_out}" | tail -10 >&2
   fail=1
fi

if [ "${fail}" -eq 0 ]; then
   printf '%s\n' 'PASS: dist-ai shell tree shellcheck-clean, no .shellcheckrc, canary catches both regressions'
fi
exit "${fail}"
