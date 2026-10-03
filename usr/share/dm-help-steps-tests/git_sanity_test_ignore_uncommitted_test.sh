#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for git_sanity_test's no-AI-skip policy at the CONSUMPTION point
## for UNCOMMITTED changes.
##
## THE GAP IT GUARDS: parse-cmd only refuses --allow-uncommitted in its FLAG branch,
## but dist_build_ignore_uncommitted=true also reaches mode_working_tree() from the
## environment or a buildconfig.d snippet, bypassing the flag. mode_working_tree() is
## where the dirty tree is HONORED ("continuing"), so the AI refusal lives there too:
## an AI session (CLAUDECODE) or a context setting dist_build_forbid_allow_uncommitted
## =true must NOT build with uncommitted changes. The AI forbid is UNCONDITIONAL --
## dist_build_unlock_dangerous_options does NOT override it; only a human build (no
## CLAUDECODE, not forbidden) may continue on a dirty tree.
##
## git_sanity_test is source-able (the `sourceable` skill): main() auto-runs only when
## executed, so sourcing it here defines mode_working_tree (plus the real colors / die
## / log_run) WITHOUT running the tool. sq_git_verify is STUBBED to isolate the
## uncommitted branch from signature verification (its own policy is covered by
## git_sanity_test_ignore_unsigned_test.sh); everything else is the REAL function.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
script="${dm_checkout}/help-steps/git_sanity_test"
if [ ! -r "${script}" ]; then
   printf '%s\n' "FATAL: git_sanity_test not found at '${script}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## A stable substring of this consumption-point refusal, specific enough that only the
## mode_working_tree guard (not parse-cmd's flag gate, which says "--allow-uncommitted
## true) is forbidden") satisfies it. Drift-guarded: a missing sentinel is a hard error.
REFUSAL='uncommitted changes (dist_build_ignore_uncommitted=true) is forbidden'
if ! grep --quiet --fixed-strings -- "${REFUSAL}" "${script}"; then
   printf '%s\n' "FATAL: refusal sentinel '${REFUSAL}' not found in '${script}'; the message drifted -- update this test." >&2
   exit 1
fi

## A throwaway git repo with one commit and a DIRTY worktree (an untracked file), so
## 'git status --porcelain' is non-empty and mode_working_tree reaches the uncommitted
## branch. core.hooksPath=/dev/null: the fixture is not testing the operator's hooks.
repo="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${repo}"; }
trap cleanup EXIT
git -C "${repo}" -c init.defaultBranch=main init --quiet
git -C "${repo}" -c core.hooksPath=/dev/null -c user.name=t -c user.email=t@t commit \
   --quiet --allow-empty --message init
printf '%s\n' 'dirty-marker' > "${repo}/dirty-untracked-file"

## Source the REAL script: defines mode_working_tree (+ colors / die / log_run).
# shellcheck disable=SC1090
source "${script}"
if [ "$(type -t mode_working_tree)" != "function" ]; then
   printf '%s\n' "FATAL: sourcing git_sanity_test did not define mode_working_tree." >&2
   exit 1
fi

## Run the REAL mode_working_tree on the dirty repo with the given env; the uncommitted
## branch is reached past the (stubbed) signature + (untagged-allowed) tag checks.
## Subshell: the guard aborts with 'exit 3', and env must not leak between probes.
## Echoes the combined output; the subshell's EXIT STATUS is the real signal.
probe_out() {
   (
      cd "${repo}" || exit 99
      ## Isolate the uncommitted branch: stub signature verification (own test) and
      ## allow the no-tag-at-HEAD case so we reach the uncommitted check.
      # shellcheck disable=SC2317  # invoked indirectly by the sourced mode_working_tree
      sq_git_verify() { return 0; }
      # shellcheck disable=SC2034  # consumed by the sourced mode_working_tree (requires context)
      context='test-context'
      # shellcheck disable=SC2034  # consumed by the sourced mode_working_tree
      dist_build_ignore_untagged='true'
      # shellcheck disable=SC2034  # consumed by the sourced mode_working_tree
      dist_build_ignore_uncommitted='true'
      # shellcheck disable=SC2034  # read by the (stubbed) sq_git_verify's real siblings
      dist_build_ignore_unsigned='true'
      # shellcheck disable=SC2034
      dist_build_redistributable='false'
      eval "$1"
      mode_working_tree 2>&1
   )
}

## $1 label, $2 expected (refused|allowed), $3 env snippet. REFUSED is asserted on the
## EXIT STATUS (the guard's 'exit 3'), not merely the printed message -- the message
## alone would still appear if the abort were dropped (fall-through), a false pass. A
## refusal must be nonzero AND carry OUR sentinel (not some unrelated failure); an
## allowed run must exit 0 (mode_working_tree proceeded past the dirty tree).
probe() {
   local label="$1" expect="$2" snippet="$3" out rc=0 got='allowed'
   out="$(probe_out "${snippet}")" || rc="$?"
   if [ "${rc}" -ne 0 ] && [[ "${out}" == *"${REFUSAL}"* ]]; then
      got='refused'
   elif [ "${rc}" -ne 0 ]; then
      fail "${label}: nonzero rc ${rc} but not OUR refusal (output: ${out})"
      return
   fi
   if [ "${got}" = "${expect}" ]; then
      pass "${label} -> ${got} (rc=${rc})"
   else
      fail "${label}: expected ${expect}, got ${got} (rc=${rc})"
   fi
}

## Refused: AI session, the general forbid var, and (hardened) AI + dangerous unlock.
probe "AI session (CLAUDECODE=1)"                       refused 'export CLAUDECODE=1'
probe "general forbid var, no AI"                       refused 'unset CLAUDECODE; export dist_build_forbid_allow_uncommitted=true'
probe "AI + dangerous-options unlock (no override)"     refused 'export CLAUDECODE=1 dist_build_unlock_dangerous_options=true'

## Allowed: a plain human build continues on the dirty tree (no CLAUDECODE, no forbid).
probe "human (no CLAUDECODE, no forbid)"                allowed 'unset CLAUDECODE'

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: git_sanity_test ignore-uncommitted AI policy (consumption point)."
