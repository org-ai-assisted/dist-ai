#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the SUDO_TO_ROOT '--preserve-env=...' cross-process leak
## in help-steps/variables.
##
## THE TRAP IT GUARDS: 'variables' finalizes SUDO_TO_ROOT once, appending
## '--preserve-env=<env_vars_keep_list>' behind a re-entrance guard flag
## ('variables_sudo_to_root_finalized'). The guard is meant to be SAME-SHELL
## only. If that flag is EXPORTED, it leaks into child processes -- build steps
## run as children, plus the recursive 'derivative-maker' and genmkfile
## invocations. A child inherits the flag as "true" but NOT SUDO_TO_ROOT (which
## is not exported), rebuilds the bare 'sudo --non-interactive' default, sees
## the inherited flag, and SKIPS the '--preserve-env' append. Every preserved
## variable then vanishes from sudo -- DIST_APTGETOPT_SERIALIZED among them --
## which aborts the cowbuilder -> pbuilder -> help-steps/mmdebstrap bootstrap
## with "DIST_APTGETOPT_SERIALIZED is unset!".
##
## The contract: a child process that re-sources 'variables' MUST still get
## '--preserve-env' in SUDO_TO_ROOT, regardless of whether an ancestor already
## sourced 'variables'. This is guaranteed only while the guard flag is NOT
## exported.
##
## Drives the REAL help-steps/pre + help-steps/variables (no copy, no
## re-implementation), sourcing them in a parent shell and again in a child, and
## inspecting the child's SUDO_TO_ROOT -- the exact shape of the production bug.
##
## Needs the same environment as dm-varname-snapshot (sources 'variables' to its
## dump hook / to completion, which writes the pbuilder config via sudo): the
## suite runs it elevated. No network, no build.

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

if [ ! -r "${dm_checkout}/help-steps/variables" ] || [ ! -r "${dm_checkout}/help-steps/pre" ]; then
   printf '%s\n' "FATAL: derivative-maker checkout not found at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

probe_script="${test_dir}/sudo_to_root_preserve_env_probe.sh"
if [ ! -r "${probe_script}" ]; then
   printf '%s\n' "FATAL: probe script not found at '${probe_script}'." >&2
   exit 1
fi

## A valid, minimal build command; the axes do not matter here, only that
## 'variables' finalizes SUDO_TO_ROOT.
build_args=( --flavor source --target root --freshness current --arch amd64 --freedom false )

## Environment 'variables' expects from the suite (elevated run of the ci-tiny /
## root paths); mirrors varname_snapshot_lib.bsh's capture env.
capture_env=( dist_build_allow_root=true dist_build_unlock_dangerous_options=true )

## Source pre+variables in a PARENT, then re-source them in a CHILD, and print
## the child's preserve-env verdict. Any extra 'NAME=value' arguments before the
## '--' are injected into the PARENT environment, to simulate an ancestor that
## has already finalized (the pre-fix leak would arrive exactly this way).
child_preserve_env_verdict() {
   local extra_env=()
   while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
      extra_env+=( "$1" )
      shift
   done
   shift ## drop the '--'

   ## The probe sources 'variables' behind pre's exception handler, whose
   ## normal-exit notice ('INFO: Script _ completed ...') also lands on stdout;
   ## extract only the verdict token so trailing notices cannot corrupt it.
   ( cd -- "${dm_checkout}" \
      && env "${capture_env[@]}" "${extra_env[@]}" bash "${probe_script}" "$@" \
   ) | grep --only-matching --extended-regexp 'CHILD_(HAS|MISSING)_PRESERVE_ENV' | tail -n 1
}

## Print the 'declare' attribute line for the guard flag from a single real
## sourcing of pre+variables (dump hook on: stop right after finalization).
guard_flag_declare_line() {
   ( cd -- "${dm_checkout}" \
      && env "${capture_env[@]}" dist_build_dump_varnames=true bash -c '
            source help-steps/pre >/dev/null 2>&1
            source help-steps/variables "$@"
         ' _ "$@" 2>/dev/null \
      | grep --extended-regexp '^declare -[^ ]* variables_sudo_to_root_finalized=' || true
   )
}

## Assertion 1 -- THE regression: a clean parent must not infect its child.
## Fails on the pre-fix code, where the parent exports the guard flag.
verdict_clean="$(child_preserve_env_verdict -- "${build_args[@]}")"
if [ "${verdict_clean}" = "CHILD_HAS_PRESERVE_ENV" ]; then
   pass "child re-sourcing variables keeps --preserve-env (no guard-flag leak)"
else
   fail "child LOST --preserve-env (verdict: '${verdict_clean}') -- guard flag leaked into the child, dropping DIST_APTGETOPT_SERIALIZED from sudo"
fi

## Assertion 2 -- detection liveness (self-canary): when the guard flag IS
## present in the parent environment (an already-infected ancestor), the child
## MUST lose --preserve-env. This proves the verdict above can actually tell the
## two states apart, so a green assertion 1 means something.
verdict_seeded="$(child_preserve_env_verdict variables_sudo_to_root_finalized=true -- "${build_args[@]}")"
if [ "${verdict_seeded}" = "CHILD_MISSING_PRESERVE_ENV" ]; then
   pass "an inherited guard flag DOES drop --preserve-env (the check is live)"
else
   fail "expected CHILD_MISSING_PRESERVE_ENV with the flag pre-seeded, got '${verdict_seeded}' -- the check cannot distinguish leak from no-leak"
fi

## Assertion 3 -- the root cause, directly: the guard flag must not be exported.
## 'declare --' (or any non-'-x' attribute) is correct; 'declare -x' is the bug.
flag_line="$(guard_flag_declare_line "${build_args[@]}")"
if [ -z "${flag_line}" ]; then
   fail "variables never set variables_sudo_to_root_finalized -- the guard is gone; the append is unguarded"
elif [[ "${flag_line}" =~ ^declare\ -[a-zA-Z]*x ]]; then
   fail "guard flag is EXPORTED ('${flag_line}') -- it leaks to children; drop the 'export'"
else
   pass "guard flag is not exported ('${flag_line}')"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: SUDO_TO_ROOT --preserve-env survives a child re-source."
