#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the MANDATORY derivative-repository choice
## (variables.d/15_redistributable.bsh).
##
## WHY this exists: the derivative-repository choice is MANDATORY -- a bare
## `./derivative-maker` with no '--repo' must FAIL rather than resolve to an implicit
## default (an implicit choice risks shipping repo-disabled images with no error).
## After parse, if build_remote_repo_enable is unset, the build errors loudly. The
## choice is satisfied by '--repo true|false', the build_remote_repo_enable environment
## variable, or dist_build_redistributable=true (which help-steps/dm-build-official-one
## sets, so the official path builds repo-enabled with no '--repo').
##
## It drives the REAL help-steps/pre + help-steps/variables of a derivative-maker
## checkout in a subprocess (variables' own error handler calls exit, so each case runs
## isolated) and inspects the outcome. Source-tree test: the checkout is found via
## DERIVATIVE_MAKER_DIR or ~/derivative-maker; no checkout is an OPTIONAL SKIP (exit 77).

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

if [ ! -f "${dm_checkout}/help-steps/variables" ] || [ ! -f "${dm_checkout}/variables.d/15_redistributable.bsh" ]; then
   printf '%s\n' "repo-mandatory-test: no derivative-maker checkout at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR). SKIP." >&2
   ## style-ok: allow-skip: cannot source help-steps/variables without a derivative-maker checkout (optional sibling).
   exit 77
fi

## Resolve build_remote_repo_enable the way a build step does: source pre + variables
## with the given extra ENV and ARGS, in a throwaway subprocess. Prints one of:
##   MANDATORY   -- the mandatory-choice error fired
##   repo=<v>    -- variables completed; build_remote_repo_enable resolved to <v>
##   other       -- variables failed for a different reason (diagnostic in $out_file)
out_file="$(mktemp)"
cleanup() { safe-rm --force -- "${out_file}" || true; }
trap cleanup EXIT

resolve_repo() {
   local extra_env="$1" extra_args="$2"
   ( cd -- "${dm_checkout}/help-steps" || exit 90
     unset dist_build_redistributable build_remote_repo_enable
     ## dist_build_allow_root=true: the dm-help-steps suite re-runs itself as root
     ## (mount-cleanup requires it), so help-steps/pre's root_check would abort with
     ## "must NOT be run as root" unless this sanctioned CI/container override is
     ## set. Harmless when non-root (root_check only consults it under EUID=0).
     export CI=true dist_build_unlock_dangerous_options=true dist_build_allow_root=true
     ## user_name: the real dm-ci build runs via docker/derivative-maker-docker-run as a
     ## NON-root user AND passes user_name=<user>; variables.d/00_preamble.bsh deliberately
     ## will NOT derive user_name at EUID=0 (SUDO_USER unset + a container where logname
     ## fails -> "Variable user_name is empty" abort). This suite re-execs as root, so mirror
     ## the real invocation; else variables aborts before the choice logic under test runs.
     export user_name="${SUDO_USER:-user}"
     eval "${extra_env:-true}"
     # shellcheck disable=SC2086  ## deliberate word-split of the arg string
     set -- ${extra_args}
     # shellcheck disable=SC1091  ## dynamic path in the derivative-maker checkout
     source pre >/dev/null 2>&1
     ## Capture variables' OWN exit status (R-011: no errexit toggle). The '( ) || true'
     ## wrapper suppresses errexit inside, so without this an unexpected variables failure
     ## would still reach printf and masquerade as a resolved repo=. The mandatory-choice
     ## 'error' still lands its message in out_file (Case 1 greps it); repo= prints ONLY
     ## when variables actually completed.
     var_rc=0
     # shellcheck disable=SC1091  ## dynamic path in the derivative-maker checkout
     source variables || var_rc=$?
     if [ "${var_rc}" -eq 0 ]; then
        printf 'repo=%s\n' "${build_remote_repo_enable:-<unset>}"
     else
        printf 'VARIABLES_FAILED rc=%s\n' "${var_rc}"
     fi
   ) > "${out_file}" 2>&1 || true   ## the mandatory-error path exits non-zero by design
   if grep --quiet -- 'MANDATORY' "${out_file}"; then
      printf 'MANDATORY\n'
   elif grep --quiet -- '^repo=' "${out_file}"; then
      grep -- '^repo=' "${out_file}" | tail -n1
   else
      ## Neither outcome: pre/variables aborted for an unexpected reason. Surface
      ## the captured diagnostic to stderr so the failure names its cause instead
      ## of an opaque 'other' (the subshell's output is otherwise swallowed).
      printf 'other\n'
      printf '%s\n' "DIAG(resolve_repo other): ---8<--- ${out_file} ---" >&2
      cat -- "${out_file}" >&2 || true
      printf '%s\n' "--->8--- end DIAG" >&2
   fi
}

base_args="--arch amd64 --tb closed --freedom false --freshness frozen --target iso --flavor kicksecure-lxqt"

## --- Case 1 (CANARY): bare build, no --repo, non-redistributable -> MANDATORY error ---
## A silent `default_if_empty build_remote_repo_enable "false"` would make this resolve
## 'repo=false' instead, so this assertion catches any weakening of the enforcement.
r="$(resolve_repo '' "${base_args}")"
if [ "${r}" = 'MANDATORY' ]; then
   pass "a bare build with no --repo fails loudly (repo choice mandatory)"
else
   fail "a bare build with no --repo did not error mandatory; got '${r}'"
fi

## --- Case 2: --repo true -> enabled ---------------------------------------------
r="$(resolve_repo '' "--repo true ${base_args}")"
if [ "${r}" = 'repo=true' ]; then
   pass "--repo true enables the repository"
else
   fail "--repo true did not resolve repo=true; got '${r}'"
fi

## --- Case 3: --repo false -> disabled (explicit opt-out still allowed) -----------
r="$(resolve_repo '' "--repo false ${base_args}")"
if [ "${r}" = 'repo=false' ]; then
   pass "--repo false disables the repository (explicit opt-out)"
else
   fail "--repo false did not resolve repo=false; got '${r}'"
fi

## --- Case 4: the build_remote_repo_enable env var satisfies the choice -----------
r="$(resolve_repo 'export build_remote_repo_enable=true' "${base_args}")"
if [ "${r}" = 'repo=true' ]; then
   pass "the build_remote_repo_enable env var satisfies the mandatory choice"
else
   fail "build_remote_repo_enable=true env did not resolve repo=true; got '${r}'"
fi

## --- Case 5: the official path (dist_build_redistributable=true) stays repo-enabled ---
## help-steps/dm-build-official-one sets this, so the official path needs no --repo.
r="$(resolve_repo 'export dist_build_redistributable=true' "${base_args}")"
if [ "${r}" = 'repo=true' ]; then
   pass "dist_build_redistributable=true (official path) builds repo-enabled with no --repo"
else
   fail "official path did not resolve repo=true; got '${r}'"
fi

## --- Case 6 (CANARY): source-run/utility help-steps are EXEMPT from the choice -------
## sign-and-tag, git_sanity_test, signing-key-* etc. set dist_build_source_run=true and
## build no image, so they must NOT abort on the mandatory check -- they default off.
## Without the source-run exemption this resolves MANDATORY (the step would abort).
r="$(resolve_repo 'export dist_build_source_run=true' "${base_args}")"
if [ "${r}" = 'repo=false' ]; then
   pass "a source-run/utility help-step (dist_build_source_run=true) is exempt, defaults repo off"
else
   fail "source-run was not exempt from the mandatory choice; got '${r}'"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: the derivative-repository choice is mandatory (bare no-repo fails), satisfied by --repo true|false, the env var, or the official dist_build_redistributable default."
