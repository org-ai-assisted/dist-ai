#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards dm-packaging-helper-script's pkg_git_check_current_branch:
## - Branch-sensitive targets require 'master', so a human who left a repo
##   on its 'ai' branch is CAUGHT (not silently allowed to commit/push
##   packaging changes onto ai). Regression: re-adding 'ai' to the accepted
##   set (a previously-made mistake) would reopen that hole.
## - A caller whose operation needs no branch (remote config, fetch) sets
##   pkg_git_branch_agnostic=true to SKIP the guard; dm-tidy does so for its
##   remote-ensure, so it runs on 'ai' or detached submodules. Regression:
##   dropping the skip line re-breaks dm-tidy on every ai-workflow submodule.
##
## Unit test of the REAL function (extracted from the current script text, so
## no drift) against throwaway git repos. No root, no network, no build.

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

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$(( test_failures + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

rel='usr/bin/dm-packaging-helper-script'
candidates=()
[ -z "${DM_PACKAGING_HELPER_SCRIPT:-}" ] || candidates+=( "${DM_PACKAGING_HELPER_SCRIPT}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-packaging-helper-script not found (set DM_PACKAGING_HELPER_SCRIPT)." >&2
   exit 1
fi

## Extract the function body. Its closing brace is the only '}' at column 0.
func_text="$(awk '
   /^pkg_git_check_current_branch\(\) \{/ { f=1 }
   f                                      { print }
   f && /^\}/                             { exit }
' "${subject}")"
if [ -z "${func_text}" ]; then
   printf '%s\n' "FATAL: could not extract pkg_git_check_current_branch from '${subject}'." >&2
   exit 1
fi

tmp_root="$(mktemp -d)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${tmp_root}"
}
trap cleanup EXIT

## A throwaway repo checked out on ${1}.
make_repo_on_branch() {
   local branch="${1}" repo
   repo="$(mktemp -d -p "${tmp_root}")"
   git -C "${repo}" init -q -b master
   git -C "${repo}" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
   [ "${branch}" = "master" ] || git -C "${repo}" checkout -q -b "${branch}"
   printf '%s\n' "${repo}"
}

## Run the extracted guard inside ${repo}, with the env flag ${2} ('' = unset).
run_guard() {
   local repo="${1}" flag="${2}"
   (
      cd -- "${repo}"
      ## Consumed by the extracted function's error path via eval below.
      # shellcheck disable=SC2034
      batch_current_package_reponame='testrepo'
      [ -z "${flag}" ] || export pkg_git_branch_agnostic="${flag}"
      eval "${func_text}"
      pkg_git_check_current_branch >/dev/null 2>&1
   )
}

repo_master="$(make_repo_on_branch master)"
repo_ai="$(make_repo_on_branch ai)"

## 1. on master, no flag -> pass (0)
if run_guard "${repo_master}" ""; then
   pass "on master without flag -> accepted"
else
   fail "on master without flag -> rejected (expected accepted)"
fi

## 2. on ai, no flag -> MUST reject (1): catches accidental human ai checkout
if run_guard "${repo_ai}" ""; then
   fail "on ai without flag -> accepted (expected rejected; accidental-ai hole)"
else
   pass "on ai without flag -> rejected"
fi

## 3. on ai, pkg_git_branch_agnostic=true -> skip -> pass (0)
if run_guard "${repo_ai}" "true"; then
   pass "on ai with pkg_git_branch_agnostic=true -> skipped"
else
   fail "on ai with pkg_git_branch_agnostic=true -> rejected (expected skip)"
fi

## 4. on master, pkg_git_branch_agnostic=true -> skip -> pass (0)
if run_guard "${repo_master}" "true"; then
   pass "on master with pkg_git_branch_agnostic=true -> skipped"
else
   fail "on master with pkg_git_branch_agnostic=true -> rejected (expected skip)"
fi

printf '%s\n' "${pass_count} pass, ${test_failures} fail, 0 skip"
[ "${test_failures}" -eq 0 ]
