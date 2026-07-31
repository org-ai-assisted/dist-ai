#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'ci/assert-submodule-not-stale'.
##
## THE BUG IT GUARDS: a lane that runs a tool out of a submodule executes the
## PINNED copy, so a lagging pin fails wherever the old tool happens to break
## -- never at the pin. Two real cases cost a full build cycle each: the
## compare lane died on "expected exactly one *.qcow2 under build-a, found 0"
## (pinned comparator predating artifact_glob="*.qcow2.libvirt.xz", and exit 2
## there means not-found, NOT "artifacts differ"), and a build step died on
## "has.sh: No such file or directory" from an old installed tool.
##
## Asserts BOTH directions -- an assertion that can only pass is worthless:
##   - a pin STRICTLY BEHIND upstream        -> exit 1, message names path + shas
##   - a pin EQUAL to upstream               -> exit 0
##   - a pin AHEAD / diverged                -> exit 0 (deliberate, not lag)
##   - an unreachable pin                    -> exit 2 (fail closed, no verdict)
##   - a missing submodule directory         -> exit 2
##
## Builds throwaway git repos; needs no root, no network.
##
## Subject selection (first that exists):
##   $DM_ASSERT_SUBMODULE  ->  ./assert-submodule-not-stale next to this test
##   ->  ~/derivative-maker/ci/assert-submodule-not-stale

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

subject_path=""
locate_subject() {
   local candidate

   if [ -n "${DM_ASSERT_SUBMODULE:-}" ]; then
      if [ ! -r "${DM_ASSERT_SUBMODULE}" ]; then
         ## SKIP, not error -- dist-ai-tests-all CONSTRUCTS this path
         ## unconditionally, so unreadable means the target is not checked out.
         printf '%s\n' "SKIP: DM_ASSERT_SUBMODULE='${DM_ASSERT_SUBMODULE}' is not readable (derivative-maker not checked out?)." >&2
         exit 77
      fi
      subject_path="${DM_ASSERT_SUBMODULE}"
      return 0
   fi
   for candidate in \
      "${test_dir}/assert-submodule-not-stale" \
      "${HOME}/derivative-maker/ci/assert-submodule-not-stale"; do
      if [ -r "${candidate}" ]; then
         subject_path="${candidate}"
         return 0
      fi
   done
   printf '%s\n' "SKIP: assert-submodule-not-stale not found (derivative-maker not checked out; set DM_ASSERT_SUBMODULE)." >&2
   exit 77
}

## A test repo must not run the operator's hooks (git skill).
git_quiet() {
   git -c core.hooksPath=/dev/null -c user.email=ci-test@example.com -c user.name=ci-test "$@"
}

commit_in() {
   local repo message

   repo="$1"
   message="$2"
   printf '%s\n' "${message}" >> "${repo}/file.txt"
   git_quiet -C "${repo}" add file.txt
   git_quiet -C "${repo}" commit --quiet --no-verify --message "${message}"
}

## Build a superproject whose gitlink for 'sub' is set to $2, with the
## submodule's origin/master at $3. Echoes the superproject path.
build_fixture() {
   local scratch upstream super pin_sha
   scratch="$1"
   pin_sha="$2"

   upstream="${scratch}/upstream"
   super="${scratch}/super"
   git_quiet init --quiet -- "${super}"
   printf 'x\n' > "${super}/README"
   git_quiet -C "${super}" add README
   git_quiet -C "${super}" commit --quiet --no-verify --message base
   ## Clone the submodule in place, then record the gitlink by hand: 'git
   ## submodule add' would insist on a remote and network.
   git_quiet clone --quiet -- "${upstream}" "${super}/sub" 2>/dev/null
   git_quiet -C "${super}" update-index --add --cacheinfo "160000,${pin_sha},sub"
   git_quiet -C "${super}" commit --quiet --no-verify --message pin
   printf '%s\n' "${super}"
}

run_subject() {
   local super rc
   super="$1"
   rc=0
   ( cd -- "${super}" && bash "${subject_path}" sub ) >"${run_out}" 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

require_rc() {
   local actual wanted description
   actual="$1"
   wanted="$2"
   description="$3"
   if [ "${actual}" = "${wanted}" ]; then
      pass "${description} (exit ${actual})"
   else
      fail "${description}: expected exit ${wanted}, got ${actual}"
      printf '%s\n' "DEBUG output:" >&2
      cat -- "${run_out}" >&2
   fi
}

main() {
   local scratch upstream old_sha new_sha super rc run_out

   locate_subject
   printf '%s\n' "INFO: subject: ${subject_path}"

   scratch="$(mktemp --directory)"
   run_out="${scratch}/out.txt"
   upstream="${scratch}/upstream"

   git_quiet init --quiet -- "${upstream}"
   commit_in "${upstream}" "first"
   old_sha="$(git_quiet -C "${upstream}" rev-parse HEAD)"
   commit_in "${upstream}" "second"
   commit_in "${upstream}" "third"
   new_sha="$(git_quiet -C "${upstream}" rev-parse HEAD)"

   ## ---- pin BEHIND upstream: must fail by name ----
   super="$(build_fixture "${scratch}" "${old_sha}")"
   rc="$(run_subject "${super}")"
   require_rc "${rc}" "1" "pin strictly behind upstream is rejected"
   if grep --fixed-strings -- "TRAILS" "${run_out}" >/dev/null 2>&1 \
      && grep --fixed-strings -- "${old_sha}" "${run_out}" >/dev/null 2>&1; then
      pass "message names the lag and the pinned sha"
   else
      fail "message did not name the lag and the pinned sha"
      cat -- "${run_out}" >&2
   fi
   safe-rm --recursive --force -- "${super}"

   ## ---- pin EQUAL to upstream: must pass ----
   super="$(build_fixture "${scratch}" "${new_sha}")"
   rc="$(run_subject "${super}")"
   require_rc "${rc}" "0" "pin equal to upstream is accepted"
   safe-rm --recursive --force -- "${super}"

   ## ---- pin AHEAD of upstream: deliberate, must pass ----
   ## A coordinated fork branch legitimately pins a commit upstream lacks.
   super="$(build_fixture "${scratch}" "${new_sha}")"
   commit_in "${super}/sub" "ahead"
   rc="$(cd -- "${super}/sub" && git_quiet rev-parse HEAD)"
   git_quiet -C "${super}" update-index --cacheinfo "160000,${rc},sub"
   git_quiet -C "${super}" commit --quiet --no-verify --message ahead
   rc="$(run_subject "${super}")"
   require_rc "${rc}" "0" "pin ahead of upstream is not treated as lag"
   safe-rm --recursive --force -- "${super}"

   ## ---- unreachable pin: fail CLOSED, never a false 'current' ----
   super="$(build_fixture "${scratch}" "0000000000000000000000000000000000000001")"
   rc="$(run_subject "${super}")"
   require_rc "${rc}" "2" "unreachable pin refuses a verdict"
   safe-rm --recursive --force -- "${super}"

   ## ---- missing submodule directory ----
   super="$(build_fixture "${scratch}" "${new_sha}")"
   safe-rm --recursive --force -- "${super}/sub"
   rc="$(run_subject "${super}")"
   require_rc "${rc}" "2" "missing submodule directory refuses a verdict"

   safe-rm --recursive --force -- "${scratch}"

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: all submodule-staleness assertions passed."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"
