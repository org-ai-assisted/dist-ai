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
## And the '--all' form, which enumerates .gitmodules instead of taking a named
## path. Naming the submodules to check answers only for the ones someone
## remembered to add, while the step title reads like full coverage:
##   - a set containing a trailing pin       -> exit 1, EVERY submodule reported
##   - '--report-only'                       -> exit 0, findings still printed
##   - a submodule that cannot be checked    -> exit 2, counted as NOT verified
##   - no / empty .gitmodules                -> exit 2 (an empty sweep is not a pass)
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
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

subject_path=""
locate_subject() {
   local candidate

   if [ -n "${DM_ASSERT_SUBMODULE:-}" ]; then
      if [ ! -r "${DM_ASSERT_SUBMODULE}" ]; then
         ## FATAL, not skip -- dist-ai-tests-all CONSTRUCTS this path
         ## unconditionally, so unreadable means the target is not checked out
         ## (a required subject absent is an environment bug, R-220).
         printf '%s\n' "FATAL: DM_ASSERT_SUBMODULE='${DM_ASSERT_SUBMODULE}' is not readable (derivative-maker not checked out?)." >&2
         exit 1
      fi
      subject_path="${DM_ASSERT_SUBMODULE}"
      return 0
   fi
   for candidate in \
      "${test_dir}/assert-submodule-not-stale" \
      "${dm_checkout}/ci/assert-submodule-not-stale"; do
      if [ -r "${candidate}" ]; then
         subject_path="${candidate}"
         return 0
      fi
   done
   printf '%s\n' "FATAL: assert-submodule-not-stale not found (derivative-maker not checked out; set DM_ASSERT_SUBMODULE)." >&2
   exit 1
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
   printf '%s\n' 'x' > "${super}/README"
   git_quiet -C "${super}" add README
   git_quiet -C "${super}" commit --quiet --no-verify --message base
   ## Clone the submodule in place, then record the gitlink by hand: 'git
   ## submodule add' would insist on a remote and network.
   git_quiet clone --quiet -- "${upstream}" "${super}/sub" 2>/dev/null
   git_quiet -C "${super}" update-index --add --cacheinfo "160000,${pin_sha},sub"
   git_quiet -C "${super}" commit --quiet --no-verify --message pin
   printf '%s\n' "${super}"
}

## Build a superproject with a '.gitmodules' recording N submodules, so the
## '--all' form has something to enumerate. Arguments are '<name>:<pin_sha>'
## pairs; each is cloned from $scratch/upstream and pinned at its own sha.
build_fixture_multi() {
   local scratch upstream super submodule_spec submodule_name submodule_pin
   scratch="$1"
   shift

   upstream="${scratch}/upstream"
   super="${scratch}/super"
   git_quiet init --quiet -- "${super}"
   printf '%s\n' 'x' > "${super}/README"
   git_quiet -C "${super}" add README
   git_quiet -C "${super}" commit --quiet --no-verify --message base

   true > "${super}/.gitmodules"
   for submodule_spec in "$@"; do
      submodule_name="${submodule_spec%%:*}"
      submodule_pin="${submodule_spec#*:}"
      git_quiet clone --quiet -- "${upstream}" "${super}/${submodule_name}" 2>/dev/null
      ## Written by hand rather than via 'git submodule add', which insists on a
      ## remote and network.
      printf '%s\n' \
         "[submodule \"${submodule_name}\"]" \
         "	path = ${submodule_name}" \
         "	url = ${upstream}" >> "${super}/.gitmodules"
      git_quiet -C "${super}" update-index --add --cacheinfo "160000,${submodule_pin},${submodule_name}"
   done
   git_quiet -C "${super}" add .gitmodules
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

run_subject_all() {
   local super rc
   super="$1"
   shift
   rc=0
   ( cd -- "${super}" && bash "${subject_path}" --all "$@" ) >"${run_out}" 2>&1 || rc="$?"
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
   local scratch upstream old_sha new_sha super rc run_out shim_dir

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

   safe-rm --recursive --force -- "${super}"

   ## ---- '--all': every pin in .gitmodules, none of them named here ---------
   ## THE BUG THIS HALF GUARDS: naming the submodules to check means answering
   ## only for the ones someone remembered to add, while the step title reads
   ## like full coverage. Two submodules, one behind and one current, must BOTH
   ## appear -- a run that checks the first and stops looks identical to a pass
   ## from the exit code alone.
   super="$(build_fixture_multi "${scratch}" "lagging:${old_sha}" "fresh:${new_sha}")"
   rc="$(run_subject_all "${super}")"
   require_rc "${rc}" "1" "--all rejects a set containing a trailing pin"
   if grep --fixed-strings -- "'lagging' pin TRAILS" "${run_out}" >/dev/null 2>&1; then
      pass "--all names the trailing submodule"
   else
      fail "--all did not name the trailing submodule"
      cat -- "${run_out}" >&2
   fi
   if grep --fixed-strings -- "'fresh' pin is current" "${run_out}" >/dev/null 2>&1; then
      pass "--all also reached the second submodule"
   else
      fail "--all stopped at the first submodule, so it does not cover the set"
      cat -- "${run_out}" >&2
   fi
   ## The counts must state coverage, not just failures: "1 trailing" alone
   ## reads as full coverage even when others were never verified.
   if grep --fixed-strings -- "2 submodule(s): 1 current or ahead, 1 trailing, 0 NOT verified" "${run_out}" >/dev/null 2>&1; then
      pass "--all summarises current / trailing / unverified counts"
   else
      fail "--all did not report all three counts"
      cat -- "${run_out}" >&2
   fi

   ## '--report-only' must still CHECK and still REPORT; only the exit changes.
   rc="$(run_subject_all "${super}" --report-only)"
   require_rc "${rc}" "0" "--all --report-only does not fail the build"
   if grep --fixed-strings -- "'lagging' pin TRAILS" "${run_out}" >/dev/null 2>&1; then
      pass "--report-only still reports the lag"
   else
      fail "--report-only suppressed the finding, so it reports nothing"
      cat -- "${run_out}" >&2
   fi
   safe-rm --recursive --force -- "${super}"

   ## ---- '--all': an unverifiable pin is NOT a pass ------------------------
   super="$(build_fixture_multi "${scratch}" "gone:${new_sha}" "fresh:${new_sha}")"
   safe-rm --recursive --force -- "${super}/gone"
   rc="$(run_subject_all "${super}")"
   require_rc "${rc}" "2" "--all refuses a verdict when a submodule cannot be checked"
   if grep --fixed-strings -- "1 NOT verified" "${run_out}" >/dev/null 2>&1; then
      pass "--all counts the unverified submodule as unverified"
   else
      fail "--all folded an unverifiable submodule into another count"
      cat -- "${run_out}" >&2
   fi
   safe-rm --recursive --force -- "${super}"

   ## ---- '--all' with nothing to enumerate must not report success --------
   ## An empty sweep that exits 0 is the silent-green failure mode: the step is
   ## green and covered nothing.
   super="$(build_fixture_multi "${scratch}" "fresh:${new_sha}")"
   safe-rm --force -- "${super}/.gitmodules"
   rc="$(run_subject_all "${super}")"
   require_rc "${rc}" "2" "--all with no .gitmodules refuses to report coverage"
   safe-rm --recursive --force -- "${super}"

   super="$(build_fixture_multi "${scratch}" "fresh:${new_sha}")"
   true > "${super}/.gitmodules"
   rc="$(run_subject_all "${super}")"
   require_rc "${rc}" "2" "--all with an empty .gitmodules refuses to report coverage"
   safe-rm --recursive --force -- "${super}"

   ## ---- no resolvable default branch: unverifiable, not "current" ---------
   ## 'actions/checkout' does not create refs/remotes/origin/HEAD, so the
   ## fallbacks are the CI path. A repo with none of them must refuse a verdict
   ## rather than compare against a branch that does not exist.
   super="$(build_fixture "${scratch}" "${new_sha}")"
   git_quiet -C "${super}/sub" branch --move master trunk
   git_quiet -C "${super}/sub" update-ref --no-deref -d refs/remotes/origin/HEAD 2>/dev/null || true
   git_quiet -C "${super}/sub" update-ref -d refs/remotes/origin/master 2>/dev/null || true
   git_quiet -C "${super}/sub" update-ref -d refs/remotes/origin/main 2>/dev/null || true
   ## Point origin at nothing BEFORE the run: the subject fetches before
   ## comparing, and a reachable origin would recreate the very refs this case
   ## deletes -- so the fixture would depend on refresh order and could pass for
   ## the wrong reason, or flake.
   git_quiet -C "${super}/sub" remote set-url origin "${scratch}/no-such-remote"
   rc="$(run_subject "${super}")"
   require_rc "${rc}" "2" "no origin/HEAD, origin/master or origin/main refuses a verdict"
   safe-rm --recursive --force -- "${super}"

   ## ---- a 'current' verdict states whether the remote was consulted -------
   ## A remote-tracking ref that never moved makes an outdated pin read as
   ## current. The fixture's origin is a local path that is reachable, so the
   ## fetch succeeds and the qualifier must be ABSENT -- the negative half of the
   ## pair, so a qualifier printed unconditionally would fail here.
   super="$(build_fixture "${scratch}" "${new_sha}")"
   rc="$(run_subject "${super}")"
   require_rc "${rc}" "0" "pin equal to a reachable upstream is accepted"
   ## Exit 0 alone does not say WHICH verdict was reached; assert the wording too,
   ## or a tool that fell through silently would satisfy this.
   if grep --fixed-strings -- "pin is current" "${run_out}" >/dev/null 2>&1; then
      pass "the reachable-remote run reports 'pin is current'"
   else
      fail "the reachable-remote run did not report a current pin"
      cat -- "${run_out}" >&2
   fi
   if grep --fixed-strings -- "remote NOT refreshed" "${run_out}" >/dev/null 2>&1; then
      fail "a reachable remote was reported as not refreshed"
   else
      pass "a reachable remote produces an unqualified verdict"
   fi
   ## Now make the remote unreachable and require the qualifier: a 'current'
   ## verdict must never read as if the remote had been consulted when it was not.
   git_quiet -C "${super}/sub" remote set-url origin "${scratch}/does-not-exist"
   rc="$(run_subject "${super}")"
   require_rc "${rc}" "0" "an unreachable remote still yields a verdict"
   if grep --fixed-strings -- "pin is current" "${run_out}" >/dev/null 2>&1; then
      pass "the unreachable-remote run still reports 'pin is current'"
   else
      fail "the unreachable-remote run reported no verdict at all"
      cat -- "${run_out}" >&2
   fi
   if grep --fixed-strings -- "remote NOT refreshed" "${run_out}" >/dev/null 2>&1; then
      pass "an unreachable remote qualifies the verdict"
   else
      fail "an unreachable remote was reported as if the remote had been consulted"
      cat -- "${run_out}" >&2
   fi
   safe-rm --recursive --force -- "${super}"

   ## ---- a git ERROR is not "diverged or ahead" ----------------------------
   ## 'merge-base --is-ancestor' exits 0 for ancestor, 1 for NOT ancestor and >1
   ## for an error. Grouping every non-zero as "deliberate, not lag" turns a git
   ## failure into an accepted pin. Forced with a 'git' shim on PATH that
   ## forwards everything except that one subcommand.
   shim_dir="${scratch}/shim"
   mkdir --parents -- "${shim_dir}"
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' '## Forward to the real git, except make one subcommand fail with an ERROR status.'
      printf '%s\n' 'for git_arg in "$@"; do'
      printf '%s\n' '   if [ "${git_arg}" = "--is-ancestor" ]; then'
      printf '%s\n' '      exit 2'
      printf '%s\n' '   fi'
      printf '%s\n' 'done'
      printf '%s\n' 'exec /usr/bin/git "$@"'
   } > "${shim_dir}/git"
   chmod 0755 -- "${shim_dir}/git"

   super="$(build_fixture "${scratch}" "${old_sha}")"
   rc=0
   ( cd -- "${super}" && PATH="${shim_dir}:${PATH}" bash "${subject_path}" sub ) >"${run_out}" 2>&1 || rc="$?"
   require_rc "${rc}" "2" "a merge-base ERROR refuses a verdict rather than accepting the pin"
   if grep --fixed-strings -- "cannot verify freshness" "${run_out}" >/dev/null 2>&1; then
      pass "the merge-base error says the pin could not be verified"
   else
      fail "the merge-base error did not report an unverifiable pin"
      cat -- "${run_out}" >&2
   fi
   safe-rm --recursive --force -- "${super}"

   ## ---- usage errors stay usage errors ------------------------------------
   super="$(build_fixture_multi "${scratch}" "fresh:${new_sha}")"
   rc="$(run_subject_all "${super}" --bogus)"
   require_rc "${rc}" "2" "--all with an unknown flag is a usage error"
   rc="$(run_subject_all "${super}" extra)"
   require_rc "${rc}" "2" "--all with a stray argument is a usage error"

   safe-rm --recursive --force -- "${scratch}"

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: all submodule-staleness assertions passed."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"
