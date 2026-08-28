#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for 'dm-preflight'.
##
## THE BUG IT GUARDS: a parent commit was pushed while the developer-meta-files
## changes were still UNCOMMITTED inside the submodule. The parent records a
## pointer, so the commit carried none of that work; CI then built a tree without
## the fix under test and three unrelated tests failed against the stale pinned
## copy. Nothing reported it, because nothing looked.
##
## The distinction that makes the tool usable is asserted here too: uncommitted
## work FAILS, while a submodule merely ahead of its pin only REPORTS. The second
## is the normal state while work is in progress on a submodule branch, and
## failing on it in a tree with thirty submodules would train everyone to ignore
## the check that matters.
##
## Builds throwaway git repos; needs no root, no network, no build.

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

subject=""
for candidate in "${DM_PREFLIGHT:-}" \
   "${test_dir}/../../bin/dm-preflight" \
   "/usr/bin/dm-preflight"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-preflight not found (set DM_PREFLIGHT)." >&2
   exit 1
fi

git_quiet() {
   git -c core.hooksPath=/dev/null -c user.email=ci-test@example.com -c user.name=ci-test "$@"
}

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

## A minimal tree that dm-preflight accepts as a derivative-maker checkout, with
## one real submodule whose state each case then varies.
build_fixture() {
   local super="$1" sub_origin="${workdir}/sub-origin"

   if [ ! -d "${sub_origin}" ]; then
      git_quiet init --quiet -- "${sub_origin}"
      printf '%s\n' 'x' > "${sub_origin}/file.txt"
      git_quiet -C "${sub_origin}" add file.txt
      git_quiet -C "${sub_origin}" commit --quiet --no-verify --message base
   fi

   git_quiet init --quiet -- "${super}"
   mkdir --parents -- "${super}/build-steps.d" "${super}/help-steps"
   printf '%s\n' 'x' > "${super}/build-steps.d/keep"
   printf '%s\n' 'x' > "${super}/help-steps/keep"
   ## A real dm checkout always carries in-tree `source "${folder_var}/..."`
   ## references; the sourced-paths stage resolves the ones fixed relative to the
   ## root and fails a MISSING target. Give the fixture one RESOLVABLE ref (and
   ## its target) so that stage passes here; the renamed-away case below removes
   ## the target to exercise the failure.
   local dmf="${super}/packages/kicksecure/developer-meta-files/usr/libexec/developer-meta-files"
   mkdir --parents -- "${dmf}"
   printf '%s\n' '## stub' > "${dmf}/package-build-freshness.bsh"
   printf '%s\n' \
      'source "${dist_developer_meta_files_folder}/usr/libexec/developer-meta-files/package-build-freshness.bsh"' \
      > "${super}/build-steps.d/2100_stub"
   git_quiet -C "${super}" add -A
   git_quiet -C "${super}" commit --quiet --no-verify --message base
   git_quiet -C "${super}" -c protocol.file.allow=always \
      submodule --quiet add -- "${sub_origin}" sub 2>/dev/null
   git_quiet -C "${super}" commit --quiet --no-verify --message pin
}

## dm-preflight treats a missing 'dist-ai-style' as a FAILURE, deliberately --
## an unverified tree is not a verified one. That makes these cases depend on the
## gate being reachable, and in CI it is present in the dist-ai checkout but not
## on PATH. Put the sibling bin/ in front rather than weakening the tool or
## skipping the test: the binary is right there.
gate_bin_dir="$( cd -- "${test_dir}/../../bin" 2>/dev/null && pwd || true )"
if [ -n "${gate_bin_dir}" ] && [ -x "${gate_bin_dir}/dist-ai-style" ]; then
   PATH="${gate_bin_dir}:${PATH}"
   export PATH
fi
if ! type -P dist-ai-style >/dev/null; then
   printf '%s\n' "FATAL: dist-ai-style not reachable; dm-preflight cannot complete a run." >&2
   exit 1
fi

## --quick: the suites are not what these cases are about, and running them here
## would make the result depend on an unrelated checkout.
run_preflight() {
   local super="$1" rc=0
   "${subject}" --dir "${super}" --quick >"${workdir}/out.txt" 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

## --- a clean tree passes ----------------------------------------------------
## The canary for everything below: without it, a tool that failed unconditionally
## would satisfy every negative assertion.
clean="${workdir}/clean"
build_fixture "${clean}"
rc="$(run_preflight "${clean}")"
if [ "${rc}" -eq 0 ]; then
   pass "canary: a clean checkout passes"
else
   fail "canary broken: a clean checkout was rejected (${rc})"
   cat -- "${workdir}/out.txt" >&2
fi

## --- uncommitted work in a submodule FAILS ----------------------------------
dirty="${workdir}/dirty"
build_fixture "${dirty}"
printf '%s\n' 'uncommitted' >> "${dirty}/sub/file.txt"
rc="$(run_preflight "${dirty}")"
if [ "${rc}" -ne 0 ]; then
   pass "uncommitted work in a submodule fails the preflight"
else
   fail "uncommitted submodule work was ACCEPTED -- the parent commit would not carry it"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'sub' "${workdir}/out.txt"; then
   pass "the failure names the submodule"
else
   fail "the failure does not name the submodule"
   cat -- "${workdir}/out.txt" >&2
fi
## An UNTRACKED file counts: it is work the parent will not carry either.
git_quiet -C "${dirty}/sub" checkout --quiet -- file.txt
printf '%s\n' 'x' > "${dirty}/sub/untracked.txt"
rc="$(run_preflight "${dirty}")"
if [ "${rc}" -ne 0 ]; then
   pass "an untracked file in a submodule also fails"
else
   fail "an untracked submodule file was accepted"
fi

## --- merely AHEAD of the pin only reports -----------------------------------
## The normal state while work is in progress on a submodule branch.
ahead="${workdir}/ahead"
build_fixture "${ahead}"
printf '%s\n' 'more' >> "${ahead}/sub/file.txt"
git_quiet -C "${ahead}/sub" commit --quiet --all --no-verify --message ahead
rc="$(run_preflight "${ahead}")"
if [ "${rc}" -eq 0 ]; then
   pass "a submodule ahead of its pin does not fail the preflight"
else
   fail "a submodule ahead of its pin was rejected; that is the normal in-progress state"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'AHEAD of the pin' "${workdir}/out.txt"; then
   pass "being ahead of the pin is still REPORTED"
else
   fail "being ahead of the pin was neither failed nor reported, so it is invisible"
   cat -- "${workdir}/out.txt" >&2
fi

## --- an UNFETCHABLE pin fails; an unverifiable one only reports -------------
## The property CI actually needs: a pin it can fetch. A submodule commit that
## exists only locally leaves 'git submodule update --init' failing in the job,
## long after the runner was allocated.
##
## And the counterpart that keeps the check usable: a scratch clone whose
## submodule remotes are LOCAL PATHS cannot answer the question at all, so it is
## reported UNVERIFIED rather than failed. A check that cries wolf on every
## scratch clone is one everyone learns to ignore -- which is how the real
## failures get missed.
unfetch="${workdir}/unfetch"
build_fixture "${unfetch}"
## Commit in the submodule WITHOUT pushing, then pin the parent at it: the exact
## shape of "committed locally, never pushed".
printf '%s\n' 'local only' >> "${unfetch}/sub/file.txt"
git_quiet -C "${unfetch}/sub" commit --quiet --all --no-verify --message local-only
local_only_sha="$(git_quiet -C "${unfetch}/sub" rev-parse HEAD)"
git_quiet -C "${unfetch}" update-index --cacheinfo "160000,${local_only_sha},sub"
git_quiet -C "${unfetch}" commit --quiet --no-verify --message pin-unpushed
## Give the submodule a network-shaped remote so the check will actually judge
## it; the URL is never contacted, only its SHAPE decides verifiability.
git_quiet -C "${unfetch}/sub" remote add net https://example.com/sub.git
rc="$(run_preflight "${unfetch}")"
if [ "${rc}" -ne 0 ]; then
   pass "a pin on no remote branch fails the preflight"
else
   fail "an unfetchable pin was ACCEPTED; CI would fail on 'git submodule update --init'"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'UNFETCHABLE' "${workdir}/out.txt"; then
   pass "the failure names the unfetchable pin"
else
   fail "the failure does not name the unfetchable pin"
   cat -- "${workdir}/out.txt" >&2
fi

## CANARY: without a network remote the same tree must NOT fail -- it must say
## it could not tell.
git_quiet -C "${unfetch}/sub" remote remove net
rc="$(run_preflight "${unfetch}")"
if [ "${rc}" -eq 0 ]; then
   pass "canary: with no network remote the pin is not judged"
else
   fail "canary broken: a clone that cannot answer the question was failed anyway"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'UNVERIFIED' "${workdir}/out.txt"; then
   pass "canary: and it says fetchability was NOT established"
else
   fail "canary broken: silently passed without saying the check did not run"
   cat -- "${workdir}/out.txt" >&2
fi

## --- a submodule with NO url in .gitmodules FAILS (unclonable) ---------------
## 'git submodule update --init' dies "fatal: No url found for submodule path"
## on such a pin (exit 128), so a preflight that only NOTED it would green-light a
## commit CI cannot check out -- the exact silent-green a preflight exists to stop.
nourl="${workdir}/nourl"
build_fixture "${nourl}"
## A network-shaped remote so the pin clears the fetchability gates and reaches
## the .gitmodules-url lookup; then strip the url from .gitmodules.
git_quiet -C "${nourl}/sub" remote add net https://example.com/sub.git
git_quiet -C "${nourl}" config -f .gitmodules --unset submodule.sub.url
git_quiet -C "${nourl}" commit --quiet --all --no-verify --message strip-url
rc="$(run_preflight "${nourl}")"
if [ "${rc}" -ne 0 ]; then
   pass "a submodule with no url in .gitmodules fails the preflight"
else
   fail "a NO-URL submodule was ACCEPTED; 'git submodule update --init' would fail on it"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'No url found' "${workdir}/out.txt"; then
   pass "the failure explains the unclonable NO-URL pin"
else
   fail "the failure does not explain the NO-URL pin"
   cat -- "${workdir}/out.txt" >&2
fi

## --- an ABSENT-locally pin the remote still serves PASSES -------------------
## The benign "a teammate bumped the pin and this submodule was not re-fetched
## here yet" state: the pinned commit is not in this clone, but the remote still
## has it. Short-circuiting to MISSING failed it; the network probe must get the
## final say. Only a pin the REMOTE also lacks is a true MISSING.
absent="${workdir}/absent"
build_fixture "${absent}"
## A bare remote carrying commit X as its master TIP, made in a throwaway clone.
absent_remote="${workdir}/absent-remote.git"
git_quiet init --quiet --bare -- "${absent_remote}"
absent_maker="${workdir}/absent-maker"
git_quiet -c protocol.file.allow=always clone --quiet -- "${absent}/sub" "${absent_maker}" >/dev/null 2>&1
printf '%s\n' 'downstream' >> "${absent_maker}/file.txt"
git_quiet -C "${absent_maker}" commit --quiet --all --no-verify --message downstream
absent_sha="$(git_quiet -C "${absent_maker}" rev-parse HEAD)"
git_quiet -C "${absent_maker}" push --quiet -- "${absent_remote}" HEAD:refs/heads/master
## Point 'sub' at the bare remote (a network-shaped file:// url). 'submodule
## foreach' exports GIT_PROTOCOL_FROM_USER=0, which blocks file://; allow it at
## the submodule level so the probe can contact the remote (production remotes
## are https/ssh and unaffected).
git_quiet -C "${absent}/sub" remote add net "file://${absent_remote}"
git_quiet -C "${absent}/sub" config protocol.file.allow always
git_quiet -C "${absent}" config -f .gitmodules submodule.sub.url "file://${absent_remote}"
git_quiet -C "${absent}" commit --quiet --all --no-verify --message net-url
## Pin the parent at X with '-m' (NOT '-am'): '-am' would restage the gitlink
## from 'sub's HEAD and undo the pin. X stays absent from 'sub's object store.
git_quiet -C "${absent}" update-index --cacheinfo "160000,${absent_sha},sub"
git_quiet -C "${absent}" commit --quiet --no-verify --message pin-absent
rc="$(run_preflight "${absent}")"
if [ "${rc}" -eq 0 ]; then
   pass "an absent-locally pin the remote still serves does not fail"
else
   fail "an absent-but-fetchable pin was FAILED (the benign not-refetched-here state)"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'MISSING' "${workdir}/out.txt"; then
   fail "the absent-but-fetchable pin was wrongly reported MISSING"
else
   pass "the absent-but-fetchable pin is not reported MISSING"
fi

## --- a 'source' of a renamed-away in-tree file FAILS ------------------------
## The developer-meta-files reprepro-freshness.bsh -> package-build-freshness.bsh
## rename with the consumer (2100_create-debian-packages) not updated. It is a
## statically resolvable reference, so it must be caught here, not mid-build.
renamed="${workdir}/renamed"
build_fixture "${renamed}"
## Repoint the consumer at a sibling name that does not exist -- exactly what a
## submodule rename leaves behind when the pin is bumped but the consumer is not.
printf '%s\n' \
   'source "${dist_developer_meta_files_folder}/usr/libexec/developer-meta-files/reprepro-freshness.bsh"' \
   > "${renamed}/build-steps.d/2100_stub"
git_quiet -C "${renamed}" commit --quiet --all --no-verify --message repoint
rc="$(run_preflight "${renamed}")"
if [ "${rc}" -ne 0 ]; then
   pass "a source of a renamed-away in-tree file fails the preflight"
else
   fail "a source of a missing in-tree file was ACCEPTED -- it would die mid-build instead"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'reprepro-freshness.bsh' "${workdir}/out.txt"; then
   pass "the failure names the missing source target"
else
   fail "the failure does not name the missing source target"
   cat -- "${workdir}/out.txt" >&2
fi

## --- a missing target with MORE THAN ONE space after 'source' still FAILS ----
## The extraction must not assume exactly one space; 'source  "..."' (two spaces)
## must resolve + existence-check like the single-space case, not slip through as
## a skipped ref.
twospace="${workdir}/twospace"
build_fixture "${twospace}"
printf '%s\n' \
   'source  "${dist_developer_meta_files_folder}/usr/libexec/developer-meta-files/two-space-missing.bsh"' \
   > "${twospace}/build-steps.d/2100_stub"
git_quiet -C "${twospace}" commit --quiet --all --no-verify --message twospace
rc="$(run_preflight "${twospace}")"
if [ "${rc}" -ne 0 ] && grep --quiet --fixed-strings -- 'two-space-missing.bsh' "${workdir}/out.txt"; then
   pass "a missing target with two spaces after 'source' is still caught"
else
   fail "a two-space 'source' to a missing target slipped the check"
   cat -- "${workdir}/out.txt" >&2
fi

## --- a git submodule failure is FAILED, not reported green ------------------
## An unparsable .gitmodules (a merge-conflict marker) makes every 'git
## submodule' command exit 128. The submodule stages must FAIL loud, not read
## the empty output through '|| true' as "ok" -- the fabricated-green this
## preflight exists to prevent.
gitfail="${workdir}/gitfail"
build_fixture "${gitfail}"
printf '<<<<<<< HEAD\n' >> "${gitfail}/.gitmodules"
git_quiet -C "${gitfail}" commit --quiet --all --no-verify --message corrupt-gitmodules
rc="$(run_preflight "${gitfail}")"
if [ "${rc}" -ne 0 ]; then
   pass "an unparsable .gitmodules (git submodule exits 128) fails the preflight"
else
   fail "a git submodule failure was reported GREEN -- fabricated"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'a green here would be fabricated' "${workdir}/out.txt"; then
   pass "the failure says the submodule check could not run, not 'ok'"
else
   fail "the git-failure was not surfaced as a check-could-not-run failure"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'no initialized submodule carries uncommitted changes' "${workdir}/out.txt"; then
   fail "still printed the green uncommitted-work line despite git failing -- fabricated-green"
else
   pass "does not print the green uncommitted-work line on a git failure"
fi

## --- a non-checkout is a usage error, not a pass ----------------------------
rc=0
"${subject}" --dir "${workdir}" --quick >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -eq 2 ]; then
   pass "a directory that is not a derivative-maker checkout exits 2"
else
   fail "a non-checkout exited ${rc}; expected 2"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-preflight."
