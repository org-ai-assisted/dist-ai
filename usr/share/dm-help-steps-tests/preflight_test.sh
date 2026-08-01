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
   printf '%s\n' "SKIP: dm-preflight not found (set DM_PREFLIGHT)." >&2
   exit 77
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
      printf 'x\n' > "${sub_origin}/file.txt"
      git_quiet -C "${sub_origin}" add file.txt
      git_quiet -C "${sub_origin}" commit --quiet --no-verify --message base
   fi

   git_quiet init --quiet -- "${super}"
   mkdir --parents -- "${super}/build-steps.d" "${super}/help-steps"
   printf 'x\n' > "${super}/build-steps.d/keep"
   printf 'x\n' > "${super}/help-steps/keep"
   git_quiet -C "${super}" add -A
   git_quiet -C "${super}" commit --quiet --no-verify --message base
   git_quiet -C "${super}" -c protocol.file.allow=always \
      submodule --quiet add -- "${sub_origin}" sub 2>/dev/null
   git_quiet -C "${super}" commit --quiet --no-verify --message pin
}

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
printf 'uncommitted\n' >> "${dirty}/sub/file.txt"
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
printf 'x\n' > "${dirty}/sub/untracked.txt"
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
printf 'more\n' >> "${ahead}/sub/file.txt"
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
