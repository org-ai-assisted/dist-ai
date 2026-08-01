#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'build-steps.d/1100_sanity-tests'
## check-git-symlinks.
##
## THE BUG IT GUARDS: with 'core.symlinks' false, git writes a REGULAR FILE
## holding the link target wherever the index records a symlink (mode 120000)
## -- and treats that as the correct materialization, so 'git status' reports
## the tree CLEAN. Kicksecure and Whonix, the project's own operating systems
## and therefore a very likely build host, ship /etc/gitconfig with
## 'core.symlinks = false' (security-misc-shared), which makes this the DEFAULT
## there. Observed on a real build host: 25 paths in a derivative-maker checkout
## (3 in the parent, 21 in live-build, 1 in qubes-template-whonix) were 15-byte
## text files, with a clean 'git status' and no other symptom. The image would
## ship text where it should ship symlinks, and nothing names the reason.
##
## Runs the SHIPPED function, not a copy of it: the function body is extracted
## from 1100_sanity-tests and sourced with 'error' stubbed, so a regression in
## the real detection logic fails here.
##
## Asserts BOTH directions -- a detector that only ever passes is worthless:
##   - a correctly materialized checkout  -> exit 0
##   - a core.symlinks=false checkout     -> non-zero, message names core.symlinks
## plus a canary proving the bad fixture really does have a clean 'git status',
## i.e. that the cheap check would NOT have caught it.
##
## Builds throwaway git repos; needs no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

sanity_tests=""
locate_subject() {
   local candidate

   for candidate in "${DM_SANITY_TESTS:-}" \
      "${DERIVATIVE_MAKER_DIR:-}/build-steps.d/1100_sanity-tests" \
      "${HOME}/derivative-maker/build-steps.d/1100_sanity-tests"; do
      case "${candidate}" in
         ''|'/build-steps.d/1100_sanity-tests')
            continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         sanity_tests="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: no derivative-maker build-steps.d/1100_sanity-tests found." >&2
   exit 77
fi

if ! grep --quiet --fixed-strings 'check-git-symlinks()' "${sanity_tests}"; then
   fail "1100_sanity-tests does not define check-git-symlinks"
   printf '%s\n' "FAILED: 1 assertion(s)." >&2
   exit 1
fi
pass "1100_sanity-tests defines check-git-symlinks"

## It must actually be dispatched; a defined-but-uncalled check is dead code.
if grep --quiet --extended-regexp '^ +check-git-symlinks "\$@"' "${sanity_tests}"; then
   pass "check-git-symlinks is called from main"
else
   fail "check-git-symlinks is defined but never called from main"
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

workdir="$(mktemp --directory)"

## -c core.hooksPath=/dev/null: this fixture is not testing the operator's hooks.
git_at() {
   local repo
   repo="$1"
   shift
   git -c core.hooksPath=/dev/null -C "${repo}" "$@"
}

## --- fixture: a repo whose index carries a symlink ---------------------------
origin_repo="${workdir}/origin"
mkdir --parents -- "${origin_repo}"
git_at "${origin_repo}" init --quiet
git_at "${origin_repo}" config user.email 'test@example.com'
git_at "${origin_repo}" config user.name 'test'
printf '%s\n' 'payload' > "${origin_repo}/real_file"
ln --symbolic -- real_file "${origin_repo}/link_to_file"
git_at "${origin_repo}" add --all
git_at "${origin_repo}" commit --quiet --message 'with a symlink'

recorded_mode="$(git_at "${origin_repo}" ls-files --stage -- link_to_file | cut -d' ' -f1)"
if [ "${recorded_mode}" = "120000" ]; then
   pass "fixture records link_to_file as mode 120000"
else
   fail "fixture did not record a symlink (mode ${recorded_mode}); the rest proves nothing"
fi

## --- run the SHIPPED function ------------------------------------------------
## Extract the function body and source it with 'error' stubbed. 'error' comes
## from help-steps/pre in the real build and exits non-zero after printing.
run_check() {
   local target_repo
   target_repo="$1"

   bash -- "${test_dir}/git_symlink_check_inner.sh" "${target_repo}" \
      < <(sed -n '/^check-git-symlinks()/,/^}/p' -- "${sanity_tests}")
}

## Good checkout: symlink is a symlink -> must pass.
good_rc=0
good_out="$(run_check "${origin_repo}" 2>&1)" || good_rc="$?"
if [ "${good_rc}" -eq 0 ]; then
   pass "correctly materialized checkout passes"
else
   fail "correctly materialized checkout was rejected (exit ${good_rc}): ${good_out}"
fi

## --- fixture: the same tree checked out with core.symlinks=false -------------
bad_repo="${workdir}/bad"
git -c core.hooksPath=/dev/null -c core.symlinks=false \
   clone --quiet -- "${origin_repo}" "${bad_repo}"

if [ -L "${bad_repo}/link_to_file" ]; then
   fail "core.symlinks=false clone still produced a real symlink; this git cannot reproduce the bug"
else
   pass "core.symlinks=false clone materialized the symlink as a regular file"
fi

## CANARY: the whole reason this check has to exist is that the cheap check --
## 'git status' -- reports nothing. If status DID flag it, this detector would
## be redundant and the assertion below would not be proving what it claims.
bad_status="$(git_at "${bad_repo}" status --porcelain=v1)"
if [ -z "${bad_status}" ]; then
   pass "canary: git status is CLEAN on the damaged checkout, so status cannot catch this"
else
   fail "canary broken: git status flagged the damaged checkout (${bad_status}); premise no longer holds"
fi

## The damaged checkout must be rejected, by name.
bad_rc=0
bad_out="$(run_check "${bad_repo}" 2>&1)" || bad_rc="$?"
if [ "${bad_rc}" -ne 0 ]; then
   pass "core.symlinks=false checkout is rejected (exit ${bad_rc})"
else
   fail "core.symlinks=false checkout was ACCEPTED; the detector does not detect"
fi

case "${bad_out}" in
   *core.symlinks*)
      pass "rejection message names core.symlinks"
      ;;
   *)
      fail "rejection message does not name core.symlinks: ${bad_out}"
      ;;
esac

case "${bad_out}" in
   *link_to_file*)
      pass "rejection message names the offending path"
      ;;
   *)
      fail "rejection message does not name the offending path: ${bad_out}"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: git symlink materialization."
