#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for how derivative-maker derives 'dist_build_version'.
##
## THE BUGS IT GUARDS -- both cost a full multi-hour build to discover, and both
## surface as something that does not name the real cause:
##
##   1. Release-channel suffix. 'help-steps/variables' strips
##      '-developers-only' / '-testers-only' / '-stable' BEFORE deriving
##      'dist_binary_build_folder', but 'ci/reproducible-build-twice' rebuilt the
##      same path from a RAW 'git describe'. With the repo's nearest tag being
##      '18.2.2.0-developers-only' the script cleaned and searched
##      '<binary>/18.2.2.0-developers-only-161-g<sha>' while the build wrote
##      '<binary>/18.2.2.0-161-g<sha>' -- so it reported
##      "build a produced no *.qcow2.libvirt.xz" and exited 3 AFTER building,
##      which reads as a build failure rather than a path bug.
##
##   2. Ephemeral signing tags. 'help-steps/sign-tag-head' tags HEAD
##      '<nearest-tag>_<commit>_<key-fingerprint>' (or 'tag_<commit>_<key>') on
##      every locally signed build. A plain 'git describe' then resolves to THAT
##      tag on the next run, so a re-run on the same checkout silently emits a
##      differently versioned image -- and a version comparison against CI
##      becomes meaningless without anything failing.
##
## Asserts BOTH the shipped contract and the semantics it relies on, and
## CANARIES the semantics: each check is also run against the pre-fix form and
## must come out WRONG there. An assertion that cannot fail is worthless.
##
## Builds a throwaway git repo; needs no root, no network.

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

## Resolve the two shipped files under test. exit 1 (FATAL) when no
## derivative-maker checkout is present -- a required subject absent is an
## environment bug that must fail loud, not skip (R-220).
repo_root=""
locate_repo_root() {
   local candidate

   for candidate in "${DERIVATIVE_MAKER_DIR:-}" "${dm_checkout}"; do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}/ci/reproducible-build-twice" ] \
         && [ -r "${candidate}/help-steps/variables" ]; then
         repo_root="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_repo_root; then
   printf '%s\n' "FATAL: no derivative-maker checkout with ci/reproducible-build-twice + help-steps/variables." >&2
   exit 1
fi

build_twice="${repo_root}/ci/reproducible-build-twice"
variables="${repo_root}/help-steps/variables"

## --- fixture -----------------------------------------------------------------
## A repo shaped like derivative-maker at build time: a channel-suffixed release
## tag, some commits on top, and an ephemeral signing tag sitting at HEAD.
fixture=""
cleanup() {
   [ -z "${fixture}" ] || safe-rm --recursive --force -- "${fixture}"
}
trap cleanup EXIT

fixture="$(mktemp --directory)"
## -c core.hooksPath=/dev/null: this fixture is not testing the operator's hooks.
git_fixture() {
   git -c core.hooksPath=/dev/null -C "${fixture}" "$@"
}

git_fixture init --quiet
git_fixture config user.email 'test@example.com'
git_fixture config user.name 'test'

printf '%s\n' 'one' > "${fixture}/file"
git_fixture add -- file
git_fixture commit --quiet --message 'one'
git_fixture tag --annotate --message 'release' '18.2.2.0-developers-only'

printf '%s\n' 'two' > "${fixture}/file"
git_fixture commit --quiet --all --message 'two'

head_sha="$(git_fixture rev-parse HEAD)"
## Same shape sign-tag-head builds: '<nearest-tag>_<commit>_<64-hex key>'.
key_fpr='1B69AFB06DECDCC5404CFD34238AF23072D1DB5E01C1C3A5D6F2207ED3E0C4C6'
ephemeral_tag="18.2.2.0-developers-only_${head_sha}_${key_fpr}"
git_fixture tag --annotate --message 'ephemeral' -- "${ephemeral_tag}"

## --- semantics + canary ------------------------------------------------------
## What the fixed derivation must produce, and what the pre-fix one produced.
fixed_describe="$(git_fixture describe --always --abbrev=1000000000 --exclude '*_*_*')"
prefix_describe="$(git_fixture describe --always --abbrev=1000000000)"

case "${fixed_describe}" in
   *"${key_fpr}"*)
      fail "--exclude did not skip the ephemeral signing tag: ${fixed_describe}"
      ;;
   18.2.2.0-developers-only-1-g*)
      pass "--exclude skips the ephemeral signing tag (${fixed_describe})"
      ;;
   *)
      fail "unexpected describe output with --exclude: ${fixed_describe}"
      ;;
esac

## CANARY: the pre-fix form MUST pick the ephemeral tag here, otherwise this
## fixture cannot tell the two apart and the assertion above proves nothing.
case "${prefix_describe}" in
   *"${key_fpr}"*)
      pass "canary: pre-fix describe does resolve to the ephemeral tag"
      ;;
   *)
      fail "canary broken: pre-fix describe did not pick the ephemeral tag (${prefix_describe}); the check above cannot fail"
      ;;
esac

## The channel strip, applied exactly as the shipped code applies it.
stripped="${fixed_describe//-developers-only/}"
stripped="${stripped//-testers-only/}"
stripped="${stripped//-stable/}"

case "${stripped}" in
   *-developers-only*)
      fail "channel suffix survived the strip: ${stripped}"
      ;;
   18.2.2.0-1-g*)
      pass "channel suffix stripped (${stripped})"
      ;;
   *)
      fail "unexpected value after strip: ${stripped}"
      ;;
esac

## CANARY: unstripped must still carry the suffix, else the strip check is moot.
case "${fixed_describe}" in
   *-developers-only*)
      pass "canary: unstripped value does carry the channel suffix"
      ;;
   *)
      fail "canary broken: unstripped value has no channel suffix; the strip check cannot fail"
      ;;
esac

## --- shipped contract --------------------------------------------------------
## The semantics above are only enforced if the shipped scripts actually ask for
## them. Grep the real files, so removing '--exclude' or a strip line fails here.
## Fixed strings, not regex: the shipped lines are quoted shell containing '$',
## '{', '*' and '/', so an ERE of them is all backslash and easy to get subtly
## wrong -- a pattern that never matches would make this a test that always fails,
## and one that matches too loosely a test that never can.
assert_contains() {
   local file needle label
   file="$1"
   needle="$2"
   label="$3"

   if grep --quiet --fixed-strings -- "${needle}" "${file}"; then
      pass "${label}"
   else
      fail "${label} -- not found in ${file}"
   fi
}

exclude_needle="describe --always --abbrev=1000000000 --exclude '*_*_*'"

assert_contains "${variables}" "${exclude_needle}" \
   "help-steps/variables excludes ephemeral signing tags"

assert_contains "${build_twice}" "${exclude_needle}" \
   "ci/reproducible-build-twice excludes ephemeral signing tags"

for suffix in developers-only testers-only stable; do
   assert_contains "${build_twice}" \
      "dist_build_version//-${suffix}/" \
      "ci/reproducible-build-twice strips -${suffix}"
done

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: build version derivation."
