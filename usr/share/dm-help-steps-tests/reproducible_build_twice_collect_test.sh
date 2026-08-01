#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional regression test for derivative-maker 'ci/reproducible-build-twice':
## it must collect the artifact the build actually wrote, and must derive the same
## version when re-run on a tree it has already signed.
##
## THE BUGS IT GUARDS, both of which only showed up AFTER a multi-hour build:
##
##   1. help-steps/variables strips the release-channel suffix
##      ('-developers-only') before deriving the build's output folder, but this
##      script rebuilt that path from a raw 'git describe'. It therefore cleaned
##      and searched '<binary>/18.2.2.0-developers-only-N-g<sha>' while the build
##      wrote '<binary>/18.2.2.0-N-g<sha>'. The run then dies on 'find: ... No such
##      file or directory' under errexit -- it does not even reach its own
##      "produced no <glob>" branch -- which reads as a build failure, not a path
##      bug, after the build has already cost hours.
##
##   2. help-steps/sign-tag-head tags HEAD '<tag>_<commit>_<key>' on every signed
##      build, so a plain 'git describe' on a RE-RUN resolves to that tag and the
##      second run silently emits a differently versioned image.
##
## Drives the REAL script end to end against a throwaway git repo, with
## signing-key-create / sign-and-tag / dm-build-official stubbed: the stub build
## writes its output to the STRIPPED path, exactly as help-steps/variables
## derives it, and the stub sign-and-tag creates the ephemeral tag exactly as
## sign-tag-head does. So the collection logic is exercised for real, in seconds,
## with no image build.
##
## Needs no root and no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

repo_root=""
locate_repo_root() {
   local candidate

   for candidate in "${DERIVATIVE_MAKER_DIR:-}" "${dm_checkout}"; do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}/ci/reproducible-build-twice" ]; then
         repo_root="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_repo_root; then
   printf '%s\n' "SKIP: no derivative-maker checkout with ci/reproducible-build-twice." >&2
   exit 77
fi

comparator_src="${repo_root}/packages/kicksecure/developer-meta-files/usr/bin/dm-reproducible-compare-artifacts"
if [ ! -r "${comparator_src}" ]; then
   ## The script delegates its verdict to that submodule, so without it the run
   ## cannot complete -- absent subject, not a defect.
   printf '%s\n' "SKIP: developer-meta-files submodule not checked out (no dm-reproducible-compare-artifacts)." >&2
   exit 77
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

workdir="$(mktemp --directory)"
fake_tree="${workdir}/tree"
binary_dir="${workdir}/binary"
mkdir --parents -- "${fake_tree}/ci" "${fake_tree}/help-steps" \
   "${fake_tree}/packages/kicksecure/developer-meta-files/usr/bin" "${binary_dir}"

cp -- "${repo_root}/ci/reproducible-build-twice" "${fake_tree}/ci/"
cp -- "${comparator_src}" "${fake_tree}/packages/kicksecure/developer-meta-files/usr/bin/"
chmod 0755 -- "${fake_tree}/ci/reproducible-build-twice" \
   "${fake_tree}/packages/kicksecure/developer-meta-files/usr/bin/dm-reproducible-compare-artifacts"

## The stubs are real files beside this test, so each one is readable on its own
## and shellcheck sees it. install_build_stub swaps in the variant a given case
## needs; the three are documented in their own headers.
stubs_dir="${test_dir}/reproducible_build_twice_stubs"

install_build_stub() {
   local variant="$1"

   cp -- "${stubs_dir}/dm-build-official-${variant}" \
      "${fake_tree}/help-steps/dm-build-official"
   chmod 0755 -- "${fake_tree}/help-steps/dm-build-official"
}

install_build_stub deterministic
cp -- "${stubs_dir}/signing-key-create" "${stubs_dir}/sign-and-tag" \
   "${fake_tree}/help-steps/"
chmod 0755 -- "${fake_tree}/help-steps/signing-key-create" \
   "${fake_tree}/help-steps/sign-and-tag"

## A repo shaped like derivative-maker: a channel-suffixed release tag, commits on
## top. -c core.hooksPath=/dev/null: not testing the operator's hooks.
git_fake() {
   git -c core.hooksPath=/dev/null -C "${fake_tree}" "$@"
}
git_fake init --quiet
git_fake config user.email 'test@example.com'
git_fake config user.name 'test'
git_fake add --all
git_fake commit --quiet --message 'one'
git_fake tag --annotate --message release '18.2.2.0-developers-only'
printf '%s\n' 'two' > "${fake_tree}/marker"
git_fake add --all
git_fake commit --quiet --message 'two'

expected_version="18.2.2.0-$(git_fake rev-list --count '18.2.2.0-developers-only..HEAD')-g$(git_fake rev-parse HEAD)"

run_script() {
   env binary_build_folder_dist="${binary_dir}" \
      "${fake_tree}/ci/reproducible-build-twice" \
      --target qcow2 --arch amd64 --flavor kicksecure-cli --freshness frozen
}

## --- run 1: must collect from the path the build actually wrote --------------
rc=0
out="$(run_script 2>&1)" || rc="$?"

## The tell for bug 1 is a channel-suffixed PATH in the failure: the script looked
## somewhere the build never wrote. Asserted on the path rather than on a specific
## message, because the pre-fix script does not reach its own "produced no <glob>"
## branch -- 'find' fails on the missing directory first and errexit ends the run.
case "${out}" in
   *"/18.2.2.0-developers-only"*)
      fail "run 1: referenced a channel-suffixed output path; the build writes the stripped one"
      ;;
   *)
      pass "run 1: never referenced a channel-suffixed output path"
      ;;
esac

if [ "${rc}" -eq 0 ]; then
   pass "run 1: exit 0 (collected both, comparator says identical)"
else
   fail "run 1: exit ${rc}, expected 0 -- output: ${out}"
fi

if [ -n "$(find "${binary_dir}" -path '*/a/*' -name '*.qcow2.libvirt.xz' -print -quit)" ] \
   && [ -n "$(find "${binary_dir}" -path '*/b/*' -name '*.qcow2.libvirt.xz' -print -quit)" ]; then
   pass "run 1: collected an artifact for BOTH builds"
else
   fail "run 1: did not collect both artifacts"
fi

## The version it built under must be the stripped one.
if [ -d "${binary_dir}/${expected_version}" ]; then
   pass "run 1: built under the stripped version (${expected_version})"
else
   fail "run 1: no ${binary_dir}/${expected_version}; got: $(find "${binary_dir}" -maxdepth 1 -mindepth 1 -type d -printf '%f ')"
fi

## --- run 2: the ephemeral tag from run 1 must not change the version ---------
## HEAD now carries '<tag>_<commit>_<key>' from the stub sign-and-tag.
if [ -z "$(git_fake tag --points-at HEAD | grep -E '_[0-9A-Fa-f]{64}$' || true)" ]; then
   fail "fixture: run 1 left no ephemeral tag; run 2 would not exercise the hazard"
else
   pass "fixture: run 1 left an ephemeral signing tag at HEAD"
fi

rc=0
out="$(run_script 2>&1)" || rc="$?"

if [ "${rc}" -eq 0 ]; then
   pass "run 2: exit 0 on a tree already signed by run 1"
else
   fail "run 2: exit ${rc}, expected 0 -- output: ${out}"
fi

## Still the SAME version directory: no second, differently versioned tree.
version_dir_count="$(find "${binary_dir}" -maxdepth 1 -mindepth 1 -type d -name '18.2.2.0*' | wc -l)"
if [ "${version_dir_count}" -eq 1 ]; then
   pass "run 2: reused the same version directory (no ephemeral-tag drift)"
else
   fail "run 2: ${version_dir_count} version directories exist; the re-run derived a different version"
fi

## --- failure paths: only bad outcomes reach these, so no green run does ------
## The exit contract is load-bearing: 0 reproducible, 1 differ, 2 usage /
## artifact-not-found, 3 a build failed. Conflating 1 with 2 or 3 is how a
## not-found once read as "images differ".

reset_binary_dir() {
   safe-rm --recursive --force -- "${binary_dir}"
   mkdir --parents -- "${binary_dir}"
}

## A build that fails must surface as 3, not as a comparison verdict.
install_build_stub fails
reset_binary_dir
rc=0
out="$(run_script 2>&1)" || rc="$?"
if [ "${rc}" -eq 3 ]; then
   pass "failing build: exit 3"
else
   fail "failing build: exit ${rc}, expected 3 -- a build failure must not read as a reproducibility verdict"
fi
install_build_stub deterministic

## A build that succeeds but emits no artifact is also 3, and must SAY the glob.
install_build_stub empty
reset_binary_dir
rc=0
out="$(run_script 2>&1)" || rc="$?"
if [ "${rc}" -eq 3 ]; then
   pass "build produced nothing: exit 3"
else
   fail "build produced nothing: exit ${rc}, expected 3"
fi
case "${out}" in
   *"produced no"*)
      pass "build produced nothing: names the missing glob"
      ;;
   *)
      fail "build produced nothing: does not name what was missing -- ${out}"
      ;;
esac
install_build_stub deterministic

## Two DIFFERING artifacts must propagate the comparator's exit 1 unchanged.
install_build_stub differing
reset_binary_dir
rc=0
out="$(run_script 2>&1)" || rc="$?"
if [ "${rc}" -eq 1 ]; then
   pass "differing builds: comparator's exit 1 propagates"
else
   fail "differing builds: exit ${rc}, expected 1 -- the verdict must reach the caller"
fi
install_build_stub deterministic

## Usage errors are 2, distinct from every build/compare outcome.
assert_usage_error() {
   local description="$1"
   shift
   local usage_rc=0

   env binary_build_folder_dist="${binary_dir}" \
      "${fake_tree}/ci/reproducible-build-twice" "$@" >/dev/null 2>&1 || usage_rc="$?"
   if [ "${usage_rc}" -eq 2 ]; then
      pass "${description}: exit 2"
   else
      fail "${description}: exit ${usage_rc}, expected 2"
   fi
}

assert_usage_error "missing --arch" --target qcow2
assert_usage_error "unknown target" --target nonsense --arch amd64
assert_usage_error "unexpected argument" --target qcow2 --arch amd64 --nonsense

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: reproducible-build-twice collection."
