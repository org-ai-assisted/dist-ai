#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-reproducible-buildinfo': the
## record's two source fields must name the SAME commit.
##
## THE BUG IT GUARDS: 'Source-Commit' is recorded PRE-SIGN by
## help-steps/sign-and-tag into the dm-source-state file, while
## 'dist_build_version' is auto-detected with 'git describe' ONLY when it is
## unset -- so a value inherited from the environment silently wins over the
## actual tree. An observed record carried
## 'Source-Commit: 02096cd4...' alongside
## 'Source-Version: 18.2.2.0-217-ge65ff458...', i.e. two DIFFERENT commits in the
## same record. A rebuild keyed on either field then reproduces the wrong tree,
## which is exactly what a provenance record exists to prevent, and nothing else
## checked it.
##
## 'git describe' ends in '-g<sha>' and that sha IS the described commit, so when
## the suffix is present it must equal Source-Commit. A clean tag build carries no
## suffix and must NOT be constrained -- the false-positive cases below are as
## much the point as the failing one.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## The derivative-maker checkout under test. An explicitly named tree is the ONLY
## answer: falling back to '~/derivative-maker' reports on a DIFFERENT tree than
## the caller asked about.
if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

subject=""
for candidate in "${DM_BUILDINFO:-}" \
   "${DEVELOPER_META_FILES_DIR:-}/usr/bin/dm-reproducible-buildinfo" \
   "${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-reproducible-buildinfo" \
   "/usr/bin/dm-reproducible-buildinfo"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "SKIP: dm-reproducible-buildinfo not found (set DM_BUILDINFO)." >&2
   exit 77
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

run_seq=0

## Run the generator with the two source variables set explicitly, and return its
## exit code. Both are passed on every call so a case is a real choice rather than
## whatever the surrounding environment happened to hold.
run_with() {
   local version="$1" commit="$2" image rc

   run_seq=$(( run_seq + 1 ))
   image="${workdir}/image-${run_seq}.raw"
   printf '' > "${image}"
   ## Source-Commit reaches the record through the PRE-SIGN state file that
   ## help-steps/sign-and-tag writes, not through an environment variable, so the
   ## fixture must be that file or the check under test never sees a commit.
   printf 'Source-Commit: %s\nSubmodule-State:\n abc123 packages/example (v1)\n' \
      "${commit}" > "${workdir}/dm-source-state"
   rc=0
   env \
      dist_build_version="${version}" \
      binary_build_folder_dist="${workdir}" \
      bash -- "${subject}" \
         --image "${image}" \
         --target qcow2 \
         --output "${workdir}/out-${run_seq}.buildinfo" \
      >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

## <description> <expected-nonzero|expected-zero> <version> <commit>
expect_refused() {
   local description="$1" version="$2" commit="$3" rc

   rc="$(run_with "${version}" "${commit}")"
   if [ "${rc}" -ne 0 ]; then
      pass "refused: ${description} (exit ${rc})"
   else
      fail "ACCEPTED a record whose source fields disagree: ${description}"
   fi
}

expect_accepted() {
   local description="$1" version="$2" commit="$3" rc

   rc="$(run_with "${version}" "${commit}")"
   if [ "${rc}" -eq 0 ]; then
      pass "accepted: ${description}"
   else
      fail "REFUSED a legitimate build: ${description} (exit ${rc})"
   fi
}

## The real observed divergence.
expect_refused 'describe suffix names a different commit than Source-Commit' \
   '18.2.2.0-217-ge65ff45812c4de50c8e00aad5b3db16169ec2507' \
   '02096cd4501e9a458d522f1c012cf85e4cfc035f'

## Short forms of the same defect must be caught too.
expect_refused 'short describe suffix disagrees' \
   '18.2.2.0-217-ge65ff458' \
   '02096cd4'

## Everything below is a LEGITIMATE build and must not be constrained. These
## matter as much as the refusal: a check that fails a clean tag build would be
## reverted, not fixed.
expect_accepted 'describe suffix agrees with Source-Commit' \
   '18.2.2.0-217-gabc123def456' \
   'abc123def456'

expect_accepted 'clean tag build, no describe suffix' \
   '18.2.2.0' \
   'abc123def456'

## A tag may legitimately contain '-g'; only a HEX suffix is a describe sha.
expect_accepted 'tag contains -g but the suffix is not hex' \
   '18.2.2.0-rc1-gui-release' \
   'abc123def456'

expect_accepted 'version unset (auto-detected by the build)' \
   '' \
   'abc123def456'

expect_accepted 'state block unrecorded, nothing to compare against' \
   '18.2.2.0-217-gdeadbeef' \
   'unrecorded (test fixture)'

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "test_buildinfo_source_fields_agree: ${test_failures} failure(s)" >&2
   exit 1
fi
printf '%s\n' "test_buildinfo_source_fields_agree: OK -- disagreeing source fields refused, legitimate builds spared."
