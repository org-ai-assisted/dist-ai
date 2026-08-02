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

## --dry-run must emit the SAME record as a real run, or the fast path proves
## nothing about the slow one. It skips ONLY the image existence check.
dry_image="${workdir}/dry-image.raw"
printf 'Source-Commit: %s\nSubmodule-State:\n abc123 packages/example (v1)\n' \
   'abc123def456' > "${workdir}/dm-source-state"
printf '' > "${dry_image}"
env dist_build_version='18.2.2.0-217-gabc123def456' binary_build_folder_dist="${workdir}" \
   bash -- "${subject}" --image "${dry_image}" --target qcow2 \
   --output "${workdir}/real-vs-dry.real" >/dev/null 2>&1
env dist_build_version='18.2.2.0-217-gabc123def456' binary_build_folder_dist="${workdir}" \
   bash -- "${subject}" --dry-run --image "${dry_image}" --target qcow2 \
   --output "${workdir}/real-vs-dry.dry" >/dev/null 2>&1
if cmp --silent -- "${workdir}/real-vs-dry.real" "${workdir}/real-vs-dry.dry"; then
   pass '--dry-run emits a record identical to a real run'
else
   fail '--dry-run record DIFFERS from a real run -- the fast path does not model the slow one'
fi

## ... and it must still work when the image does not exist at all, which is the
## whole point: the record is derivable long before the artifact is.
safe-rm --force -- "${dry_image}"
dry_rc=0
env dist_build_version='18.2.2.0-217-gabc123def456' binary_build_folder_dist="${workdir}" \
   bash -- "${subject}" --dry-run --image "${dry_image}" --target qcow2 \
   --output "${workdir}/real-vs-dry.noimage" >/dev/null 2>&1 || dry_rc="$?"
if [ "${dry_rc}" -eq 0 ] \
   && cmp --silent -- "${workdir}/real-vs-dry.real" "${workdir}/real-vs-dry.noimage"; then
   pass '--dry-run works with NO image present and still matches'
else
   fail "--dry-run failed or differed with no image present (rc=${dry_rc})"
fi

## Without --dry-run a missing image must STILL be refused: the fast path is opt-in.
strict_rc=0
env dist_build_version='18.2.2.0-217-gabc123def456' binary_build_folder_dist="${workdir}" \
   bash -- "${subject}" --image "${dry_image}" --target qcow2 \
   --output "${workdir}/real-vs-dry.strict" >/dev/null 2>&1 || strict_rc="$?"
if [ "${strict_rc}" -ne 0 ]; then
   pass 'without --dry-run a missing image is still refused'
else
   fail 'a missing image was accepted WITHOUT --dry-run -- the check is gone, not opt-in'
fi

## An image built with --reproducible-dist-build-version is NOT what an official
## build of the same commit produces, so the record must say so -- otherwise it is
## indistinguishable from a release artifact and a comparison against one would
## read the difference as a reproducibility failure.
printf 'Source-Commit: %s\nSubmodule-State:\n abc123 packages/example (v1)\n' \
   'abc123def456' > "${workdir}/dm-source-state"
printf '' > "${workdir}/norm.raw"
env dist_build_version='18.2.2.0' binary_build_folder_dist="${workdir}" \
   dist_build_version_reproducible='true' \
   bash -- "${subject}" --dry-run --image "${workdir}/norm.raw" --target qcow2 \
   --output "${workdir}/normalized.bi" >/dev/null 2>&1
if grep --quiet '^Version-Normalized: true' -- "${workdir}/normalized.bi"; then
   pass 'a normalized build is marked Version-Normalized in the record'
else
   fail 'a normalized build is NOT marked -- indistinguishable from a release artifact'
fi

## BOTH versions must be recorded. Keeping only the normalized one discards what
## the version would have been, so a normalized image cannot be tied back to the
## release artifact it corresponds to without the repo in hand.
printf '' > "${workdir}/norm2.raw"
env dist_build_version='18.2.2.0' binary_build_folder_dist="${workdir}" \
   dist_build_version_reproducible='true' \
   dist_build_version_unnormalized='18.2.2.0-219-gdeadbeefcafe' \
   bash -- "${subject}" --dry-run --image "${workdir}/norm2.raw" --target qcow2 \
   --output "${workdir}/normalized2.bi" >/dev/null 2>&1
if grep --quiet '^Source-Version-Unnormalized: 18.2.2.0-219-gdeadbeefcafe' -- "${workdir}/normalized2.bi"; then
   pass 'the record keeps the UNNORMALIZED version alongside the normalized one'
else
   fail 'the unnormalized version is lost -- a normalized image cannot be traced back to its release artifact'
fi
if grep --quiet '^Source-Version: 18.2.2.0$' -- "${workdir}/normalized2.bi"; then
   pass 'Source-Version still holds what the image actually carries'
else
   fail 'Source-Version does not hold the normalized value the image embeds'
fi

## ...and an ordinary build must be byte-unchanged, or every existing comparison
## breaks on a field that was not there before.
env dist_build_version='18.2.2.0' binary_build_folder_dist="${workdir}" \
   bash -- "${subject}" --dry-run --image "${workdir}/norm.raw" --target qcow2 \
   --output "${workdir}/plain.bi" >/dev/null 2>&1
if grep --quiet 'Version-Normalized' -- "${workdir}/plain.bi"; then
   fail 'an ordinary build gained a Version-Normalized field it should not have'
else
   pass 'an ordinary build record is unchanged'
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "test_buildinfo_source_fields_agree: ${test_failures} failure(s)" >&2
   exit 1
fi
printf '%s\n' "test_buildinfo_source_fields_agree: OK -- disagreeing source fields refused, legitimate builds spared."
