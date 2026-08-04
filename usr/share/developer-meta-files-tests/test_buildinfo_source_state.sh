#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-reproducible-buildinfo': the
## source-state block it interpolates into the Deb822 record.
##
## THE BUG IT GUARDS: the block was accepted on '[ -r ]' alone. A blank line is
## the Deb822 record TERMINATOR, so an EMPTY state file did not merely lose
## provenance -- it interpolated a blank line into the middle of the record and
## detached Source-Version, Flavor, Target, Architecture and everything after it
## into a second, invalid paragraph. A partial file (no Submodule-State) silently
## published incomplete provenance as if it were complete.
##
## Second defect: the path fell back to "${binary_build_folder_dist:-}/dm-source-state",
## which is the ABSOLUTE path '/dm-source-state' when that variable is unset, so
## the script read whatever happened to sit in the root directory.
##
## The structural assertion is the point: the emitted record must contain exactly
## one blank line, at the very end. That is what the bug violated.
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
## the caller asked about, and a stale checkout there then reads as a defect in
## the code under test rather than as a stale checkout.
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

## The script WRITES '<image>.dm-buildinfo' rather than printing the record, so
## the harness makes a stand-in image, runs it, and returns the file's contents.
##
## $binary_build_folder_dist is passed explicitly so the 'unset' case below is a
## real choice rather than whatever the surrounding environment happened to hold.
##
## A run that fails, or that produces no record, is FATAL rather than an empty
## string: every assertion here is a substring match, and an empty record
## satisfies the negative ones -- which is how a broken harness reads as a pass.
emit_seq=0
emit() {
   local state_file="$1" image record rc

   emit_seq=$(( emit_seq + 1 ))
   image="${workdir}/image-${emit_seq}.raw"
   touch -- "${image}"

   ## Unset source_code_folder_dist so these state-file assertions are decided by
   ## the file alone: with a source tree present the script now reads HEAD when a
   ## file is missing (its own test below), which would otherwise flip the
   ## missing/empty cases here if the ambient environment happened to export it.
   rc=0
   env --unset=source_code_folder_dist \
      dm_source_state_file="${state_file}" \
      binary_build_folder_dist="${workdir}/binary" \
      bash -- "${subject}" --target raw --image "${image}" >/dev/null 2>&1 || rc="$?"
   if [ "${rc}" -ne 0 ]; then
      printf '%s\n' "FAILED: dm-reproducible-buildinfo exited ${rc} for '${state_file}'; the harness is broken, not the subject." >&2
      exit 1
   fi
   record="$(cat -- "${image}.dm-buildinfo")"
   if [ -z "${record}" ]; then
      printf '%s\n' "FAILED: empty record for '${state_file}'; an empty record satisfies every negative assertion below." >&2
      exit 1
   fi
   printf '%s\n' "${record}"
}

## Exactly one blank line, at the end: a Deb822 record with a blank line in the
## middle is two paragraphs, and everything after the blank is detached.
assert_single_trailing_blank() {
   local description="$1" record="$2" interior_blanks

   ## Strip the trailing terminator, then count what blank lines remain.
   interior_blanks="$(printf '%s' "${record}" | grep --count '^$' || true)"
   if [ "${interior_blanks}" -eq 0 ]; then
      pass "${description}: record has no interior blank line"
   else
      fail "${description}: record has ${interior_blanks} interior blank line(s); every field after the first is detached"
   fi
}

## --- a well-formed state file ----------------------------------------------
good_state="${workdir}/good"
printf '%s\n' \
   'Source-Commit: 3d18509fa9a511d6e8c1f26e92c1ec51694c316b' \
   'Submodule-State:' \
   ' 0a52b166247c2f193f8347a5ef07321c5c06d4e4 packages/kicksecure/developer-meta-files (heads/ai)' \
   > "${good_state}"

good_out="$(emit "${good_state}")"
case "${good_out}" in
   *'Source-Commit: 3d18509fa9a511d6e8c1f26e92c1ec51694c316b'*)
      pass "well-formed state file: the recorded commit reaches the record"
      ;;
   *)
      fail "well-formed state file: the commit did not reach the record -- ${good_out}"
      ;;
esac
case "${good_out}" in
   *unrecorded*)
      fail "well-formed state file: reported as unrecorded; the validation rejects a valid file"
      ;;
   *)
      pass "canary: a valid file is NOT reported unrecorded, so the checks below are not blanket rejections"
      ;;
esac
assert_single_trailing_blank "well-formed state file" "${good_out}"

## --- the bug: an EMPTY state file ------------------------------------------
empty_state="${workdir}/empty"
touch -- "${empty_state}"
empty_out="$(emit "${empty_state}")"
assert_single_trailing_blank "empty state file" "${empty_out}"
case "${empty_out}" in
   *'Source-Commit: unrecorded'*)
      pass "empty state file: reported as unrecorded"
      ;;
   *)
      fail "empty state file: not reported unrecorded -- ${empty_out}"
      ;;
esac

## --- a state file containing a blank line ----------------------------------
blank_state="${workdir}/blank"
printf '%s\n' 'Source-Commit: abc' '' 'Submodule-State:' > "${blank_state}"
blank_out="$(emit "${blank_state}")"
assert_single_trailing_blank "state file with a blank line" "${blank_out}"
case "${blank_out}" in
   *unrecorded*)
      pass "state file with a blank line: reported as unrecorded"
      ;;
   *)
      fail "state file with a blank line: accepted, and it terminated the record -- ${blank_out}"
      ;;
esac

## --- a PARTIAL state file: provenance that looks complete but is not --------
partial_state="${workdir}/partial"
printf '%s\n' 'Source-Commit: abc123' > "${partial_state}"
partial_out="$(emit "${partial_state}")"
case "${partial_out}" in
   *unrecorded*)
      pass "state file with no Submodule-State: reported as unrecorded"
      ;;
   *)
      fail "state file with no Submodule-State: published as complete provenance -- ${partial_out}"
      ;;
esac

## --- missing file ----------------------------------------------------------
missing_out="$(emit "${workdir}/does-not-exist")"
case "${missing_out}" in
   *'Source-Commit: unrecorded'*)
      pass "missing state file: reported as unrecorded"
      ;;
   *)
      fail "missing state file: not reported unrecorded -- ${missing_out}"
      ;;
esac
assert_single_trailing_blank "missing state file" "${missing_out}"

## --- neither variable set: must NOT fall back to /dm-source-state ----------
unset_image="${workdir}/image-unset.raw"
touch -- "${unset_image}"
env --unset=dm_source_state_file --unset=binary_build_folder_dist --unset=source_code_folder_dist \
   bash -- "${subject}" --target raw --image "${unset_image}" >/dev/null 2>&1
unset_out="$(cat -- "${unset_image}.dm-buildinfo")"
if [ -z "${unset_out}" ]; then
   printf '%s\n' "FAILED: empty record with both variables unset." >&2
   exit 1
fi
case "${unset_out}" in
   */dm-source-state*)
      fail "with both variables unset the script still names '/dm-source-state', i.e. it reads the root directory"
      ;;
   *)
      pass "with both variables unset the script does not fall back to the root directory"
      ;;
esac
case "${unset_out}" in
   *unrecorded*)
      pass "with both variables unset: reported as unrecorded"
      ;;
   *)
      fail "with both variables unset: not reported unrecorded -- ${unset_out}"
      ;;
esac

## --- no state file, but a real source tree: read HEAD directly --------------
## sign-and-tag writes dm-source-state ONLY when it amends
## (dist_build_sign_and_tag=true). With signing off there is no file, yet HEAD is
## the REAL, fetchable commit -- so the record must carry it, not 'unrecorded'.
## FAILS on the pre-fix code, which ignored source_code_folder_dist here. git is
## a hard dependency of the whole toolchain (assumed present, not skip-guarded).
head_repo="${workdir}/src"
mkdir -- "${head_repo}"
git -c core.hooksPath=/dev/null -C "${head_repo}" init --quiet
git -c core.hooksPath=/dev/null -C "${head_repo}" \
   -c user.name=t -c user.email=t@example.com \
   commit --quiet --allow-empty --message 'seed'
head_sha="$(git -C "${head_repo}" rev-parse HEAD)"

head_image="${workdir}/image-head.raw"
touch -- "${head_image}"
env source_code_folder_dist="${head_repo}" \
   dm_source_state_file="${workdir}/no-such-state" \
   binary_build_folder_dist="${workdir}/binary" \
   bash -- "${subject}" --target raw --image "${head_image}" >/dev/null 2>&1
head_out="$(cat -- "${head_image}.dm-buildinfo")"
case "${head_out}" in
   *"Source-Commit: ${head_sha}"*)
      pass "no state file + source tree: HEAD recorded as the source commit"
      ;;
   *)
      fail "no state file + source tree: HEAD not recorded -- ${head_out}"
      ;;
esac
case "${head_out}" in
   *unrecorded*)
      fail "no state file + source tree: reported unrecorded despite a readable HEAD"
      ;;
   *)
      pass "no state file + source tree: not reported unrecorded"
      ;;
esac
assert_single_trailing_blank "no state file + source tree" "${head_out}"

## Canary: the SAME missing-file case WITHOUT a source tree must still be
## 'unrecorded', proving the HEAD path is gated on source_code_folder_dist and
## is not a blanket change that would mask a genuinely unrecorded build.
nohead_image="${workdir}/image-nohead.raw"
touch -- "${nohead_image}"
env --unset=source_code_folder_dist \
   dm_source_state_file="${workdir}/no-such-state" \
   binary_build_folder_dist="${workdir}/binary" \
   bash -- "${subject}" --target raw --image "${nohead_image}" >/dev/null 2>&1
nohead_out="$(cat -- "${nohead_image}.dm-buildinfo")"
case "${nohead_out}" in
   *'Source-Commit: unrecorded'*)
      pass "canary: no state file AND no source tree still reports unrecorded"
      ;;
   *)
      fail "canary: no state file AND no source tree should be unrecorded -- ${nohead_out}"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: buildinfo source state."
