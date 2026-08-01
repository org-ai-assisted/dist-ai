#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-reproducible-compare-artifacts'
## on the path a GREEN lane never takes.
##
## WHY THIS EXISTS: the verdict is a whole-file sha256, and everything after it --
## the DIFFER report, the tar descent, diffoscope_bounded, the nbd/mount route,
## the trap chain, the direct-comparison fallback -- runs ONLY when the two
## artifacts differ. The reproducibility lane is green, so that code has never
## executed in CI. It is roughly two thirds of the file, and it is exactly the
## code a developer depends on the first time a build stops being reproducible:
## the diagnosis arrives when nothing has been exercising it.
##
## The nbd route is the concrete case: a missing 'modprobe' disables it silently,
## and only an actual mismatch would reveal that -- which is the one moment the
## route needs to work.
##
## Uses artifacts small enough that the whole run is seconds:
##   - iso target: two tiny files, exercising the direct route in isolation
##   - qcow2 target: two one-member tar.xz archives, exercising the unpack and
##     member-selection path
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

subject=""
locate_subject() {
   local candidate

   for candidate in "${DM_COMPARE_ARTIFACTS:-}" \
      "${DEVELOPER_META_FILES_DIR:-}/usr/bin/dm-reproducible-compare-artifacts" \
      "${HOME}/derivative-maker/packages/kicksecure/developer-meta-files/usr/bin/dm-reproducible-compare-artifacts" \
      "/usr/bin/dm-reproducible-compare-artifacts"; do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}" ]; then
         subject="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: dm-reproducible-compare-artifacts not found." >&2
   exit 77
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

## --- identical pair: the verdict path, as a control -------------------------
## Without this the DIFFER assertions below could pass on a comparator that
## reports DIFFER unconditionally.
mkdir --parents -- "${workdir}/same_a" "${workdir}/same_b"
printf '%s\n' 'identical-payload' > "${workdir}/same_a/Kicksecure-CLI-1.iso"
printf '%s\n' 'identical-payload' > "${workdir}/same_b/Kicksecure-CLI-1.iso"

rc=0
out="$("${subject}" --target iso --dir-a "${workdir}/same_a" --dir-b "${workdir}/same_b" \
   --output "${workdir}/same.report" 2>&1)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "identical pair: exit 0"
else
   fail "identical pair: exit ${rc} -- ${out}"
fi
case "${out}" in
   *"identical"*)
      pass "identical pair: reports identical"
      ;;
   *)
      fail "identical pair: did not report identical -- ${out}"
      ;;
esac

## --- differing pair, iso: exit 1 and a report naming both sides -------------
mkdir --parents -- "${workdir}/iso_a" "${workdir}/iso_b"
printf '%s\n' 'payload-a' > "${workdir}/iso_a/Kicksecure-CLI-1.iso"
printf '%s\n' 'payload-b' > "${workdir}/iso_b/Kicksecure-CLI-1.iso"

rc=0
out="$("${subject}" --target iso --dir-a "${workdir}/iso_a" --dir-b "${workdir}/iso_b" \
   --output "${workdir}/iso.report" 2>&1)" || rc="$?"

if [ "${rc}" -eq 1 ]; then
   pass "differing iso pair: exit 1 (the documented 'differ' code)"
else
   fail "differing iso pair: exit ${rc}, expected 1 -- ${out}"
fi

if [ -s "${workdir}/iso.report" ]; then
   pass "differing iso pair: wrote a non-empty report"
else
   fail "differing iso pair: report is empty; a mismatch must leave evidence"
fi

## The report must carry BOTH sha256 values. A report that says only "differ" is
## not actionable, and the two hashes are what a developer compares first.
report_hashes="$(grep --count --extended-regexp '[0-9a-f]{64}' "${workdir}/iso.report" || true)"
if [ "${report_hashes}" -ge 2 ]; then
   pass "differing iso pair: report records both sha256 values"
else
   fail "differing iso pair: report has ${report_hashes} sha256 value(s), expected >= 2"
fi

case "$(cat -- "${workdir}/iso.report")" in
   *DIFFER*)
      pass "differing iso pair: report states DIFFER"
      ;;
   *)
      fail "differing iso pair: report does not state DIFFER"
      ;;
esac

## --- differing pair, qcow2: the tar descent ---------------------------------
## The qcow2 artifact is a 'tar --xz' holding the image, so this reaches the
## unpack and member-selection code the iso target skips entirely.
mkdir --parents -- "${workdir}/q_a" "${workdir}/q_b" "${workdir}/build_a" "${workdir}/build_b"
printf '%s\n' 'qcow2-payload-a' > "${workdir}/build_a/Kicksecure-CLI-1.Intel_AMD64.qcow2"
printf '%s\n' 'qcow2-payload-b' > "${workdir}/build_b/Kicksecure-CLI-1.Intel_AMD64.qcow2"
tar --create --xz --directory="${workdir}/build_a" \
   --file "${workdir}/q_a/Kicksecure-CLI-1.Intel_AMD64.qcow2.libvirt.xz" \
   'Kicksecure-CLI-1.Intel_AMD64.qcow2'
tar --create --xz --directory="${workdir}/build_b" \
   --file "${workdir}/q_b/Kicksecure-CLI-1.Intel_AMD64.qcow2.libvirt.xz" \
   'Kicksecure-CLI-1.Intel_AMD64.qcow2'

rc=0
out="$("${subject}" --target qcow2 --dir-a "${workdir}/q_a" --dir-b "${workdir}/q_b" \
   --output "${workdir}/q.report" 2>&1)" || rc="$?"

if [ "${rc}" -eq 1 ]; then
   pass "differing qcow2 pair: exit 1"
else
   fail "differing qcow2 pair: exit ${rc}, expected 1 -- ${out}"
fi

if [ -s "${workdir}/q.report" ]; then
   pass "differing qcow2 pair: wrote a non-empty report"
else
   fail "differing qcow2 pair: report is empty"
fi

## --- setup errors: exit 2, distinct from 'differ' ---------------------------
## Conflating these with exit 1 is how "expected exactly one *.qcow2, found 0"
## once read as a reproducibility failure when it was a not-found.
assert_setup_error() {
   local description="$1"
   shift
   local setup_rc=0

   "${subject}" "$@" >/dev/null 2>&1 || setup_rc="$?"
   if [ "${setup_rc}" -eq 2 ]; then
      pass "${description}: exit 2"
   else
      fail "${description}: exit ${setup_rc}, expected 2 -- a setup error must not read as 'artifacts differ'"
   fi
}

mkdir --parents -- "${workdir}/empty" "${workdir}/two"
printf '%s\n' 'x' > "${workdir}/two/Kicksecure-CLI-1.iso"
printf '%s\n' 'y' > "${workdir}/two/Kicksecure-CLI-2.iso"

assert_setup_error "no artifact under dir-a" \
   --target iso --dir-a "${workdir}/empty" --dir-b "${workdir}/iso_b" --output "${workdir}/e1.report"
assert_setup_error "two artifacts under dir-a" \
   --target iso --dir-a "${workdir}/two" --dir-b "${workdir}/iso_b" --output "${workdir}/e2.report"
assert_setup_error "unknown target" \
   --target nonsense --dir-a "${workdir}/iso_a" --dir-b "${workdir}/iso_b" --output "${workdir}/e3.report"
assert_setup_error "nonexistent dir-a" \
   --target iso --dir-a "${workdir}/does-not-exist" --dir-b "${workdir}/iso_b" --output "${workdir}/e4.report"

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: compare-artifacts differ + setup errors."
