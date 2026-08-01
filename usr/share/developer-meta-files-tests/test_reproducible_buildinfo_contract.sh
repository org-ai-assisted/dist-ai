#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Contract test for developer-meta-files 'dm-reproducible-buildinfo': the
## default output NAME, the shape of the emitted record, and the REFUSALS.
##
## WHY THESE THREE CANNOT COME FROM A BUILD: dm-prepare-release exercises the
## happy path on every real run and on the CI dry-run, so that half needs no
## stand-in. What a successful release never reaches is bad input -- a green lane
## is precisely the run that does not take a refusal branch. And the default
## output name is load-bearing but unstated: dm-prepare-release calls the tool
## WITHOUT '--output' and then signs '<image>.dm-buildinfo', so a change to the
## derivation breaks signing with no other symptom.
##
## THE BUG IT GUARDS: a release that silently emitted a buildinfo for a missing
## image, or for no target, publishes a SIGNED record of nothing.
##
## Needs no root, no network, no build -- so it belongs in the test suite, not in
## a CI lane that pays for a container start.

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
for candidate in "${DM_BUILDINFO:-}" \
   "${DEVELOPER_META_FILES_DIR:-}/usr/bin/dm-reproducible-buildinfo" \
   "${HOME}/derivative-maker/packages/kicksecure/developer-meta-files/usr/bin/dm-reproducible-buildinfo" \
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

dummy_image="${workdir}/dummy.raw"
true > "${dummy_image}"
buildinfo_file="${dummy_image}.dm-buildinfo"

## Two build variables exported so the record has real values to propagate; the
## tool tolerates the rest being unset, which the 'unknown' assertion below then
## pins.
export dist_build_flavor="kicksecure-cli"
export SOURCE_DATE_EPOCH="1600000000"

## --- default output name ----------------------------------------------------
## No '--output': the form dm-prepare-release uses.
emit_rc=0
bash -- "${subject}" --target raw --image "${dummy_image}" >/dev/null 2>&1 || emit_rc="$?"
if [ "${emit_rc}" -eq 0 ]; then
   pass "emits with no --output (exit 0)"
else
   fail "emitting with no --output exited ${emit_rc}"
fi
if [ -f "${buildinfo_file}" ]; then
   pass "derives '<image>.dm-buildinfo', the exact name dm-prepare-release signs"
else
   fail "without --output the tool did not create '${buildinfo_file}'; dm-prepare-release signs that exact name"
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi

## --- record shape -----------------------------------------------------------
for expected_field in \
   "Format: 1.0" \
   "Buildinfo-Type: derivative-image" \
   "Target: raw" \
   "Image-File: dummy.raw" \
   "Flavor: kicksecure-cli" \
   "Source-Date-Epoch: 1600000000" ; do
   if grep --quiet --fixed-strings -- "${expected_field}" "${buildinfo_file}"; then
      pass "record carries '${expected_field}'"
   else
      fail "record is missing '${expected_field}'"
   fi
done

## An unset variable must render as 'unknown' rather than an empty value: an
## empty Deb822 value is not a well-formed record for a parser.
if grep --quiet --fixed-strings -- "Build-Type: unknown" "${buildinfo_file}"; then
   pass "an unset build variable renders as 'unknown'"
else
   fail "an unset build variable did not render as 'unknown'"
fi

## CANARY: the field greps must be able to MISS, or every assertion above is
## satisfied by a grep that matches anything.
if grep --quiet --fixed-strings -- "Target: definitely-not-a-target" "${buildinfo_file}"; then
   fail "canary broken: the field grep reports a field that is not in the record"
else
   pass "canary: the field grep can report a field as absent"
fi

## --- the refusals -----------------------------------------------------------
## Each must exit 2. Only bad input reaches these, so no successful build does.
assert_refuses() {
   local description="$1"
   shift
   local refuse_rc=0

   bash -- "${subject}" "$@" >/dev/null 2>&1 || refuse_rc="$?"
   if [ "${refuse_rc}" -eq 2 ]; then
      pass "refuses: ${description} (exit 2)"
   else
      fail "refuses: ${description}: expected exit 2, got ${refuse_rc}"
   fi
}

assert_refuses "missing --target" --image "${dummy_image}"
assert_refuses "missing --image" --target raw
assert_refuses "nonexistent image" --target raw --image "${workdir}/does-not-exist.raw"
assert_refuses "unknown argument" --target raw --image "${dummy_image}" --nonsense

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: reproducible buildinfo contract."
