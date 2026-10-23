#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: the firmware-identity classifier maps the three independent axes to the right canonical
## identity, decides declared-vs-detected match correctly (a MISMATCH is the fail-loud signal a
## lane emits as environment.firmware.match=false -> red run), and rejects malformed axes with a
## usage error instead of classifying a default. Sources the REAL tool's pure classify function
## AND drives its real CLI -- no synthetic copy.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

## Test seam: point at a deliberately-broken copy to confirm a case FAILS on it.
TOOL="${DM_FIRMWARE_IDENTITY_BIN:-}"
if [ -z "${TOOL}" ]; then
   if [ -x "${test_dir}/../../bin/dm-firmware-identity" ]; then
      TOOL="${test_dir}/../../bin/dm-firmware-identity"
   else
      TOOL='/usr/bin/dm-firmware-identity'
   fi
fi
[ -x "${TOOL}" ] || { printf '%s\n' "FATAL: dm-firmware-identity not found/executable at ${TOOL}" >&2; exit 1; }

failures=0
check() {
   if [ "$2" -eq 0 ]; then
      printf '%s\n' "PASS: ${1}"
   else
      printf '%s\n' "FAIL: ${1}"
      failures=$(( failures + 1 ))
   fi
}

## Source the real tool to exercise the PURE classify function directly (the $0-guard keeps main
## from running on source). A reimplementation here would drift from the shipped mapping.
# shellcheck source=../../bin/dm-firmware-identity
source "${TOOL}"

## --- the pure mapping: every (efi, coreboot, secureboot) combination -> canonical identity. ---
## bios whenever efi=0 (coreboot/sb are don't-cares there: our coreboot target is UEFI-payload).
expect_classify() {
   local efi="$1" cb="$2" sb="$3" want="$4" got
   got="$(firmware_identity_classify "${efi}" "${cb}" "${sb}")"
   if [ "${got}" = "${want}" ]; then r=0; else r=1; fi
   check "classify efi=${efi} coreboot=${cb} secureboot=${sb} -> ${want} (got '${got}')" "${r}"
}
expect_classify 0 0 0 bios
expect_classify 0 1 0 bios
expect_classify 0 0 1 bios
expect_classify 0 1 1 bios
expect_classify 1 0 0 vbox-efi
expect_classify 1 0 1 vbox-efi-secureboot
expect_classify 1 1 0 dasharo-efi
expect_classify 1 1 1 dasharo-efi-secureboot

## --- the CLI: detected + match (the fail-loud declared-vs-detected decision). ---
cli() { "${TOOL}" "$@"; }

out="$(cli --efi 1 --coreboot 1 --secureboot 0 --declared dasharo-efi)"
case "${out}" in *'detected=dasharo-efi'*) case "${out}" in *'match=true'*) r=0 ;; *) r=1 ;; esac ;; *) r=1 ;; esac
check 'CLI: declared matches detected -> match=true' "${r}"

## The fail-loud case: a lane declaring dasharo-efi but the guest booting plain vbox-efi MUST
## report match=false (the results site turns that run red even on rc=0).
out="$(cli --efi 1 --coreboot 0 --secureboot 0 --declared dasharo-efi)"
case "${out}" in *'detected=vbox-efi'*) case "${out}" in *'match=false'*) r=0 ;; *) r=1 ;; esac ;; *) r=1 ;; esac
check 'CLI: declared dasharo-efi but detected vbox-efi -> match=false (fail-loud)' "${r}"

## secureboot sub-state participates in the match: declared efi but booted efi-secureboot mismatches.
out="$(cli --efi 1 --coreboot 0 --secureboot 1 --declared vbox-efi)"
case "${out}" in *'match=false'*) r=0 ;; *) r=1 ;; esac
check 'CLI: secureboot sub-state is part of the identity (vbox-efi vs vbox-efi-secureboot)' "${r}"

out="$(cli --efi 0 --declared bios)"
case "${out}" in *'match=true'*) r=0 ;; *) r=1 ;; esac
check 'CLI: bios declared+detected -> match=true' "${r}"

## No --declared -> match=unknown (detected still reported), never a spurious true/false.
out="$(cli --efi 1 --coreboot 1 --secureboot 0)"
case "${out}" in *'match=unknown'*) r=0 ;; *) r=1 ;; esac
check 'CLI: omitted --declared -> match=unknown' "${r}"

## --- strict axes: a malformed value is a usage error (64), never classified as a default. ---
rc=0; cli --efi 2 >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
check 'CLI: a non-0/1 --efi is rejected (64), not classified as a default' "${r}"

rc=0; cli --coreboot yes --efi 1 >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
check 'CLI: a non-0/1 --coreboot is rejected (64)' "${r}"

rc=0; cli --coreboot 1 >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
check 'CLI: a missing required --efi is rejected (64)' "${r}"

rc=0; cli --efi 1 --bogus >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 64 ]; then r=0; else r=1; fi
check 'CLI: an unknown flag is rejected (64)' "${r}"

printf '%s\n' "" "$(basename -- "$0"): ${failures} fail"
[ "${failures}" -eq 0 ] || exit 1
exit 0
