#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-calamares-install's capture_firmware_lane: it probes the installed
## guest for the firmware lane it ACTUALLY booted, cross-checks against the declared --firmware,
## and writes DETECTED=/MATCH=/evidence to --firmware-evidence-file for the results plane. Pins
## the detection via the shared dm-firmware-identity classifier (bios / vbox-efi / dasharo-efi,
## each with a -secureboot variant, keyed on the efi dir + mokutil + /sys/class/dmi/id/bios_vendor)
## and the declared-vs-detected match, so a wrong-lane boot -- including a coreboot ROM booted on a
## lane that declared VBox EFI -- surfaces as a loud mismatch, not a silent pass.
##
## Drives the REAL capture_firmware_lane (sourced define-only) and the REAL dm-firmware-identity
## sibling, with gc_run stubbed to return a canned probe output per case. No VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

# shellcheck disable=SC1090
source "${subject}"

## Stub gc_run to return the canned probe output for the case under test.
TEST_FW_OUT=""
# shellcheck disable=SC2317
gc_run() { printf '%s\n' "${TEST_FW_OUT}"; }

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## case: run capture_firmware_lane with declared=$1, probe output=$2; return the evidence file.
run_case() {
   # shellcheck disable=SC2034  ## read by the sourced capture_firmware_lane
   firmware="$1"
   TEST_FW_OUT="$2"
   # shellcheck disable=SC2034
   firmware_evidence_file="${work}/fw"
   true > "${firmware_evidence_file}"
   capture_firmware_lane
}

## VBox's own EFI reports bios_vendor 'innotek GmbH'; the dasharo coreboot+UefiPayload ROM reports
## 'coreboot'. The probe snippet also prints the efi dir + mokutil sb-state lines.
efi_sb_out='[ -d /sys/firmware/efi ] -> UEFI
mokutil --sb-state -> SecureBoot enabled
bios_vendor -> innotek GmbH'
efi_out='[ -d /sys/firmware/efi ] -> UEFI
mokutil --sb-state -> SecureBoot disabled
bios_vendor -> innotek GmbH'
bios_out='[ -d /sys/firmware/efi ] -> BIOS
mokutil --sb-state -> EFI variables are not supported on this system
bios_vendor -> innotek GmbH'
dasharo_out='[ -d /sys/firmware/efi ] -> UEFI
mokutil --sb-state -> SecureBoot disabled
bios_vendor -> coreboot'

## --- declared efi-secureboot, booted VBox EFI + SecureBoot -> vbox-efi-secureboot, match ---
run_case efi-secureboot "${efi_sb_out}"
got=0; has 'DETECTED=vbox-efi-secureboot' "$(cat -- "${work}/fw")" || got=1
check "efi-secureboot + SB-enabled + innotek vendor -> DETECTED=vbox-efi-secureboot" "${got}"
got=0; has 'MATCH=true' "$(cat -- "${work}/fw")" || got=1
check "efi-secureboot matching its lane -> MATCH=true" "${got}"
got=0; has 'mokutil --sb-state -> SecureBoot enabled' "$(cat -- "${work}/fw")" || got=1
check "the probe command+output is recorded as evidence" "${got}"

## --- declared efi-secureboot, booted BIOS -> MISMATCH ---
run_case efi-secureboot "${bios_out}"
got=0; has 'DETECTED=bios' "$(cat -- "${work}/fw")" || got=1
check "no efi dir -> DETECTED=bios" "${got}"
got=0; has 'MATCH=false' "$(cat -- "${work}/fw")" || got=1
check "declared efi-secureboot but booted BIOS -> MATCH=false (loud mismatch)" "${got}"

## --- declared efi, booted VBox EFI (SB off) -> vbox-efi, match ---
run_case efi "${efi_out}"
got=0; has 'DETECTED=vbox-efi' "$(cat -- "${work}/fw")" && ! has 'vbox-efi-secureboot' "$(cat -- "${work}/fw")" || got=1
check "efi + SB-disabled + innotek vendor -> DETECTED=vbox-efi (not -secureboot)" "${got}"
got=0; has 'MATCH=true' "$(cat -- "${work}/fw")" || got=1
check "declared efi matching vbox-efi -> MATCH=true" "${got}"

## --- declared bios, booted BIOS -> match ---
run_case bios "${bios_out}"
got=0; has 'DETECTED=bios' "$(cat -- "${work}/fw")" && has 'MATCH=true' "$(cat -- "${work}/fw")" || got=1
check "declared bios matching BIOS -> MATCH=true" "${got}"

## --- declared efi (VBox EFI) but the guest booted a COREBOOT ROM -> detected dasharo-efi,
##     loud MISMATCH. The coreboot bios_vendor is what distinguishes dasharo-efi from vbox-efi. ---
run_case efi "${dasharo_out}"
got=0; has 'DETECTED=dasharo-efi' "$(cat -- "${work}/fw")" || got=1
check "coreboot bios_vendor -> DETECTED=dasharo-efi (distinct from vbox-efi)" "${got}"
got=0; has 'MATCH=false' "$(cat -- "${work}/fw")" || got=1
check "declared vbox-efi but booted coreboot -> MATCH=false (loud mismatch)" "${got}"

## --- no evidence file set: capture is a no-op (does not error) ---
# shellcheck disable=SC2034  ## read by the sourced capture_firmware_lane
firmware=efi
# shellcheck disable=SC2034
firmware_evidence_file=""
rc=0; capture_firmware_lane || rc=$?
check "no --firmware-evidence-file -> capture no-ops cleanly" "${rc}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
