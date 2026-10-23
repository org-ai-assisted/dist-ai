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

## The guest emits TRUSTED EFI/SB/COREBOOT key=value lines (computed in-guest) plus the raw
## BIOS_VENDOR (evidence, last). VBox's own EFI -> COREBOOT=0 (bios_vendor 'innotek GmbH'); the
## dasharo coreboot+UefiPayload ROM -> COREBOOT=1 (bios_vendor 'coreboot').
efi_sb_out='EFI=1
SB=1
COREBOOT=0
BIOS_VENDOR=innotek GmbH'
efi_out='EFI=1
SB=0
COREBOOT=0
BIOS_VENDOR=innotek GmbH'
bios_out='EFI=0
SB=0
COREBOOT=0
BIOS_VENDOR=innotek GmbH'
dasharo_out='EFI=1
SB=0
COREBOOT=1
BIOS_VENDOR=coreboot'

## --- declared efi-secureboot, booted VBox EFI + SecureBoot -> vbox-efi-secureboot, match ---
run_case efi-secureboot "${efi_sb_out}"
got=0; has 'DETECTED=vbox-efi-secureboot' "$(cat -- "${work}/fw")" || got=1
check "efi-secureboot + SB-enabled + innotek vendor -> DETECTED=vbox-efi-secureboot" "${got}"
got=0; has 'MATCH=true' "$(cat -- "${work}/fw")" || got=1
check "efi-secureboot matching its lane -> MATCH=true" "${got}"
got=0; has 'BIOS_VENDOR=innotek GmbH' "$(cat -- "${work}/fw")" || got=1
check "the probe output is recorded as evidence" "${got}"

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

## --- a probe MISSING an axis (here COREBOOT) is incomplete -> unverified + MATCH=false. ---
partial_probe='EFI=1
SB=0
BIOS_VENDOR=innotek GmbH'
run_case efi "${partial_probe}"
got=0; has 'DETECTED=unverified' "$(cat -- "${work}/fw")" && has 'MATCH=false' "$(cat -- "${work}/fw")" || got=1
check "a probe missing an axis -> DETECTED=unverified MATCH=false" "${got}"

## --- a firmware-controlled BIOS_VENDOR cannot FORGE an axis: the host reads EFI/SB from their own
##     key lines (first-wins, emitted before the untrusted vendor), so an 'EFI=1'/'SB=1' injected
##     after the vendor does NOT flip a real BIOS boot to vbox-efi. ---
forge_probe='EFI=0
SB=0
COREBOOT=0
BIOS_VENDOR=innotek
EFI=1
SB=1'
run_case efi "${forge_probe}"
got=0; has 'DETECTED=bios' "$(cat -- "${work}/fw")" && has 'MATCH=false' "$(cat -- "${work}/fw")" || got=1
check "a vendor-injected EFI=1/SB=1 does not forge the axis (first-wins) -> DETECTED=bios MATCH=false" "${got}"

## --- fail CLOSED: an EMPTY probe (gc_run failed) must NOT default to a BIOS identity that
##     silently MATCHes a --firmware bios lane; it records unverified + MATCH=false. ---
run_case bios ""
got=0; has 'DETECTED=unverified' "$(cat -- "${work}/fw")" && has 'MATCH=false' "$(cat -- "${work}/fw")" || got=1
check "empty probe + declared bios -> DETECTED=unverified MATCH=false (no silent bios MATCH)" "${got}"

## --- fail CLOSED: a MISSING/erroring classifier (empty output) must not leave MATCH empty (which
##     dm-release-test forwards as null -> the results site reads GREEN); force MATCH=false. ---
stub_libdir="${work}/stub-bin"
mkdir --parents -- "${stub_libdir}"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${stub_libdir}/dm-firmware-identity"   ## prints nothing
chmod +x -- "${stub_libdir}/dm-firmware-identity"
saved_lib_dir="${lib_dir}"
# shellcheck disable=SC2034  ## read by the sourced capture_firmware_lane
lib_dir="${stub_libdir}"
run_case efi-secureboot "${efi_sb_out}"
# shellcheck disable=SC2034
lib_dir="${saved_lib_dir}"
got=0; has 'DETECTED=unverified' "$(cat -- "${work}/fw")" && has 'MATCH=false' "$(cat -- "${work}/fw")" || got=1
check "empty classifier output -> DETECTED=unverified MATCH=false (never null/green)" "${got}"

## --- fail CLOSED on a PARTIAL/out-of-order classifier: 'match=true' with NO detected= line must
##     NOT ride green -- detected becomes unverified and MATCH is forced false. ---
partial_libdir="${work}/partial-bin"
mkdir --parents -- "${partial_libdir}"
printf '%s\n' '#!/bin/bash' "printf '%s\\n' match=true" > "${partial_libdir}/dm-firmware-identity"
chmod +x -- "${partial_libdir}/dm-firmware-identity"
saved_lib_dir2="${lib_dir}"
# shellcheck disable=SC2034  ## read by the sourced capture_firmware_lane
lib_dir="${partial_libdir}"
run_case efi "${efi_out}"
# shellcheck disable=SC2034
lib_dir="${saved_lib_dir2}"
got=0; has 'DETECTED=unverified' "$(cat -- "${work}/fw")" && has 'MATCH=false' "$(cat -- "${work}/fw")" || got=1
check "classifier printed match=true but no detected= -> DETECTED=unverified MATCH=false" "${got}"

## --- milestone_blank_mode classifier (#41): must-be-rich milestones -> rich (default near-black
##     gate), legitimately-sparse -> sparse (uniform-only), pure-transient/elsewhere-gated -> skip.
##     A wrong class is a false-green (rich-as-skip hides a blank desktop) or false-fail (transient
##     -as-rich reds a valid run), so pin the split. ---
mbm() { milestone_blank_mode "$1"; }
## RICH = the settled snap() captures (desktop / Calamares GUI / first boot / checks) + the
## restored graphical desktop: a near-black frame there is a real render failure.
for rich in live-guestcontrol-ready welcome location keyboard partitions partitions-luks-filled \
   summary install-started install-done first-boot mok-reboot-desktop terminal-open \
   check-6-gui-rendered checks-complete vt-graphical-restored; do
   got=0; [ "$(mbm "${rich}")" = 'rich' ] || got=1
   check "milestone_blank_mode(${rich}) = rich (default near-black gate)" "${got}"
done
for sparse in luks-prompt luks-passphrase-typed luks-unlocked sysmaint-luks-prompt; do
   got=0; [ "$(mbm "${sparse}")" = 'sparse' ] || got=1
   check "milestone_blank_mode(${sparse}) = sparse (uniform-only, legit near-black)" "${got}"
done
## SKIP (fail-SAFE default): transient host-side frames that are legitimately uniform-black at
## capture (power-on/GRUB/kernel-boot/first-frame/install-host/sysmaint-terminal), vt-* (gated by
## require_vt_captures), the dm-text-to-png cards (gated by the card gate), and the EXIT-trap final
## frames (written AFTER the gate). power-on-first-frame / install-host-launched / sysmaint-terminal
## MUST be skip -- defaulting them to rich false-failed every --shot-dir run (always-black firmware
## grab / transitional frames).
for skip in power-on-first-frame live-kernel-boot live-grub-menu live-grub-entry-selected \
   install-host-launched installed-first-frame installed-grub-menu sysmaint-terminal firmware-state \
   final-last-frame vt-switched vt-logged-in vt-logged-out vm-defined vm-stopped-iso-detached \
   vm-stopped-final mok-cert-enrolled failure-vm-state; do
   got=0; [ "$(mbm "${skip}")" = 'skip' ] || got=1
   check "milestone_blank_mode(${skip}) = skip (transient / gated elsewhere / post-gate)" "${got}"
done

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
