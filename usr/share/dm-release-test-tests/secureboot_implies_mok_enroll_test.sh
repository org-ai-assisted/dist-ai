#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the efi-secureboot lane MUST invoke dm-calamares-install with --mok-enroll.
##
## WHY: Secure Boot is only meaningful if the installed system's out-of-tree modules (tirdad,
## Guest Additions) are DKMS-signed and their MOK enrolled; otherwise they silently fail to load
## under enforced SB and the lane would pass while testing nothing. The efi/bios lanes must NOT
## pass it. CANARY: before the coupling, efi-secureboot ran WITHOUT --mok-enroll.
##
## Drives the REAL rt_lane_kicksecure (sourced) with a SUCCEEDING iso-download stub + a recording
## dm-calamares-install stub + a sudo passthrough, and inspects the recorded install argv. Mirrors
## lane_test.sh's stub harness (download succeeds here so the installer is actually reached).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not found at ${subject}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${subject}"

failures=0
work="$(mktemp --directory --tmpdir dm-release-test-mok.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

stubbin="${work}/bin"
mkdir --parents -- "${stubbin}"
install_argv="${work}/calamares.argv"

## iso-download stub: print a (fake) ISO path and SUCCEED, so the lane reaches the installer.
iso_stub="${stubbin}/iso-download-stub"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "printf '%s\\n' '${work}/fake.iso'"
   printf '%s\n' 'exit 0'
} > "${iso_stub}"

## dm-calamares-install recorder: record argv, succeed (the install itself is not under test).
install_stub="${stubbin}/dm-calamares-install"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "printf '%s\\n' \"\$*\" >> '${install_argv}'"
   printf '%s\n' 'exit 0'
} > "${install_stub}"

## sudo passthrough: drop "-u <user>" and a leading "--", run the rest as this user.
sudo_stub="${stubbin}/sudo"
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'args=()'
   printf '%s\n' 'while [ "$#" -gt 0 ]; do'
   printf '%s\n' '  if [ "$1" = "-u" ]; then shift 2; continue; fi'
   printf '%s\n' '  if [ "$1" = "--" ]; then shift; break; fi'
   printf '%s\n' '  args+=("$1"); shift'
   printf '%s\n' 'done'
   printf '%s\n' 'exec "${args[@]}" "$@"'
} > "${sudo_stub}"
chmod 0770 -- "${iso_stub}" "${install_stub}" "${sudo_stub}"

export PATH="${stubbin}:${PATH}"
export ISO_DOWNLOAD="${iso_stub}"
export DM_CALAMARES_INSTALL="${install_stub}"
export interface='lxqt'
export desktop='LXQt'
export channel='developers'
export run_checks='false'
export RESULTS_ROOT="${work}/results"
export RESULTS_OWNER
RESULTS_OWNER="$(id --user --name)"

check() {
   if [ "$2" = 'true' ]; then printf '%s\n' "ok: $1"; else printf '%s\n' "FAIL: $1" >&2; failures=$((failures + 1)); fi
}
## Whole-TOKEN (phrase) match on the recorded argv string, NOT a substring: pad both
## haystack and needle with spaces so a check for '--firmware efi' matches only the
## complete 'efi' value, never 'efi-secureboot' / 'efi-invalid'. A substring match
## would false-pass a lane that passed the wrong firmware value.
has_arg() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac }

## Run the lane for a given firmware and return the recorded install argv.
argv_for_firmware() {
   true > "${install_argv}"
   firmware="$1"
   export firmware
   rt_lane_kicksecure "persist-inst-kicksecure" 18.2.3.5 >/dev/null 2>&1 || true
   cat -- "${install_argv}" 2>/dev/null || true
}

sb_argv="$(argv_for_firmware 'efi-secureboot')"
check "efi-secureboot reached the installer" "$(has_arg '--firmware efi-secureboot' "${sb_argv}" && printf '%s' true || printf '%s' false)"
check "efi-secureboot passes --mok-enroll" "$(has_arg '--mok-enroll' "${sb_argv}" && printf '%s' true || printf '%s' false)"

efi_argv="$(argv_for_firmware 'efi')"
## Whole-token match: a lane that regressed to '--firmware efi-secureboot' (or any other
## wrong value) must FAIL this, not satisfy it the way a substring 'efi' would.
check "plain efi reached the installer" "$(has_arg '--firmware efi' "${efi_argv}" && printf '%s' true || printf '%s' false)"
check "plain efi does NOT pass --mok-enroll" "$(has_arg '--mok-enroll' "${efi_argv}" && printf '%s' false || printf '%s' true)"

bios_argv="$(argv_for_firmware 'bios')"
## Positive reach check FIRST: without it an empty bios_argv (lane never reached the
## installer) would false-pass the --mok-enroll-absent assertion below.
check "bios reached the installer" "$(has_arg '--firmware bios' "${bios_argv}" && printf '%s' true || printf '%s' false)"
check "bios does NOT pass --mok-enroll" "$(has_arg '--mok-enroll' "${bios_argv}" && printf '%s' false || printf '%s' true)"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "" "${failures} mok-enroll coupling assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' "" "all mok-enroll coupling assertions passed"
