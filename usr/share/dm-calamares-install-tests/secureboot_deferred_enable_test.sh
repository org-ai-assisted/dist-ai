#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-calamares-install's Secure Boot sequencing on the efi-secureboot lane.
##
## THE BUG IT GUARDS: apply_firmware enabled Secure Boot at VM build, i.e. for the LIVE/install
## boot. The live ISO's VirtualBox Guest Additions modules are unsigned, so under enforced
## Secure Boot they are rejected and VBoxService/guestcontrol never comes up -- the install
## cannot be driven (rc=5, zero screenshots). The live/install phase must run with Secure Boot
## OFF; enforcement is turned ON only before the installed-system first boot
## (enable_secureboot_installed), where the GA is DKMS-signed and the MOK enrolled.
##
## Drives the REAL apply_firmware + enable_secureboot_installed (sourced define-only) with a
## recording VBOXMANAGE stub. No VM, no root, no network.

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
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## Recording VBOXMANAGE stub: append every invocation's args to a log, always succeed.
vboxmanage_stub="${work}/vboxmanage-stub"
nvram_log="${work}/vbox-calls"
cat > "${vboxmanage_stub}" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${VBOX_CALLS}"
exit 0
STUB
chmod +x "${vboxmanage_stub}"
export VBOX_CALLS="${nvram_log}"

# shellcheck disable=SC1090
source "${subject}"

# shellcheck disable=SC2034
vm="testvm"
# shellcheck disable=SC2034
VBOXMANAGE="${vboxmanage_stub}"

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## --- efi-secureboot: apply_firmware enrolls keys but leaves Secure Boot OFF (live phase) ----
# shellcheck disable=SC2034
firmware="efi-secureboot"
true > "${nvram_log}"
apply_firmware
calls="$(cat -- "${nvram_log}")"
got=0; has 'modifyvm testvm --firmware efi' "${calls}" || got=1
check "apply_firmware sets EFI firmware for efi-secureboot" "${got}"
got=0; has 'inituefivarstore' "${calls}" && has 'enrollorclpk' "${calls}" && has 'enrollmssignatures' "${calls}" || got=1
check "apply_firmware enrolls the varstore + PK + MS keys" "${got}"
got=0; has 'secureboot --disable' "${calls}" || got=1
check "apply_firmware leaves Secure Boot DISABLED for the live/install phase" "${got}"
## CANARY: pre-fix apply_firmware enabled Secure Boot here (breaking the live GA / guestcontrol).
got=0; if has 'secureboot --enable' "${calls}"; then got=1; fi
check "apply_firmware does NOT enable Secure Boot during the live phase" "${got}"

## --- efi-secureboot: enable_secureboot_installed turns it ON for the installed boot ---------
true > "${nvram_log}"
enable_secureboot_installed
calls="$(cat -- "${nvram_log}")"
got=0; has 'secureboot --enable' "${calls}" || got=1
check "enable_secureboot_installed turns Secure Boot ON for the installed boot" "${got}"
## It must NOT re-init the varstore (would wipe the install's boot entries).
got=0; if has 'inituefivarstore' "${calls}"; then got=1; fi
check "enable_secureboot_installed does not re-init the varstore" "${got}"

## --- plain efi + bios: enable_secureboot_installed is a no-op --------------------------------
for fw in efi bios; do
   # shellcheck disable=SC2034
   firmware="${fw}"
   true > "${nvram_log}"
   enable_secureboot_installed
   got=0; [ ! -s "${nvram_log}" ] || got=1
   check "enable_secureboot_installed is a no-op on the ${fw} lane" "${got}"
done

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
