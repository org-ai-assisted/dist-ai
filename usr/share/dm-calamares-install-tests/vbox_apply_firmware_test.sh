#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for the shared vbox_apply_firmware primitive (vbox-session.bsh), extracted from
## dm-calamares-install's apply_firmware so dm-release-test can apply the SAME firmware sequence
## to the imported whonix pair. Drives the REAL function (sourced from the shared fragment) with
## a recording VBOXMANAGE stub. No VM, no root, no network. Asserts:
##   - bios        -> modifyvm --firmware bios only (no NVRAM ops);
##   - efi-secureboot defer    -> enroll keys + secureboot --disable (live/install phase);
##   - efi-secureboot enable-now -> enroll keys + secureboot --enable (installed pair);
##   - plain efi   -> modifyvm --firmware efi + tolerant secureboot --disable, no enroll;
##   - VBOX_FW_RUNNER override prefixes EVERY VBoxManage call (the per-account sudo route);
##   - dm-calamares-install apply_firmware delegates to vbox_apply_firmware ... defer (canary).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

vbox_session_lib=""
for candidate in \
   "${test_dir}/../dm-smbios-reader-boot-tests/vbox-session.bsh" \
   "/usr/share/dm-smbios-reader-boot-tests/vbox-session.bsh"; do
   if [ -f "${candidate}" ]; then
      vbox_session_lib="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${vbox_session_lib}" ]; then
   printf '%s\n' "FATAL: vbox-session.bsh not found." >&2
   exit 1
fi

calamares_install=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      calamares_install="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${calamares_install}" ]; then
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
vbox_calls="${work}/vbox-calls"
cat > "${vboxmanage_stub}" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${VBOX_CALLS}"
exit 0
STUB
chmod +x "${vboxmanage_stub}"
export VBOX_CALLS="${vbox_calls}"

# shellcheck disable=SC1090
source "${vbox_session_lib}"

# shellcheck disable=SC2034  ## read by vbox_apply_firmware's default runner
VBOXMANAGE="${vboxmanage_stub}"

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## --- bios: firmware only, no NVRAM ops ------------------------------------------------------
true > "${vbox_calls}"
vbox_apply_firmware testvm bios enable-now
calls="$(cat -- "${vbox_calls}")"
got=0; has 'modifyvm testvm --firmware bios' "${calls}" || got=1
check "bios sets BIOS firmware" "${got}"
got=0; if has 'modifynvram' "${calls}"; then got=1; fi
check "bios touches no NVRAM / Secure Boot state" "${got}"

## --- efi-secureboot defer: enroll keys, leave Secure Boot OFF (live/install) -----------------
true > "${vbox_calls}"
vbox_apply_firmware testvm efi-secureboot defer
calls="$(cat -- "${vbox_calls}")"
got=0; has 'modifyvm testvm --firmware efi' "${calls}" || got=1
check "efi-secureboot sets EFI firmware" "${got}"
got=0; has 'inituefivarstore' "${calls}" && has 'enrollorclpk' "${calls}" && has 'enrollmssignatures' "${calls}" || got=1
check "efi-secureboot enrolls the varstore + PK + MS keys" "${got}"
got=0; has 'secureboot --disable' "${calls}" || got=1
check "efi-secureboot defer leaves Secure Boot DISABLED" "${got}"
got=0; if has 'secureboot --enable' "${calls}"; then got=1; fi
check "efi-secureboot defer does NOT enable Secure Boot" "${got}"

## --- efi-secureboot enable-now: enroll keys AND turn Secure Boot ON (installed pair) ---------
true > "${vbox_calls}"
vbox_apply_firmware testvm efi-secureboot enable-now
calls="$(cat -- "${vbox_calls}")"
got=0; has 'inituefivarstore' "${calls}" && has 'enrollmssignatures' "${calls}" || got=1
check "efi-secureboot enable-now enrolls the keys" "${got}"
got=0; has 'secureboot --enable' "${calls}" || got=1
check "efi-secureboot enable-now turns Secure Boot ON" "${got}"
got=0; if has 'secureboot --disable' "${calls}"; then got=1; fi
check "efi-secureboot enable-now does NOT disable Secure Boot" "${got}"

## --- plain efi: firmware + tolerant SB scrub, no key enroll ----------------------------------
true > "${vbox_calls}"
vbox_apply_firmware testvm efi enable-now
calls="$(cat -- "${vbox_calls}")"
got=0; has 'modifyvm testvm --firmware efi' "${calls}" || got=1
check "plain efi sets EFI firmware" "${got}"
got=0; has 'secureboot --disable' "${calls}" || got=1
check "plain efi scrubs inherited Secure Boot state" "${got}"
got=0; if has 'inituefivarstore' "${calls}"; then got=1; fi
check "plain efi does NOT enroll the varstore" "${got}"

## --- VBOX_FW_RUNNER override prefixes EVERY call (per-account sudo route) ---------------------
## Point the DEFAULT VBOXMANAGE at a path that would FAIL if used, so a passing run proves the
## override array -- not the default -- carried every call. A sentinel first token is asserted
## on every recorded line.
true > "${vbox_calls}"
VBOXMANAGE_SAVED="${VBOXMANAGE}"
# shellcheck disable=SC2034  ## consumed by vbox_apply_firmware's default-runner expansion
VBOXMANAGE="/nonexistent/VBoxManage-should-not-run"
# shellcheck disable=SC2034  ## read by the sourced vbox_apply_firmware via dynamic scope
VBOX_FW_RUNNER=( "${vboxmanage_stub}" __WRAP__ )
vbox_apply_firmware testvm efi-secureboot enable-now
unset VBOX_FW_RUNNER
# shellcheck disable=SC2034
VBOXMANAGE="${VBOXMANAGE_SAVED}"
## got=1 iff ANY recorded line LACKS the sentinel prefix (grep -v matches a non-prefixed line).
got=0
if grep --quiet --invert-match '^__WRAP__ ' "${vbox_calls}"; then
   got=1
fi
check "VBOX_FW_RUNNER override prefixes every VBoxManage call" "${got}"
got=0; [ -s "${vbox_calls}" ] || got=1
check "VBOX_FW_RUNNER override actually ran calls (not the failing default)" "${got}"

## --- canary: dm-calamares-install apply_firmware delegates to the shared primitive -----------
got=0
# shellcheck disable=SC2016  ## intentional literal match of the source text (no expansion)
grep --quiet --fixed-strings 'vbox_apply_firmware "${vm}" "${firmware}" defer' "${calamares_install}" || got=1
check "dm-calamares-install apply_firmware delegates to vbox_apply_firmware ... defer" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
