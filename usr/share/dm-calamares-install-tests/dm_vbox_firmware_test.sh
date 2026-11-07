#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for the shared dm-vbox-firmware tool -- the single source for the modifyvm --firmware
## + Secure Boot NVRAM sequence, extracted from dm-calamares-install's apply_firmware and reused by
## dm-release-test. Drives the REAL script with a recording VBOXMANAGE stub. No VM, no root. Asserts
## the CLEAN interface:
##   bios                         -> modifyvm --firmware bios only (no NVRAM ops);
##   efi                          -> modifyvm --firmware efi + tolerant secureboot --disable;
##   efi-secureboot               -> enroll keys + secureboot --ENABLE (the expected default);
##   efi-secureboot --defer-enforcement -> enroll keys + secureboot --disable (install phase);
##   enable-secureboot            -> secureboot --enable ONLY (no modifyvm, no inituefivarstore);
##   --defer-enforcement with a non-efi-secureboot mode -> rejected (exit 64);
##   dm-calamares-install apply_firmware invokes it with --defer-enforcement for efi-secureboot.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_VBOX_FIRMWARE:-}" \
   "${test_dir}/../../bin/dm-vbox-firmware" \
   "/usr/bin/dm-vbox-firmware"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-vbox-firmware not found (set DM_VBOX_FIRMWARE)." >&2
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
export VBOXMANAGE="${vboxmanage_stub}"

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

run_fw() {
   true > "${vbox_calls}"
   "${subject}" "$@"
}

## --- bios: firmware only, no NVRAM ---
run_fw testvm bios
calls="$(cat -- "${vbox_calls}")"
got=0; has 'modifyvm testvm --firmware bios' "${calls}" || got=1
check "bios sets BIOS firmware" "${got}"
got=0; if has 'modifynvram' "${calls}"; then got=1; fi
check "bios touches no NVRAM" "${got}"

## --- efi: firmware + tolerant SB scrub, no key enroll ---
run_fw testvm efi
calls="$(cat -- "${vbox_calls}")"
got=0; has 'modifyvm testvm --firmware efi' "${calls}" || got=1
check "efi sets EFI firmware" "${got}"
got=0; has 'secureboot --disable' "${calls}" || got=1
check "efi scrubs inherited Secure Boot state" "${got}"
got=0; if has 'inituefivarstore' "${calls}"; then got=1; fi
check "efi does NOT enroll the varstore" "${got}"

## --- efi-secureboot: enroll keys AND enable Secure Boot (the expected default) ---
run_fw testvm efi-secureboot
calls="$(cat -- "${vbox_calls}")"
got=0; has 'inituefivarstore' "${calls}" && has 'enrollorclpk' "${calls}" && has 'enrollmssignatures' "${calls}" || got=1
check "efi-secureboot enrolls the varstore + PK + MS keys" "${got}"
got=0; has 'secureboot --enable' "${calls}" || got=1
check "efi-secureboot ENABLES Secure Boot by default" "${got}"
got=0; if has 'secureboot --disable' "${calls}"; then got=1; fi
check "efi-secureboot default does NOT leave Secure Boot disabled" "${got}"

## --- efi-secureboot --defer-enforcement: enroll keys, leave Secure Boot OFF (install phase) ---
run_fw testvm efi-secureboot --defer-enforcement
calls="$(cat -- "${vbox_calls}")"
got=0; has 'inituefivarstore' "${calls}" || got=1
check "efi-secureboot --defer-enforcement still enrolls the keys" "${got}"
got=0; has 'secureboot --disable' "${calls}" || got=1
check "efi-secureboot --defer-enforcement leaves Secure Boot DISABLED" "${got}"
got=0; if has 'secureboot --enable' "${calls}"; then got=1; fi
check "efi-secureboot --defer-enforcement does NOT enable Secure Boot" "${got}"

## --- enable-secureboot: enforce ON only, no re-init (preserves boot entries + MOK) ---
run_fw testvm enable-secureboot
calls="$(cat -- "${vbox_calls}")"
got=0; has 'secureboot --enable' "${calls}" || got=1
check "enable-secureboot turns Secure Boot ON" "${got}"
got=0; if has 'inituefivarstore' "${calls}"; then got=1; fi
check "enable-secureboot does NOT re-init the varstore" "${got}"
got=0; if has 'modifyvm' "${calls}"; then got=1; fi
check "enable-secureboot does NOT change the firmware type" "${got}"

## --- --defer-enforcement is rejected for a non-efi-secureboot mode ---
rej_rc=0
"${subject}" testvm bios --defer-enforcement >/dev/null 2>&1 || rej_rc=$?
got=0; [ "${rej_rc}" -eq 64 ] || got=1
check "--defer-enforcement rejected with bios (exit 64)" "${got}"

## --- a bad mode is rejected ---
bad_rc=0
"${subject}" testvm bogus >/dev/null 2>&1 || bad_rc=$?
got=0; [ "${bad_rc}" -eq 64 ] || got=1
check "unknown mode rejected (exit 64)" "${got}"

## --- canary: dm-calamares-install apply_firmware defers enforcement for efi-secureboot ---
# shellcheck disable=SC2016  ## intentional literal match of the source text
got=0; grep --quiet --fixed-strings 'fw_args+=( --defer-enforcement )' "${calamares_install}" || got=1
check "dm-calamares-install defers enforcement via dm-vbox-firmware" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
