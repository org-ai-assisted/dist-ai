#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-calamares-install's coreboot+UefiPayload firmware layer. The coreboot ROM is
## a generic EFI firmware (a drop-in for VBox's OVMF), so --coreboot-rom is PURELY ADDITIVE on the
## efi lane:
##   - apply_firmware emits the two efi-device extradata keys (EfiRom + CorebootRom 1);
##   - build_vm's modifyvm swaps in the proven coreboot board (piix3 / IOAPIC / HPET / vboxvga /
##     the 36-bit-phys cpuid leaf) and a COM1 server socket;
##   - WITHOUT --coreboot-rom the bios/efi/efi-secureboot modifyvm argv is BYTE-UNCHANGED.
##
## CANARY: the coreboot path MUST set 'CorebootRom 1' -- absent on the pre-coreboot code, so this
## FAILS against it. Drives the REAL apply_firmware + build_vm (sourced define-only) with a
## recording VBOXMANAGE stub. No VM, no root, no network.

## vm/VBOXMANAGE/firmware/coreboot_rom/reinstall/disk below are consumed by the sourced
## dm-calamares-install (apply_firmware/build_vm) via dynamic scope, and me is defined there --
## shellcheck cannot see across the source.
# shellcheck disable=SC2034,SC2154
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
vbox_calls="${work}/vbox-calls"
cat > "${vboxmanage_stub}" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${VBOX_CALLS}"
exit 0
STUB
chmod +x "${vboxmanage_stub}"
export VBOX_CALLS="${vbox_calls}"

# shellcheck disable=SC1090
source "${subject}"

vm="testvm"
VBOXMANAGE="${vboxmanage_stub}"
reinstall="false"
disk="${work}/disk.vdi"

cb_rom="/opt/coreboot/cb-uefi-gfx.rom"
cb_cpuid='0x80000008 0x00003024 0x791ef257 0x0000400f 0x00010000'
efirom_key='VBoxInternal/Devices/efi/0/Config/EfiRom'
corebootrom_key='VBoxInternal/Devices/efi/0/Config/CorebootRom'

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: $1"
   fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## --- apply_firmware WITHOUT coreboot: plain efi emits NO coreboot extradata ------------------
firmware="efi"
coreboot_rom=""
true > "${vbox_calls}"
apply_firmware
calls="$(cat -- "${vbox_calls}")"
got=0; if has "${efirom_key}" "${calls}" || has "${corebootrom_key}" "${calls}"; then got=1; fi
check "apply_firmware emits NO coreboot extradata without --coreboot-rom" "${got}"

## --- apply_firmware WITH coreboot: EfiRom + CorebootRom 1 on the efi device ------------------
coreboot_rom="${cb_rom}"
true > "${vbox_calls}"
apply_firmware
calls="$(cat -- "${vbox_calls}")"
got=0; has "setextradata testvm ${efirom_key} ${cb_rom}" "${calls}" || got=1
check "apply_firmware sets EfiRom = the coreboot ROM path" "${got}"
## CANARY: pre-coreboot apply_firmware never wrote CorebootRom -- this assertion FAILS on it.
got=0; has "setextradata testvm ${corebootrom_key} 1" "${calls}" || got=1
check "apply_firmware sets CorebootRom 1 (coreboot layered on the efi device)" "${got}"

## --- build_vm WITHOUT coreboot: the modifyvm argv is BYTE-UNCHANGED (additive proof) --------
firmware="efi"
coreboot_rom=""
cb_uart_sock=""
true > "${vbox_calls}"
build_vm
modify_line="$(grep -- '^modifyvm testvm --memory' "${vbox_calls}" | head -n 1)"
cpus=""
if [[ "${modify_line}" =~ --cpus\ ([0-9]+) ]]; then
   cpus="${BASH_REMATCH[1]}"
fi
expected_plain="modifyvm testvm --memory 4096 --cpus ${cpus} --graphicscontroller vmsvga --vram 128 --mouse usbtablet --usb-ohci on --nic1 nat"
got=0; [ -n "${cpus}" ] && [ "${modify_line}" = "${expected_plain}" ] || got=1
check "build_vm modifyvm argv is byte-unchanged without --coreboot-rom (additive)" "${got}"
got=0; [ -z "${cb_uart_sock}" ] || got=1
check "build_vm sets no COM1 drain socket without --coreboot-rom" "${got}"

## --- build_vm WITH coreboot: swaps in the coreboot board + COM1 server socket ----------------
firmware="efi"
coreboot_rom="${cb_rom}"
cb_uart_sock=""
true > "${vbox_calls}"
build_vm
calls="$(cat -- "${vbox_calls}")"
cb_modify_line="$(grep -- '^modifyvm testvm --memory' "${vbox_calls}" | head -n 1)"
for tok in '--chipset piix3' '--ioapic on' '--hpet on' \
   '--graphicscontroller vboxvga' "--cpuid-set ${cb_cpuid}" \
   '--uart1 0x3f8 4 --uartmode1 server'; do
   got=0; has "${tok}" "${cb_modify_line}" || got=1
   check "build_vm coreboot modifyvm carries '${tok}'" "${got}"
done
## The coreboot recipe REPLACES vmsvga -- it must not leak the default controller.
got=0; if has 'vmsvga' "${cb_modify_line}"; then got=1; fi
check "build_vm coreboot modifyvm drops vmsvga (vboxvga only)" "${got}"
## build_vm -> apply_firmware wires the extradata on the same run.
got=0; has "setextradata testvm ${corebootrom_key} 1" "${calls}" || got=1
check "build_vm (via apply_firmware) wires CorebootRom 1" "${got}"
## COM1 is a per-run server socket under HOME.
got=0; [ "${cb_uart_sock}" = "${HOME}/${me}-cb-uart.sock" ] || got=1
check "build_vm sets cb_uart_sock under HOME for the COM1 drain" "${got}"

## --- Finding 3 regression: --reinstall + --coreboot-rom re-arms the COM1 drain --------------
## The reinstall branch returns early (reuses the VM + its persisted coreboot board); it must
## still set cb_uart_sock or cb_drain_start no-ops and the undrained 16550 wedges the boot.
reinstall='true'
coreboot_rom="${cb_rom}"
iso="${work}/k.iso"
cb_uart_sock=''
build_vm >/dev/null 2>&1 || true
got=0; [ "${cb_uart_sock}" = "${HOME}/${me}-cb-uart.sock" ] || got=1
check "build_vm --reinstall coreboot re-arms cb_uart_sock (drain not skipped)" "${got}"
reinstall='false'

## --- Finding 1 regression: a coreboot install declares dasharo-efi, so it MATCHES ------------
## capture_firmware_lane must declare the coreboot identity (dasharo-efi), NOT vbox-efi, or a
## SUCCESSFUL coreboot install is reported a firmware MISMATCH and the whole run is marked FAIL.
## Stub the guest probe to a coreboot boot (EFI=1/SB=0/COREBOOT=1) and drive the REAL
## dm-firmware-identity. FAILS on the pre-fix code (declared=vbox-efi != detected=dasharo-efi
## -> MATCH=false).
# shellcheck disable=SC2317  ## called indirectly by the sourced capture_firmware_lane
gc_run() { printf '%s\n' 'EFI=1' 'SB=0' 'COREBOOT=1' 'BIOS_VENDOR=coreboot'; }
live_account='user'
firmware='efi'
coreboot_rom="${cb_rom}"
firmware_evidence_file="${work}/fw-evidence"
capture_firmware_lane
fw_ev="$(cat "${firmware_evidence_file}" 2>/dev/null)"
got=0; has 'MATCH=true' "${fw_ev}" || got=1
check "capture_firmware_lane: coreboot install MATCHes (declares dasharo-efi, not a false mismatch)" "${got}"
got=0; has 'DETECTED=dasharo-efi' "${fw_ev}" || got=1
check "capture_firmware_lane: coreboot detected=dasharo-efi" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
