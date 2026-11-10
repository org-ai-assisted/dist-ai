#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## build_vm classifies a failed `unregistervm` as "genuinely unregistered" (and removes the stale
## dir) by matching VBox's not-found text. The match is ANCHORED on `Could not find a registered
## machine named ` so a still-registered, session-LOCKED VM whose NAME happens to contain the
## phrase is NOT misclassified: VBox's lock error quotes the name WITHOUT a following `named `, so
## it must fall through to the loud die, not to deletion.
## [CANARY: an UNANCHORED substring match (bare 'Could not find a registered machine') treats this
## locked VM's error as not-registered and deletes its settings dir.]

## vm/VBOXMANAGE/firmware/coreboot_rom/reinstall/disk are consumed by the sourced build_vm via
## dynamic scope; me/lib_dir are defined there -- shellcheck cannot see across the source.
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

## The crafted VM name embeds the not-found phrase (legal: --vm only rejects '/' and '..').
vmname='Could not find a registered machine'

machine_folder="${work}/vms"
mkdir --parents -- "${machine_folder}"
vboxmanage_stub="${work}/vboxmanage-stub"
vbox_calls="${work}/vbox-calls"
createvm_reached="${work}/createvm-reached"
cat > "${vboxmanage_stub}" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${VBOX_CALLS}"
case "$1" in
   list)
      if [ "$2" = systemproperties ]; then
         printf '%s\n' "Default machine folder:          ${MACHINE_FOLDER}"
         exit 0
      fi
      ;;
   unregistervm)
      ## Still registered + session-locked: VBox quotes the VM name in the lock error. The name
      ## contains "Could not find a registered machine" but there is no following " named ".
      printf '%s\n' "VBoxManage: error: The machine '${VMNAME}' is already locked for a session (or being unlocked)" >&2
      printf '%s\n' "VBoxManage: error: Details: code VBOX_E_INVALID_OBJECT_STATE (0x80bb0007), component MachineWrap, interface IMachine" >&2
      exit 1
      ;;
   createvm)
      printf '%s\n' reached >> "${CREATEVM_REACHED}"
      exit 0
      ;;
esac
exit 0
STUB
chmod +x "${vboxmanage_stub}"
export VBOX_CALLS="${vbox_calls}"
export MACHINE_FOLDER="${machine_folder}"
export CREATEVM_REACHED="${createvm_reached}"
export VMNAME="${vmname}"

if [ -x "${test_dir}/../../bin/dm-vbox-firmware" ]; then
   DM_VBOX_FIRMWARE="$(readlink --canonicalize -- "${test_dir}/../../bin/dm-vbox-firmware")"
else
   DM_VBOX_FIRMWARE='/usr/bin/dm-vbox-firmware'
fi
export DM_VBOX_FIRMWARE

# shellcheck disable=SC1090
source "${subject}"

## No-op sleep so the sourced vbox_config_retry's bounded lock-retry loop runs instantly.
# shellcheck disable=SC2317  ## invoked indirectly from the sourced build_vm / vbox_config_retry
sleep() { :; }

VBOXMANAGE="${vboxmanage_stub}"
vm="${vmname}"
firmware="efi"
coreboot_rom=""
reinstall="false"
cb_uart_sock=""
disk="${work}/disk.vdi"

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: ${1}"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${1}"; fi
}

## Plant the registered-but-locked VM's settings dir (name = the crafted string).
mkdir --parents -- "${machine_folder}/${vmname}"
printf '%s\n' registered > "${machine_folder}/${vmname}/vm.vbox"
[ -e "${machine_folder}/${vmname}/vm.vbox" ] || { printf '%s\n' "FATAL: could not plant VM dir" >&2; exit 1; }

## Run build_vm in a command-substitution subshell so its die() `exit` is caught here, not
## propagated to this script.
true > "${vbox_calls}"
rc=0
build_vm_out="$(build_vm 2>&1)" || rc=$?
unset build_vm_out

## CANARY: the locked VM's settings must survive. An unanchored match deletes them.
got=0; { [ -d "${machine_folder}/${vmname}" ] && [ -e "${machine_folder}/${vmname}/vm.vbox" ]; } || got=1
check 'a locked VM named after the not-found phrase keeps its settings dir' "${got}"
got=0; [ "${rc}" -ne 0 ] || got=1
check 'build_vm fails loud instead of deleting + continuing' "${got}"
got=0; { [ ! -s "${createvm_reached}" ]; } || got=1
check 'createvm is not reached' "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
