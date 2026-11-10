#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## build_vm non-reinstall path: when the VM is STILL REGISTERED and its session will not release
## (running / session-locked), `unregistervm --delete` fails. build_vm must NOT then delete the
## VM's on-disk settings dir -- doing so loses the VM and createvm still fails (name taken). It
## must fail LOUD instead. Drives the REAL build_vm (sourced define-only) with a VBOXMANAGE stub
## that reports the VM registered and makes unregistervm fail with the locked-session error.
## [CANARY: pre-fix build_vm swallows the failed unregister, deletes the dir on `[ -e ]` alone,
## and proceeds to createvm -> the registered VM's settings are lost.]

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

## VBOXMANAGE stub: record calls; answer `list systemproperties` with our machine folder; report
## the VM REGISTERED (showvminfo exit 0); make `unregistervm --delete` fail with the locked-session
## error vbox_config_retry recognises (so the fixed build_vm retries, then fails loud). createvm is
## recorded if ever reached -- the fix must die before it.
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
   showvminfo)
      ## testvm is STILL REGISTERED, but showvminfo --machinereadable takes a SHARED machine lock
      ## and fails in the async post-poweroff unlock window -- a lock-based registration probe is
      ## fooled into reading this as "not registered". (Load-bearing: the fix must NOT probe with
      ## showvminfo; a build_vm that does deletes this live VM's dir.)
      printf '%s\n' "VBoxManage: error: The machine 'testvm' is already locked for a session (or being unlocked)" >&2
      printf '%s\n' "VBoxManage: error: Details: code VBOX_E_INVALID_OBJECT_STATE (0x80bb0007), component MachineWrap, interface IMachine" >&2
      exit 1
      ;;
   unregistervm)
      ## Session-locked: VBox refuses to unregister. Message carries the lock markers
      ## vbox_config_retry matches (already locked / VBOX_E_INVALID_OBJECT_STATE).
      printf '%s\n' "VBoxManage: error: Cannot unregister the machine 'testvm' while it is locked" >&2
      printf '%s\n' "VBoxManage: error: Details: code VBOX_E_INVALID_OBJECT_STATE (0x80bb0007), the machine 'testvm' is already locked for a session (or being unlocked)" >&2
      exit 1
      ;;
   createvm)
      ## The fix must die before this; record it so a pre-fix fall-through is caught.
      printf '%s\n' reached >> "${CREATEVM_REACHED}"
      mkdir --parents -- "${MACHINE_FOLDER}/testvm"
      exit 0
      ;;
esac
exit 0
STUB
chmod +x "${vboxmanage_stub}"
export VBOX_CALLS="${vbox_calls}"
export MACHINE_FOLDER="${machine_folder}"
export CREATEVM_REACHED="${createvm_reached}"

if [ -x "${test_dir}/../../bin/dm-vbox-firmware" ]; then
   DM_VBOX_FIRMWARE="$(readlink --canonicalize -- "${test_dir}/../../bin/dm-vbox-firmware")"
else
   DM_VBOX_FIRMWARE='/usr/bin/dm-vbox-firmware'
fi
export DM_VBOX_FIRMWARE

# shellcheck disable=SC1090
source "${subject}"

## No-op sleep so the sourced vbox_config_retry's bounded (~30 x 1s) lock-retry loop runs instantly;
## the subject's own `sleep 2` collapses too. We assert the branch, not the wall-clock.
# shellcheck disable=SC2317  ## invoked indirectly from the sourced build_vm / vbox_config_retry
sleep() { :; }

VBOXMANAGE="${vboxmanage_stub}"
vm="testvm"
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
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## Plant the REGISTERED VM's settings dir (what unregistervm cannot remove while locked).
mkdir --parents -- "${machine_folder}/testvm"
printf '%s\n' registered > "${machine_folder}/testvm/testvm.vbox"
[ -e "${machine_folder}/testvm/testvm.vbox" ] || { printf '%s\n' "FATAL: could not plant VM dir" >&2; exit 1; }

true > "${vbox_calls}"
rc=0
out="$(build_vm 2>&1)" || rc=$?

## CANARY (data loss): the registered VM's settings dir and .vbox must SURVIVE. Pre-fix build_vm
## deletes them; the fix leaves them untouched.
got=0; { [ -d "${machine_folder}/testvm" ] && [ -e "${machine_folder}/testvm/testvm.vbox" ]; } || got=1
check 'the registered VM settings dir + .vbox are preserved (not deleted)' "${got}"

## build_vm must FAIL LOUD rather than fall through. Pre-fix swallows the error and returns 0.
got=0; [ "${rc}" -ne 0 ] || got=1
check 'build_vm fails (non-zero) instead of continuing' "${got}"
got=0; has 'refusing to delete' "${out}" || got=1
check 'build_vm explains it is refusing to delete the locked VM dir' "${got}"

## createvm must never be reached once unregister failed (name still taken -> it would fail anyway).
got=0; { [ ! -s "${createvm_reached}" ]; } || got=1
check 'createvm is not reached after the failed unregister' "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
