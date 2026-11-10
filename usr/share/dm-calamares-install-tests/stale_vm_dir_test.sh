#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## build_vm non-reinstall path: a crashed prior run can leave this VM's settings dir on disk
## WITHOUT a registration, so the swallowed `unregistervm --delete` is a no-op and `createvm` then
## dies VBOX_E_FILE_ERROR ("Machine settings file ... already exists"). image-test-gc cannot clear
## it (it refuses persist-*), so build_vm must remove the stale per-VM dir itself -- scoped to the
## one VM it is about to recreate. Drives the REAL build_vm (sourced define-only) with a VBOXMANAGE
## stub that emulates VBox's refusal (createvm fails if the dir exists).
## [CANARY: pre-fix build_vm never removes the dir -> createvm fails and build_vm aborts.]

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

## VBOXMANAGE stub: record calls; answer `list systemproperties` with our machine folder; emulate
## VBox by REFUSING createvm when the per-VM dir already exists (and creating it otherwise). All
## other verbs succeed.
machine_folder="${work}/vms"
mkdir --parents -- "${machine_folder}"
vboxmanage_stub="${work}/vboxmanage-stub"
vbox_calls="${work}/vbox-calls"
cat > "${vboxmanage_stub}" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${VBOX_CALLS}"
if [ "$1" = list ] && [ "$2" = systemproperties ]; then
   printf '%s\n' "Default machine folder:          ${MACHINE_FOLDER}"
   exit 0
fi
if [ "$1" = unregistervm ]; then
   ## This scenario is crash residue: the dir exists but the VM is NOT registered. unregistervm
   ## reports exactly that, so build_vm classifies it as unregistered and proceeds to the stale-dir
   ## removal below (rather than failing loud).
   printf '%s\n' "VBoxManage: error: Could not find a registered machine named 'testvm'" >&2
   exit 1
fi
if [ "$1" = createvm ]; then
   if [ -e "${MACHINE_FOLDER}/testvm" ]; then
      ## Marker: createvm was REFUSED because the dir still exists (VBOX_E_FILE_ERROR). The fix
      ## removes the dir first, so on fixed code this never fires -- a clean canary independent of
      ## errexit suppression (build_vm runs under `|| rc=$?`, which disables errexit inside it).
      printf '%s\n' refused >> "${CREATEVM_REFUSED}"
      printf '%s\n' "VBoxManage: error: Machine settings file '${MACHINE_FOLDER}/testvm/testvm.vbox' already exists" >&2
      exit 1
   fi
   mkdir --parents -- "${MACHINE_FOLDER}/testvm"
   exit 0
fi
exit 0
STUB
chmod +x "${vboxmanage_stub}"
createvm_refused="${work}/createvm-refused"
export VBOX_CALLS="${vbox_calls}"
export MACHINE_FOLDER="${machine_folder}"
export CREATEVM_REFUSED="${createvm_refused}"

if [ -x "${test_dir}/../../bin/dm-vbox-firmware" ]; then
   DM_VBOX_FIRMWARE="$(readlink --canonicalize -- "${test_dir}/../../bin/dm-vbox-firmware")"
else
   DM_VBOX_FIRMWARE='/usr/bin/dm-vbox-firmware'
fi
export DM_VBOX_FIRMWARE

# shellcheck disable=SC1090
source "${subject}"

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

## Pre-plant a stale, UNREGISTERED VM dir (the crash residue).
mkdir --parents -- "${machine_folder}/testvm"
printf '%s\n' stale > "${machine_folder}/testvm/testvm.vbox"
[ -e "${machine_folder}/testvm/testvm.vbox" ] || { printf '%s\n' "FATAL: could not plant stale dir" >&2; exit 1; }

true > "${vbox_calls}"
rc=0
out="$(build_vm 2>&1)" || rc=$?

## CANARY (createvm refusal): pre-fix build_vm leaves the stale dir, so the stub REFUSES createvm;
## the fix removes it first, so createvm is never refused. Independent of build_vm's own rc (which
## is unreliable here -- the `|| rc=$?` call disables errexit inside the function).
got=0; { [ ! -s "${createvm_refused}" ]; } || got=1
check 'createvm never refused (stale dir removed before createvm)' "${got}"
got=0; has 'removing stale VM dir' "${out}" || got=1
check 'build_vm warns it removed the stale VM dir' "${got}"
got=0; has 'createvm --name testvm' "$(cat -- "${vbox_calls}")" || got=1
check 'createvm was reached' "${got}"
## The stale .vbox is gone; the only testvm dir now is the one createvm recreated empty.
got=0; { [ -d "${machine_folder}/testvm" ] && [ ! -e "${machine_folder}/testvm/testvm.vbox" ]; } || got=1
check 'the stale settings file is gone (dir was wiped, not reused)' "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
