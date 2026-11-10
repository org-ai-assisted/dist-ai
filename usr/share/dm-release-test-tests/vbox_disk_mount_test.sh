#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-test the thin VBox/VM-aware vbox-disk-mount wrapper without root, a real VM, or a real
## disk: source the real tool (its BASH_SOURCE guard keeps main from running), stub VBoxManage
## (so installed_disk_path resolves a disk) and image-mount (records argv), and assert the
## wrapper resolves the VM's disk + format and delegates `image-mount run --disk <disk>
## --format <fmt> [--passphrase-file PF] -- CMD`. The real mount is covered by image_mount_*.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject="${VBOX_DISK_MOUNT_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/vbox-disk-mount" ]; then
      subject="${test_dir}/../../bin/vbox-disk-mount"
   else
      subject='/usr/bin/vbox-disk-mount'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: vbox-disk-mount not found at ${subject}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
test_cleanup() { safe-rm --recursive --force -- "${work}"; }
trap test_cleanup EXIT

argv_log="${work}/im.argv"
## Stub image-mount: record argv, do not mount. Set BEFORE sourcing -- the wrapper resolves the
## engine path at source time from IMAGE_MOUNT.
stub="${work}/image-mount-stub"
cat > "${stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$*" > "${argv_log}"
exit 0
STUB
chmod +x "${stub}"
export IMAGE_MOUNT="${stub}"

## Stub VBoxManage (read at call time by installed_disk_path). Default: a VM with a .vdi disk.
vbm="${work}/VBoxManage"
write_vbm_disk() {
   cat > "${vbm}" <<STUB
#!/bin/bash
cat <<OUT
name="testvm"
"SATA-0-0"="$1"
VMState="poweroff"
OUT
STUB
   chmod +x "${vbm}"
}
write_vbm_disk '/home/eph/VirtualBox VMs/testvm/testvm.vdi'
export VBOXMANAGE="${vbm}"

# shellcheck source=../../bin/vbox-disk-mount
source "${subject}"

pass=0
fail=0
check() {
   local desc="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "ok: ${desc}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}" "  got:  ${got}" "  want: ${want}" >&2
      fail=$(( fail + 1 ))
   fi
}
outcome() { if [ "$1" -eq 0 ]; then printf '%s' 'accepted'; else printf '%s' 'rejected'; fi; }

## --- argument rejection ---------------------------------------------------------------
rc=0; ( parse_args ) >/dev/null 2>&1 || rc=$?
check 'no arguments rejected' "$(outcome "${rc}")" 'rejected'

rc=0; ( parse_args foo ) >/dev/null 2>&1 || rc=$?
check 'a first argument other than run rejected' "$(outcome "${rc}")" 'rejected'

rc=0; ( parse_args run -- echo hi ) >/dev/null 2>&1 || rc=$?
check 'missing --vm rejected' "$(outcome "${rc}")" 'rejected'

rc=0; ( parse_args run --vm testvm ) >/dev/null 2>&1 || rc=$?
check 'missing command after -- rejected' "$(outcome "${rc}")" 'rejected'

## --- delegation: resolve the VM disk + format, call image-mount with the right argv -------
## Each main() in a SUBSHELL: the real tool is a fresh process per run, so run-scoped globals
## (vm, cmd, passphrase_file set by parse_args) must not leak between cases in this sourced shell.
true > "${argv_log}"
( main run --vm testvm -- touch marker )
check 'vdi VM: delegates run --disk <vdi> --format vdi -- touch marker' \
   "$(cat -- "${argv_log}")" "run --disk /home/eph/VirtualBox VMs/testvm/testvm.vdi --format vdi -- touch marker"

## With a passphrase file -> --passphrase-file is threaded through, after --format.
pf="${work}/pf"
printf '%s' 'k' > "${pf}"
true > "${argv_log}"
( main run --vm testvm --passphrase-file "${pf}" -- touch marker )
check 'encrypted VM: --passphrase-file threaded after --format' \
   "$(cat -- "${argv_log}")" "run --disk /home/eph/VirtualBox VMs/testvm/testvm.vdi --format vdi --passphrase-file ${pf} -- touch marker"

## A non-vdi (.vmdk) VM disk -> format resolved to vmdk (disk_format_for), never forced to vdi.
write_vbm_disk '/home/eph/VirtualBox VMs/ws/ws.vmdk'
true > "${argv_log}"
( main run --vm testvm -- touch marker )
check 'vmdk VM: format resolved to vmdk' \
   "$(cat -- "${argv_log}")" "run --disk /home/eph/VirtualBox VMs/ws/ws.vmdk --format vmdk -- touch marker"

## --- vbox_manage(): resolve the VM as the INVOKING user under sudo, directly otherwise --------
## VBoxManage reads the PER-USER registry, so a sudo run (euid 0, HOME=/root) must runuser to
## SUDO_USER or it reads root's registry and misses the caller's VM. Exercise the REAL function's
## branch selection with PATH-shadowed stubs: 'id -u' reports a forced euid (FAKE_UID), 'runuser'
## and 'VBoxManage' each record which path fired. Everything else on PATH stays real.
stubdir="${work}/pathstub"
mkdir --parents -- "${stubdir}"
vm_call="${work}/vm.call"
cat > "${stubdir}/id" <<STUB
#!/bin/bash
if [ "\$1" = '-u' ]; then printf '%s\n' "\${FAKE_UID:-1000}"; exit 0; fi
exec /usr/bin/id "\$@"
STUB
cat > "${stubdir}/runuser" <<STUB
#!/bin/bash
printf 'RUNUSER:%s\n' "\$*" > "${vm_call}"
STUB
cat > "${stubdir}/VBoxManage" <<STUB
#!/bin/bash
printf 'DIRECT:%s\n' "\$*" > "${vm_call}"
STUB
chmod +x "${stubdir}/id" "${stubdir}/runuser" "${stubdir}/VBoxManage"

## Run the REAL vbox_manage once with a forced euid (FAKE_UID, read by the id stub) + SUDO_USER.
## A function with `local -x` scopes PATH/FAKE_UID/SUDO_USER to the call and restores them on
## return -- no subshell, so nothing leaks between cases. SUDO_USER='' is the "no SUDO_USER" case
## (the function tests `-n "${SUDO_USER:-}"`, so empty and unset select the same direct branch).
vm_manage_case() {
   local -x PATH="${stubdir}:${PATH}"
   local -x FAKE_UID="$1"
   local -x SUDO_USER="$2"
   true > "${vm_call}"
   vbox_manage showvminfo testvm --machinereadable
}

## euid 0 + SUDO_USER (non-root) -> runuser to that user, VBoxManage args threaded after '--'.
vm_manage_case 0 alice
check 'vbox_manage: sudo (euid 0, SUDO_USER=alice) runs VBoxManage as the invoking user' \
   "$(cat -- "${vm_call}")" 'RUNUSER:-u alice -- VBoxManage showvminfo testvm --machinereadable'

## euid 0 but no SUDO_USER (a direct root shell) -> call VBoxManage directly, no runuser.
vm_manage_case 0 ''
check 'vbox_manage: root with no SUDO_USER calls VBoxManage directly' \
   "$(cat -- "${vm_call}")" 'DIRECT:showvminfo testvm --machinereadable'

## euid 0 + SUDO_USER=root (sudo -u root) -> no user switch, call VBoxManage directly.
vm_manage_case 0 root
check 'vbox_manage: SUDO_USER=root calls VBoxManage directly (no self-runuser)' \
   "$(cat -- "${vm_call}")" 'DIRECT:showvminfo testvm --machinereadable'

## non-root direct run (even with SUDO_USER set) -> call VBoxManage directly as the caller.
vm_manage_case 1000 alice
check 'vbox_manage: non-root run calls VBoxManage directly' \
   "$(cat -- "${vm_call}")" 'DIRECT:showvminfo testvm --machinereadable'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
