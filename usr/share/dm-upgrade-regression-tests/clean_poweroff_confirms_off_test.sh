#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## clean_poweroff (vbox-session.bsh) must CONFIRM the VM is actually powered off before
## returning 0 -- boot_installed mounts the disk offline right after, and the frontend holds
## the disk lock until the VM is off, so a premature success races qemu-nbd. Drives the REAL
## clean_poweroff with a stub VBoxManage and short (overridable) deadlines:
##   * a VM stuck 'running' through BOTH the ACPI wait and the hard-poweroff wait -> RETURN 1
##     (canary: the pre-fix body fell through to the loop's success status and returned 0).
##   * a VM that reports 'poweroff' -> RETURN 0.
## No real VM, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
lib="${test_dir}/../dm-smbios-reader-boot-tests/vbox-session.bsh"
[ -r "${lib}" ] || { printf '%s\n' "FATAL: not found: ${lib}" >&2; exit 1; }

tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${tmp}"; }
trap cleanup EXIT

## Stub VBoxManage: controlvm succeeds; showvminfo reports the state named by VM_STATE.
stub="${tmp}/VBoxManage"
cat > "${stub}" <<'STUB'
#!/bin/bash
case "$1" in
   showvminfo) printf 'VMState="%s"\n' "${VM_STATE:-running}" ;;
   *) : ;;
esac
exit 0
STUB
chmod +x "${stub}"

# shellcheck disable=SC2034  ## read by the sourced fragment
VBOXMANAGE="${stub}"
# shellcheck disable=SC2034
vm='testvm'
# shellcheck disable=SC2034
me='clean_poweroff_test'

# shellcheck source=../dm-smbios-reader-boot-tests/vbox-session.bsh
source "${lib}"

pass=0
fail=0
check() {
   if [ "$2" = "$3" ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1 (got '$2' want '$3')" >&2
      fail=$(( fail + 1 ))
   fi
}

## 1. Never powers off -> RETURN 1 (short deadlines keep the real waits to a few seconds).
rc=0
VM_STATE='running' CLEAN_POWEROFF_ACPI_S=1 CLEAN_POWEROFF_HARD_S=1 clean_poweroff >/dev/null 2>&1 || rc=$?
check "stuck-running VM: clean_poweroff returns nonzero (not a false success)" "${rc}" '1'

## 2. Reports powered off -> RETURN 0 (first poll, no wait).
rc=0
VM_STATE='poweroff' clean_poweroff >/dev/null 2>&1 || rc=$?
check "powered-off VM: clean_poweroff returns 0" "${rc}" '0'

## 3. A clean_poweroff now CAN return 1 (a wedged VM), so a CLEANUP EXIT trap that calls it must
## be best-effort -- a bare call aborts the errexit trap before `exit "${rc}"` and turns a PASS
## into exit 1 (the fabricated-fail the on_exit / boot_gateway `|| true` fixes close). Mirror that
## structure (a trap function doing `local rc=$?; ...; exit "${rc}"`, as on_exit does) with the
## REAL clean_poweroff stubbed to a wedged VM, and assert a PASS still exits 0.
# shellcheck disable=SC2317  ## fires via the EXIT trap, not a direct call
exit_trap() {
   local trap_rc=$?
   VM_STATE='running' CLEAN_POWEROFF_ACPI_S=1 CLEAN_POWEROFF_HARD_S=1 clean_poweroff >/dev/null 2>&1 || true
   exit "${trap_rc}"
}
rc=0
(
   set -o errexit
   trap exit_trap EXIT
   true   ## the run's real outcome: a PASS
) >/dev/null 2>&1 || rc=$?
check "best-effort clean_poweroff in an errexit EXIT trap preserves a PASS (exit 0)" "${rc}" '0'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ]
