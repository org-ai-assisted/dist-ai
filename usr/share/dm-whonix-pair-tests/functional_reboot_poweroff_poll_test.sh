#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ws_func_reboot_sysmaint is the battery's reboot_sysmaint_fn. It must (a) confirm the WS
## actually powered off (wait_vm_off) BEFORE startvm -- clean_poweroff is async, so an
## immediate startvm can race a still-running VM; and (b) on ANY reboot failure RETURN
## nonzero rather than die/exit, so run_release_check_battery records check 2's failure
## (number + reason) and main_functional reports it. Canary: a die would exit the process
## under the callback, losing the recorded reason.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## DM_WHONIX_PAIR_BIN overrides the subject (the canary points it at a pre-fix export).
tool="${DM_WHONIX_PAIR_BIN:-${here}/../../bin/dm-whonix-pair}"
[ -x "${tool}" ] || { printf '%s\n' "FATAL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

export VBM_LOG="${work}/vboxmanage.argv"
printf '%s' "" > "${VBM_LOG}"
cat > "${work}/VBoxManage" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${VBM_LOG}"
exit 0
STUB
chmod +x "${work}/VBoxManage"
export VBOXMANAGE="${work}/VBoxManage"

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

## Shadow sleep so bounded loops run instantly; shadow the heavy reboot-prefix/suffix helpers
## so only wait_vm_off + startvm (the ordering under test) reach the VBoxManage recorder.
# shellcheck disable=SC2317
sleep() { :; }
# shellcheck disable=SC2317
clean_poweroff() { :; }
# shellcheck disable=SC2317
select_installed_sysmaint() { :; }
# shellcheck disable=SC2317
wait_guestcontrol_ready() { :; }
# shellcheck disable=SC2317
wait_ready() { :; }
# shellcheck disable=SC2317
open_terminal() { :; }

pass=0
fail=0
assert() { local label="$1"; shift; if "$@"; then pass=$(( pass + 1 )); printf '%s\n' "PASS: ${label}"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${label}"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## Unit: wait_vm_off returns 0 when the VM reports off, nonzero when it never does.
# shellcheck disable=SC2317
vm_state() { printf '%s\n' "poweroff"; }
rc=0; wait_vm_off testvm 2 || rc=$?
assert "wait_vm_off: off -> rc 0" test "${rc}" -eq 0
# shellcheck disable=SC2317
vm_state() { printf '%s\n' "running"; }
rc=0; wait_vm_off testvm 2 || rc=$?
assert "wait_vm_off: never off -> rc nonzero" test "${rc}" -ne 0

## Case A: WS stuck 'running' (wait_vm_off never settles). The callback must RETURN 1 (not
## die/exit) and NEVER reach startvm.
printf '%s' "" > "${VBM_LOG}"
rc=0
( ws_func_reboot_sysmaint ) >/dev/null 2>&1 || rc=$?
assert "stuck-running reboot RETURNS 1 (does not die/exit the process)" test "${rc}" -eq 1
if grep --quiet startvm "${VBM_LOG}"; then
   fail=$(( fail + 1 ))
   printf '%s\n' "FAIL: startvm was called though the WS never powered off"
else
   pass=$(( pass + 1 ))
   printf '%s\n' "PASS: startvm NOT called when WS never powered off"
fi

## Case B: WS powers off but guestcontrol never comes back as sysmaint -> also RETURN 1.
# shellcheck disable=SC2317
vm_state() { printf '%s\n' "poweroff"; }
# shellcheck disable=SC2317
wait_guestcontrol_ready() { return 1; }
rc=0
( ws_func_reboot_sysmaint ) >/dev/null 2>&1 || rc=$?
assert "guestcontrol-not-ready reboot RETURNS 1 (does not die/exit)" test "${rc}" -eq 1
# shellcheck disable=SC2317
wait_guestcontrol_ready() { :; }   ## restore the passing stub

## Integration: the REAL battery must RECORD a failing reboot (number + reason), not have the
## process killed under it. A passing exec stub reaches the user->sysmaint transition, then the
## REAL ws_func_reboot_sysmaint fails (WS stuck 'running'). A pre-fix die exits the subshell
## before the printf -> empty capture, so both assertions fail on old code.
# shellcheck disable=SC2317
ws_func_exec() { return 0; }
# shellcheck disable=SC2317
vm_state() { printf '%s\n' "running"; }
out="$( rc=0; run_release_check_battery ws_func_exec ws_func_reboot_sysmaint '' >/dev/null 2>&1 || rc=$?; printf '%s\n' "rc=${rc}" "${RELEASE_CHECK_FAILED_REASON}" )" || true
assert "failing reboot: battery returns 1 (not a process-exit under the callback)" has 'rc=1' "${out}"
assert "failing reboot: battery records the reboot-failure reason" has 'reboot failed' "${out}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
