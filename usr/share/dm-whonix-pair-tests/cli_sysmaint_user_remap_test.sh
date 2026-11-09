#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The CLI edition has NO user/sysmaint account split (wiki/sysmaint): sysmaint-BOOT elevates the
## `user` account (dsudo -> root); there is no `sysmaint` account to guestcontrol into. So the CLI
## battery's post-reboot checks 2/3 (SESSION=sysmaint, shared with the splitting GUI edition) must
## run as the `user` account, and the reboot callback must wait for the `user` guestcontrol channel.
## Canary: the pre-fix CLI executor passed --role sysmaint straight through, and the reboot waited
## for a sysmaint account that never answers on a CLI image -- so checks 2/3 could never run.
## Drives the REAL dm-whonix-pair ws_func_cli_exec + ws_func_cli_reboot_sysmaint (define-only
## source, no VM/root/network); vbox-exec-local + the VM ops are stubbed to record the role.

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

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
assert() {
   local label="$1"
   shift
   if "$@"; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label}"
   fi
}

work="$(mktemp --directory --tmpdir dm-whonix-pair-cli-remap.XXXXXX)"
# shellcheck disable=SC2317  ## invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Stub vbox-exec-local: record the --role seen, succeed so the executor reports PASS.
rolelog="${work}/roles"
true > "${rolelog}"
stub="${work}/vbox-exec-local"
cat > "${stub}" <<STUB
#!/bin/bash
prev=""
for a in "\$@"; do
   [ "\${prev}" = "--role" ] && printf '%s\n' "\${a}" >> "${rolelog}"
   prev="\${a}"
done
exit 0
STUB
chmod +x "${stub}"

## Globals the CLI executor/reboot callback read.
VBOX_EXEC_LOCAL="${stub}"
me='cli-remap-test'
ws='Whonix-Workstation-CLI'
vm="${ws}"
check_log=''
FAIL_RC=1

## --- ws_func_cli_exec: SESSION=sysmaint must reach vbox-exec-local as --role user ---
true > "${rolelog}"
ws_func_cli_exec 2 sysmaint 'grep -q boot-role=sysmaint /proc/cmdline' 60 >/dev/null 2>&1
role_check2="$(tail -n1 "${rolelog}" 2>/dev/null || true)"
assert "check 2 (SESSION=sysmaint) runs as --role user on the CLI edition" \
   [ "${role_check2}" = user ]

true > "${rolelog}"
ws_func_cli_exec 3 sysmaint 'upgrade-nonroot --yes' 60 >/dev/null 2>&1
role_check3="$(tail -n1 "${rolelog}" 2>/dev/null || true)"
assert "check 3 (SESSION=sysmaint) runs as --role user on the CLI edition" \
   [ "${role_check3}" = user ]

## --- a genuine user-session check (SESSION=user) stays --role user ---
true > "${rolelog}"
ws_func_cli_exec 1 user '! grep -q boot-role=sysmaint /proc/cmdline' 60 >/dev/null 2>&1
role_check1="$(tail -n1 "${rolelog}" 2>/dev/null || true)"
assert "check 1 (SESSION=user) stays --role user" \
   [ "${role_check1}" = user ]

## --- ws_func_cli_reboot_sysmaint must wait for the `user` guestcontrol channel ---
waitlog="${work}/wait-role"
true > "${waitlog}"
## Stub the VM-op dependencies so only the readiness-role assertion is exercised.
clean_poweroff() { :; }
wait_vm_off() { return 0; }
select_installed_sysmaint() { :; }
wait_guestcontrol_ready() {
   printf '%s\n' "$1" >> "${waitlog}"
   return 0
}
VBOXMANAGE='true'
ws_func_cli_reboot_sysmaint >/dev/null 2>&1
wait_role="$(tail -n1 "${waitlog}" 2>/dev/null || true)"
assert "reboot callback waits for the user guestcontrol channel (no sysmaint account)" \
   [ "${wait_role}" = user ]

printf '%s\n' "cli_sysmaint_user_remap_test: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
