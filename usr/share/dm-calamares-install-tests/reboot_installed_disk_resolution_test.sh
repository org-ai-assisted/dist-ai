#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## reboot_installed (dm-calamares-install) selects SYSMAINT OFFLINE via the disk path. A
## --reinstall run without --disk leaves ${disk} EMPTY, and the offline selector/privleap
## action reject an empty disk -- so reboot_installed MUST resolve the disk from the VM when
## ${disk} is empty (OCR is retired; there is no no-disk fallback). This drives the REAL
## reboot_installed (sourced define-only) with recording stubs and asserts:
##   * empty disk  -> installed_disk_path is consulted and its result reaches the selector;
##   * explicit disk -> that disk reaches the selector, installed_disk_path is NOT consulted.
## No VM, no root, no network. Canary: RED on the pre-fix code (empty disk reaches the selector).

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
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

select_log="${work}/select.disk"
resolve_log="${work}/resolve.called"

## Globals the sourced subject reads; seeded here (shellcheck cannot see across the source).
# shellcheck disable=SC2034
vm='testvm'
# shellcheck disable=SC2034
passphrase='irrelevant'
# shellcheck disable=SC2034
passphrase_file="${work}/pf"
printf '%s' 'irrelevant' > "${passphrase_file}"
# shellcheck disable=SC2034
VBOXMANAGE='true'
# shellcheck disable=SC2034
GUESTCTL='true'

# shellcheck source=../../bin/dm-calamares-install
source "${subject}"

## Neutralize every VM/GUI side effect of reboot_installed; capture only the two under test.
# shellcheck disable=SC2317
sleep() { :; }
# shellcheck disable=SC2317
cb_reset_nvram() { :; }
# shellcheck disable=SC2317
installed_disk_path() { printf '%s\n' "${resolve_log}" >> "${resolve_log}"; printf '%s\n' '/resolved/from/vm.vdi'; }
# shellcheck disable=SC2317
select_installed_sysmaint_offline() { printf '%s' "$1" > "${select_log}"; }
# shellcheck disable=SC2317
start_vm_frontend() { :; }
# shellcheck disable=SC2317
gui_wait_for() { :; }
# shellcheck disable=SC2317
gui_scan() { :; }
# shellcheck disable=SC2317
wait_ready() { :; }
# shellcheck disable=SC2317
open_terminal() { :; }
# shellcheck disable=SC2317
story_snap() { :; }
# shellcheck disable=SC2317
redact_boot_tokens() { :; }

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

## 1. --reinstall without --disk: ${disk} empty -> resolve from the VM, feed the selector.
disk=""
safe-rm --force -- "${select_log}" "${resolve_log}"
reboot_installed sysmaint
check "empty disk: installed_disk_path consulted" "$([ -e "${resolve_log}" ] && printf '%s' yes || printf '%s' no)" 'yes'
check "empty disk: selector receives the RESOLVED disk" "$(cat -- "${select_log}" 2>/dev/null)" '/resolved/from/vm.vdi'

## 2. explicit --disk: that path reaches the selector, no VM resolution needed.
disk='/explicit/install.vdi'
safe-rm --force -- "${select_log}" "${resolve_log}"
reboot_installed sysmaint
check "explicit disk: selector receives the given disk" "$(cat -- "${select_log}" 2>/dev/null)" '/explicit/install.vdi'
check "explicit disk: installed_disk_path NOT consulted" "$([ -e "${resolve_log}" ] && printf '%s' yes || printf '%s' no)" 'no'

## 3. user role never selects SYSMAINT at all.
disk=""
safe-rm --force -- "${select_log}" "${resolve_log}"
reboot_installed user
check "user role: selector NOT called" "$([ -e "${select_log}" ] && printf '%s' yes || printf '%s' no)" 'no'

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ]
