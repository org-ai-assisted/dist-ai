#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-release-test's --coreboot-rom pass-through to dm-calamares-install. The
## coreboot ROM swap is the SAME default-EFI install lane with only the firmware changed, so the
## release lane must (a) forward --coreboot-rom and (b) point the install run at the patched
## CorebootRom-aware VBoxManage. rt_resolve_coreboot is the pure decision: it builds cb_env (the
## env prefix for the sudo'd install: patched VBOXMANAGE + its LD_LIBRARY_PATH) and cb_arg (the
## --coreboot-rom flag), prefers DASHARO_VBOX_BIN, falls back to a non-default VBOXMANAGE, and
## FAILS CLOSED when neither is set (the stock VBoxManage silently ignores CorebootRom -> a wrong
## subject). Drives the REAL dm-release-test (sourced). No VM, no root, no network.
##
## CANARY: on the pre-coreboot code --coreboot-rom is an unknown option and rt_resolve_coreboot
## does not exist.

## coreboot_rom/DASHARO_VBOX_BIN/VBOXMANAGE are consumed by the sourced rt_resolve_coreboot via
## dynamic scope, so shellcheck (which cannot see across the source) flags them unused (SC2034).
## The wiring-canary greps intentionally search for literal '${...}' strings in the script (SC2016).
# shellcheck disable=SC2034,SC2016
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not found at ${subject}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

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
in_array() {
   ## in_array NEEDLE "${arr[@]}"
   local needle="$1"
   shift
   local item
   for item in "$@"; do
      [ "${item}" = "${needle}" ] && return 0
   done
   return 1
}

# shellcheck disable=SC1090
source "${subject}"

cb_rom="/opt/coreboot/cb-uefi-gfx.rom"
cb_env=()
cb_arg=()

## --- no --coreboot-rom: a no-op (both arrays empty) -> the normal lanes are unchanged ---------
coreboot_rom=""
DASHARO_VBOX_BIN=""
VBOXMANAGE="VBoxManage"
rt_resolve_coreboot
got=0; { [ "${#cb_env[@]}" -eq 0 ] && [ "${#cb_arg[@]}" -eq 0 ]; } || got=1
check "rt_resolve_coreboot is a no-op without --coreboot-rom" "${got}"

## --- DASHARO_VBOX_BIN (a bin dir with VBoxManage) is the preferred selector -------------------
vbin="${work}/vbin"
mkdir -p -- "${vbin}"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${vbin}/VBoxManage"
chmod +x -- "${vbin}/VBoxManage"
coreboot_rom="${cb_rom}"
DASHARO_VBOX_BIN="${vbin}"
VBOXMANAGE="VBoxManage"
rt_resolve_coreboot
got=0; in_array "--coreboot-rom" "${cb_arg[@]}" && in_array "${cb_rom}" "${cb_arg[@]}" || got=1
check "rt_resolve_coreboot forwards --coreboot-rom + the ROM path" "${got}"
got=0; in_array "VBOXMANAGE=${vbin}/VBoxManage" "${cb_env[@]}" || got=1
check "rt_resolve_coreboot points VBOXMANAGE at the patched build in DASHARO_VBOX_BIN" "${got}"
## A source-built VBoxManage resolves its shared libs from its own bin dir.
got=0; in_array "LD_LIBRARY_PATH=${vbin}" "${cb_env[@]}" || got=1
check "rt_resolve_coreboot adds the patched bin dir to LD_LIBRARY_PATH" "${got}"

## --- fallback: a non-default VBOXMANAGE (no DASHARO_VBOX_BIN) is honored -----------------------
coreboot_rom="${cb_rom}"
DASHARO_VBOX_BIN=""
VBOXMANAGE="/opt/patched/VBoxManage"
rt_resolve_coreboot
got=0; in_array "VBOXMANAGE=/opt/patched/VBoxManage" "${cb_env[@]}" || got=1
check "rt_resolve_coreboot falls back to a non-default VBOXMANAGE" "${got}"

## --- fail CLOSED: --coreboot-rom with NO patched VBoxManage resolvable must die ----------------
got=0
if ( coreboot_rom="${cb_rom}"; DASHARO_VBOX_BIN=""; VBOXMANAGE="VBoxManage"; cb_env=(); cb_arg=(); rt_resolve_coreboot ) >/dev/null 2>&1; then
   got=1
fi
check "rt_resolve_coreboot fails closed when no patched VBoxManage is resolvable" "${got}"

## --- the install invocation actually SPLICES cb_env + cb_arg (wiring canary) ------------------
## Static assert on the real script: the sudo'd dm-calamares-install call must carry the resolved
## patched-VBoxManage env and the --coreboot-rom flag, else the resolver's output never reaches
## the install (the guards above would pass while the forward silently did nothing).
got=0; grep --fixed-strings --quiet '"${rt_session_env[@]}" "${cb_env[@]}" "${DM_CALAMARES_INSTALL}"' "${subject}" || got=1
check "install invocation splices cb_env into the env prefix" "${got}"
got=0; grep --fixed-strings --quiet '"${cb_arg[@]}" "${checks_arg[@]}"' "${subject}" || got=1
check "install invocation passes cb_arg (--coreboot-rom)" "${got}"

## --- --coreboot-rom is a real CLI option (rejects a missing/empty value) ----------------------
got=0; if "${subject}" kicksecure lxqt --coreboot-rom 2>/dev/null; then got=1; fi
check "--coreboot-rom requires a value" "${got}"
got=0; if "${subject}" kicksecure lxqt --coreboot-rom '' --dry-run 2>/dev/null; then got=1; fi
check "--coreboot-rom rejects an empty value" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
