#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## restore_fresh verifies the RESTORED snapshot firmware against EXPECT_FIRMWARE, and must FAIL
## CLOSED: a firmware READ error (showvminfo fails) yields an empty fw_actual, which fails the
## EXPECT_FIRMWARE equality check and dies SETUP_RC (INCONCLUSIVE) -- never a mislabeled release
## FAIL on the leak lane. Locks that fail-closed invariant on the ok / read-failure / mismatch
## paths, so a future refactor cannot let a read error leak through as a verdict.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${here}/../../bin/dm-whonix-pair"
[ -x "${tool}" ] || { printf '%s\n' "FAIL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## VBoxManage stub: showvminfo behaves per FW_MODE (ok -> prints firmware=; fail -> exits 1;
## any value -> prints it as the firmware). All other subcommands succeed silently.
cat > "${work}/VBoxManage" <<'STUB'
#!/bin/bash
if [ "$1" = "showvminfo" ]; then
   case "${FW_MODE}" in
      fail) exit 1 ;;
      ok)   printf 'firmware="BIOS"\n'; exit 0 ;;
      *)    printf 'firmware="%s"\n' "${FW_MODE}"; exit 0 ;;
   esac
fi
exit 0
STUB
chmod +x "${work}/VBoxManage"

export VBOXMANAGE="${work}/VBoxManage"
export EXPECT_FIRMWARE="BIOS"
export SNAPSHOT="clean-live"
export PATH="${work}:${PATH}"
# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

## Shadow the poweroff-poll's state probe so the firmware showvminfo is the only VBoxManage read
## FW_MODE drives (the poll otherwise reads showvminfo too and would see the firmware stub).
vm_state() { printf '%s' "poweroff"; }

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: ${1}"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${1}"; fi }

## A matching restored firmware returns cleanly.
rc=0; ( FW_MODE="ok" restore_fresh "ws-vm" ) >/dev/null 2>&1 || rc=$?
check "matching restored firmware (BIOS) -> success (exit 0)" "$([ "${rc}" = "0" ] && printf '%s' "0" || printf '%s' "1")"

## A failed showvminfo is a drive error -> SETUP_RC, never the raw status read as a release FAIL.
rc=0; ( FW_MODE="fail" restore_fresh "ws-vm" ) >/dev/null 2>&1 || rc=$?
check "showvminfo failure -> SETUP_RC(${SETUP_RC}), not a mislabeled FAIL" "$([ "${rc}" = "${SETUP_RC}" ] && printf '%s' "0" || printf '%s' "1")"

## A firmware MISMATCH (restored EFI under a -bios cell) is a provisioning bug -> SETUP_RC.
rc=0; ( FW_MODE="EFI" restore_fresh "ws-vm" ) >/dev/null 2>&1 || rc=$?
check "firmware mismatch (EFI vs BIOS) -> SETUP_RC(${SETUP_RC})" "$([ "${rc}" = "${SETUP_RC}" ] && printf '%s' "0" || printf '%s' "1")"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
