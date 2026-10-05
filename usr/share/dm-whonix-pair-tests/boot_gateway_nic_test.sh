#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## boot_gateway must keep the GW's EXTERNAL NIC DISCONNECTED for the pin-only first boot and
## RECONNECT it for the traced second boot. Rationale: a warmed snapshot autostarts Tor onto its
## OWN (non-pinned) guards the instant it boots; on the shared host wire (a continuous capture
## bracketing the whole run) that PRE-pin egress would read as non-pinned-guard clearnet and
## FALSE-FAIL. Disconnecting the NIC for boot 1 (guestcontrol rides the NIC-independent
## guest-additions channel, so the pin still writes) removes that egress; boot 2 reconnects.
## This asserts the on -> pin -> off ordering around the two boots.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${here}/../../bin/dm-whonix-pair"
[ -x "${tool}" ] || { printf 'FAIL: dm-whonix-pair not found at %s\n' "${tool}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## VBoxManage stub: append every invocation (verbatim args) to an ORDERED log.
cat > "${work}/VBoxManage" <<'STUB'
#!/bin/bash
printf 'VBOXMANAGE %s\n' "$*" >> "${LOG}"
exit 0
STUB
chmod +x "${work}/VBoxManage"
export LOG="${work}/order.log"
printf '' > "${LOG}"

export PATH="${work}:${PATH}"
export VBOXMANAGE="${work}/VBoxManage"
export VBOX_EXEC_LOCAL="${work}/VBoxManage"   ## unused here (gw_pin_guards is stubbed)
# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

## Shadow the heavy boot-dance helpers so only boot_gateway's OWN VBoxManage calls (the NIC +
## trace toggles under test) and the pin marker reach the ordered log.
restore_fresh() { :; }
wait_guestcontrol_ready() { return 0; }
clean_poweroff() { :; }
vm_state() { printf 'poweroff'; }
gw_pin_guards() { printf 'PIN\n' >> "${LOG}"; }

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf 'PASS: %s\n' "$1"; else fail=$(( fail + 1 )); printf 'FAIL: %s\n' "$1"; fi }

boot_gateway >/dev/null 2>&1
log="$(cat -- "${LOG}")"

## Line numbers of the key events in invocation order (disconnect = cableconnected1 off).
disc_line="$(grep -n -- 'cableconnected1 off' <<< "${log}" | head -1 | cut -d: -f1)"
pin_line="$(grep -n -- '^PIN$' <<< "${log}" | head -1 | cut -d: -f1)"
recon_line="$(grep -n -- 'cableconnected1 on' <<< "${log}" | head -1 | cut -d: -f1)"

rc=0; [ -n "${disc_line}" ] || rc=1
check 'boot_gateway disconnects the external NIC (--cableconnected1 off)' "${rc}"
rc=0; [ -n "${recon_line}" ] || rc=1
check 'boot_gateway reconnects the external NIC (--cableconnected1 on)' "${rc}"
rc=0; { [ -n "${disc_line}" ] && [ -n "${pin_line}" ] && [ "${disc_line}" -lt "${pin_line}" ]; } || rc=1
check 'NIC is disconnected BEFORE the guard pin (no pre-pin uplink)' "${rc}"
rc=0; { [ -n "${pin_line}" ] && [ -n "${recon_line}" ] && [ "${pin_line}" -lt "${recon_line}" ]; } || rc=1
check 'NIC is reconnected AFTER the pin (for the traced boot)' "${rc}"
## The reconnect rides the SAME modifyvm that enables the trace (one offline reconfigure).
rc=0; grep --quiet -- 'cableconnected1 on .*nictrace1 on\|nictrace1 on .*cableconnected1 on' <<< "${log}" || rc=1
check 'reconnect + nictrace enablement happen together (single offline modifyvm)' "${rc}"
## Fail-closed: a NIC toggle that cannot run aborts SETUP, never a silent pass.
printf '#!/bin/bash\nexit 1\n' > "${work}/VBoxManage"; chmod +x "${work}/VBoxManage"
rc=0; ( boot_gateway ) >/dev/null 2>&1 || rc=$?
check "a failed NIC toggle -> SETUP_RC(${SETUP_RC}), never a silent pass" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
