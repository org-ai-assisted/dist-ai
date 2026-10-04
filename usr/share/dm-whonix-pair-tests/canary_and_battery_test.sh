#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-whonix-pair pure-logic unit tests (no VM): the fail-closed GW-trace canary (a leak MUST
## turn it red, a blind/missing capture MUST NOT read as a no-leak) and the battery run-command
## assembly (one short command on /mnt/shared under sudo -S, no inline script). Sources the real
## dm-whonix-pair (its source-guard keeps main() from running) with stubbed tcpdump/vbox-exec-local.

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

## Stub tcpdump: a "dst host" filter arg -> emit as many lines as STUB_DIR/hits; else (full
## read) STUB_DIR/total. Counts come from FILES (not subshell env) so canary can run in a
## die-catching subshell with no lost-subshell-var warning.
cat > "${work}/tcpdump" <<'STUB'
#!/bin/bash
has_filter=0
for a in "$@"; do case "$a" in *"dst host"*) has_filter=1; printf '%s' "$a" > "${STUB_DIR}/last_filter" ;; esac; done
f="${STUB_DIR}/total"
[ "${has_filter}" = 1 ] && f="${STUB_DIR}/hits"
n="$(cat -- "${f}" 2>/dev/null || printf 0)"
i=0
while [ "${i}" -lt "${n}" ]; do
   printf 'pkt\n'
   i=$(( i + 1 ))
done
STUB
chmod +x "${work}/tcpdump"
export STUB_DIR="${work}"

## Stub vbox-exec-local: echo its args so ws_battery's / gw_stop_tor's assembled --cmd is captured.
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
printf '%s\n' "$*"
STUB
chmod +x "${work}/vbe"

## Stub sleep: the killswitch retry/settle sleeps must not slow the unit test.
cat > "${work}/sleep" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x "${work}/sleep"

## Stub VBoxManage: on_exit powers off VMs / toggles the NIC trace -- no real VBox here.
cat > "${work}/VBoxManage" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x "${work}/VBoxManage"

## Override the tool's externals BEFORE sourcing; the source-guard keeps main() from running.
export PATH="${work}:${PATH}"   ## picks up the stub sleep (gw_stop_tor calls bare `sleep`)
export TCPDUMP="${work}/tcpdump"
export VBOX_EXEC_LOCAL="${work}/vbe"
export VBOXMANAGE="${work}/VBoxManage"
# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf 'PASS: %s\n' "$1"; else fail=$(( fail + 1 )); printf 'FAIL: %s\n' "$1"; fi }
check_fail() { if [ "$2" -ne 0 ]; then pass=$(( pass + 1 )); printf 'PASS: %s\n' "$1"; else fail=$(( fail + 1 )); printf 'FAIL: %s (rc=0, wanted nonzero)\n' "$1"; fi }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## --- canary_gateway_pcap: fail-closed ------------------------------------------------------
nictrace_pcap="${work}/pcap"
printf 'x\n' > "${nictrace_pcap}"   ## non-empty so the [ -s ] guard passes

set_counts() { printf '%s\n' "$1" > "${work}/total"; printf '%s\n' "$2" > "${work}/hits"; }

set_counts 7 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check 'canary clean (traffic present, 0 hits to any probe target) -> PASS' "${rc}"

set_counts 7 3
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check_fail 'canary CATCHES a leak (a probe target on the wire) -> nonzero (NO silent green)' "${rc}"

set_counts 0 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check_fail 'canary blind capture (pcap empty of traffic) -> nonzero (not a false no-leak)' "${rc}"

nictrace_pcap="${work}/does-not-exist"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check_fail 'canary missing pcap -> nonzero (fail-closed)' "${rc}"
nictrace_pcap="${work}/pcap"

## --- ws_battery: one short command on /mnt/shared, no inline script -------------------------
out="$(ws_battery '--probe tor-confirm')"
rc=0; has "sudo python3 -Bsu ${GUEST_SHARE_MOUNT}/anon-leak-test --probe tor-confirm --json" "${out}" || rc=$?
check 'ws_battery: runs the battery on /mnt/shared under plain sudo (no copyto, no inline script)' "${rc}"
rc=0; has "printf " "${out}" && rc=1 || rc=0
check 'ws_battery: no piped password (sysmaint passwordless sudo; no hardcoded secret)' "${rc}"

## --- canary watch list: IPv6 targets are watched too ---------------------------------------
set_counts 5 0
( canary_gateway_pcap ) >/dev/null 2>&1 || true
rc=0; { grep --quiet "${CLEARNET_IPV6}" "${work}/last_filter" && grep --quiet "${CRAFT_SRC6}" "${work}/last_filter"; } || rc=1
check 'canary watches the IPv6 target + forged v6 source (dst host filter)' "${rc}"
rc=0; { grep --quiet "${CRAFT_SRC}" "${work}/last_filter" && grep --quiet "${CLEARNET_NTP}" "${work}/last_filter"; } || rc=1
check 'canary still watches the IPv4 targets' "${rc}"

## --- gw_stop_tor: arms the killswitch from the GW USER session, fail-closed -----------------
out="$(gw_stop_tor 2>&1)"; rc=$?
check 'gw_stop_tor succeeds when guestcontrol does' "${rc}"
rc=0; has 'leaprun sudo && sudo --non-interactive systemctl stop tor@default.service' "${out}" || rc=1
check 'gw_stop_tor stops Tor via leaprun sudo (so the GW stays in its user session, forwarding intact)' "${rc}"
rc=0; has '--role user' "${out}" || rc=1
check 'gw_stop_tor runs in the GW USER session (not sysmaint)' "${rc}"

## Fail-closed: a GW whose Tor cannot be stopped makes the killswitch untestable -> SETUP (2),
## never a silent pass.
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
exit 1
STUB
chmod +x "${work}/vbe"
rc=0; ( gw_stop_tor ) >/dev/null 2>&1 || rc=$?
check_fail 'gw_stop_tor fails-closed (nonzero) when the GW Tor-stop cannot run' "${rc}"
## restore the succeeding stub for anything after
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
printf '%s\n' "$*"
STUB
chmod +x "${work}/vbe"

## --- gw_start_tor: recovery restarts Tor (same user-session path), so the STOP brackets ---
out="$(gw_start_tor 2>&1)"; rc=$?
check 'gw_start_tor succeeds when guestcontrol does' "${rc}"
rc=0; has 'leaprun sudo && sudo --non-interactive systemctl start tor@default.service' "${out}" || rc=1
check 'gw_start_tor restarts Tor (killswitch recovery) via leaprun sudo' "${rc}"
rc=0; has '--role user' "${out}" || rc=1
check 'gw_start_tor runs in the GW USER session' "${rc}"

## --- on_exit: PRESERVE the GW capture on a leak, drop it on a clean PASS --------------------
export LEAK_ARTIFACT_DIR="${work}"
# shellcheck disable=SC2034  ## consumed by the sourced dm-whonix-pair on_exit (dynamic scope)
ws_started='false'
# shellcheck disable=SC2034  ## consumed by the sourced dm-whonix-pair on_exit
gw_started='false'
# shellcheck disable=SC2034  ## consumed by the sourced dm-whonix-pair on_exit
share_dir=''

printf 'PCAPDATA\n' > "${work}/trace.pcap"
nictrace_pcap="${work}/trace.pcap"
## Run on_exit with $?=FAIL_RC without toggling errexit: the failing subshell feeds
## its status into on_exit via `||` (bash gives B the status of A in `A || B`), and a
## trailing `|| true` absorbs on_exit's own return so errexit never trips.
( exit "${FAIL_RC}" ) || on_exit >/dev/null 2>&1 || true
rc=0; ls "${work}"/whonix-pair-leak-*.pcap >/dev/null 2>&1 || rc=1
check 'on_exit PRESERVES the GW capture on a non-clean (leak) exit (evidence kept)' "${rc}"
rc=0; ls "${work}"/whonix-pair-leak-*.txt >/dev/null 2>&1 || rc=1
check 'on_exit writes a human-readable decode alongside the preserved pcap' "${rc}"

safe-rm -f -- "${work}"/whonix-pair-leak-*.pcap "${work}"/whonix-pair-leak-*.txt 2>/dev/null || true
printf 'PCAPDATA\n' > "${work}/trace.pcap"
nictrace_pcap="${work}/trace.pcap"
## Clean PASS: set $?=PASS_RC, then run on_exit (its own return absorbed by `|| true`).
## No errexit toggle, and no `A && B || C` (SC2015) ambiguity.
( exit "${PASS_RC}" )
on_exit >/dev/null 2>&1 || true
rc=0; ls "${work}"/whonix-pair-leak-*.pcap >/dev/null 2>&1 && rc=1
check 'on_exit does NOT preserve on a clean PASS (artifact only on failure)' "${rc}"
rc=0; [ -e "${work}/trace.pcap" ] && rc=1
check 'on_exit removes the working pcap on a clean PASS' "${rc}"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
