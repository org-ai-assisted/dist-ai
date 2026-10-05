#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-whonix-pair pure-logic unit tests (no VM): the fail-closed GW-trace canary (a leak MUST
## turn it red, a blind/missing capture MUST NOT read as a no-leak), the battery run-command
## assembly (one short command on /mnt/shared under plain sudo, no inline script), and the
## systemcheck positive control (both Tor ports, sysmaint, no sudo, fail-closed). Sources the real
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

## Stub tcpdump, five filter kinds (canary runs the denylist, the Tor-guard read, the pc read, and
## the allowlist read), classified by filter text (most specific first):
##   - ALLOWLIST (deny-by-default) -> has the unique "169.254" infra term -> emit STUB_DIR/allow.
##   - DENYLIST (watched targets)  -> has "dst host", no 169.254 -> emit STUB_DIR/hits.
##   - POSITIVE CONTROL (reserved guard ORPort) -> has "tcp port" -> emit STUB_DIR/pc.
##   - TOR GUARD (entry guards) -> has "host " -> emit STUB_DIR/tor.
##   - full read (no filter) -> emit STUB_DIR/total.
## A missing count file reads as 0. Counts come from FILES (not subshell env) so canary can run in
## a die-catching subshell cleanly.
cat > "${work}/tcpdump" <<'STUB'
#!/bin/bash
mode=full
for a in "$@"; do case "$a" in *"169.254"*) mode=allow; printf '%s' "$a" > "${STUB_DIR}/last_filter_allow"; break ;; esac; done
if [ "${mode}" = full ]; then
   for a in "$@"; do case "$a" in *"dst host"*) mode=deny; printf '%s' "$a" > "${STUB_DIR}/last_filter"; break ;; esac; done
fi
if [ "${mode}" = full ]; then
   for a in "$@"; do case "$a" in *"tcp port"*) mode=pc; printf '%s' "$a" > "${STUB_DIR}/last_filter_pc"; break ;; esac; done
fi
if [ "${mode}" = full ]; then
   for a in "$@"; do case "$a" in *"host "*) mode=tor; printf '%s' "$a" > "${STUB_DIR}/last_filter_tor"; break ;; esac; done
fi
case "${mode}" in
   allow) f="${STUB_DIR}/allow" ;;
   deny)  f="${STUB_DIR}/hits" ;;
   tor)   f="${STUB_DIR}/tor" ;;
   pc)    f="${STUB_DIR}/pc" ;;
   *)     f="${STUB_DIR}/total" ;;
esac
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

set_counts() { printf '%s\n' "$1" > "${work}/total"; printf '%s\n' "$2" > "${work}/hits"; printf '20\n' > "${work}/tor"; printf '1\n' > "${work}/pc"; }

set_counts 7 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check 'canary clean (traffic present, 0 hits to any probe target) -> PASS' "${rc}"

set_counts 7 3
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "canary CATCHES a leak (a probe target on the wire) -> FAIL_RC(${FAIL_RC}), a proven leak" "$([ "${rc}" = "${FAIL_RC}" ] && printf 0 || printf 1)"

set_counts 0 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "canary blind capture (pcap empty of traffic) -> SETUP_RC(${SETUP_RC}), inconclusive not a leak" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

nictrace_pcap="${work}/does-not-exist"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "canary missing pcap -> SETUP_RC(${SETUP_RC}), inconclusive not a leak (fail-closed, no false no-leak)" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"
nictrace_pcap="${work}/pcap"

## --- ws_battery: one short command on /mnt/shared, no inline script -------------------------
out="$(ws_battery '--probe tor-confirm')"
rc=0; has "sudo python3 -Bsu ${GUEST_SHARE_MOUNT}/anon-leak-test --probe tor-confirm --json" "${out}" || rc=$?
check 'ws_battery: runs the battery on /mnt/shared under plain sudo (no copyto, no inline script)' "${rc}"
rc=0; has "printf " "${out}" && rc=1 || rc=0
check 'ws_battery: no piped password (sysmaint passwordless sudo; no hardcoded secret)' "${rc}"

## --- ws_tor_confirm: systemcheck positive control, BOTH Tor ports, sysmaint, no sudo ---------
out="$(ws_tor_confirm)"
rc=0; has "systemcheck --cli --leak-tests --function check_tor_socks_port" "${out}" || rc=1
check 'ws_tor_confirm: confirms Tor SocksPort via the AppArmor-confined systemcheck' "${rc}"
rc=0; has "systemcheck --cli --leak-tests --function check_tor_trans_port" "${out}" || rc=1
check 'ws_tor_confirm: confirms Tor TransPort too (BOTH ports -- not the SocksPort-or-TransPort OR)' "${rc}"
rc=0; has "--role sysmaint" "${out}" || rc=1
check 'ws_tor_confirm: runs systemcheck in the sysmaint session (the booted role)' "${rc}"
rc=0; has "sudo " "${out}" && rc=1 || rc=0
check 'ws_tor_confirm: NO sudo (systemcheck runs unprivileged; single --function skips root_check)' "${rc}"

## Fail-closed: if EITHER port control cannot confirm Tor, the positive control MUST fail -- a
## dead/half-broken link must never read as a pass (no false green).
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
exit 1
STUB
chmod +x "${work}/vbe"
rc=0; ws_tor_confirm >/dev/null 2>&1 || rc=$?
check_fail 'ws_tor_confirm fails-closed (nonzero) when a port control cannot confirm Tor' "${rc}"
## restore the echoing stub for anything after
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
printf '%s\n' "$*"
STUB
chmod +x "${work}/vbe"

## --- canary watch list: IPv6 targets are watched too ---------------------------------------
set_counts 5 0
( canary_gateway_pcap ) >/dev/null 2>&1 || true
rc=0; { grep --quiet "${CLEARNET_IPV6}" "${work}/last_filter" && grep --quiet "${CRAFT_SRC6}" "${work}/last_filter"; } || rc=1
check 'canary watches the IPv6 target + forged v6 source (dst host filter)' "${rc}"
rc=0; { grep --quiet "${CRAFT_SRC}" "${work}/last_filter" && grep --quiet "${CLEARNET_NTP}" "${work}/last_filter"; } || rc=1
check 'canary still watches the IPv4 targets' "${rc}"

## --- gw_stop_tor: arms the killswitch from the GW USER session, fail-closed -----------------
rc=0; out="$(gw_stop_tor 2>&1)" || rc=$?
check 'gw_stop_tor succeeds when guestcontrol does' "${rc}"
rc=0; has 'leaprun sudo && sudo --non-interactive systemctl stop tor@default.service' "${out}" || rc=1
check 'gw_stop_tor stops Tor via leaprun sudo (so the GW stays in its user session, forwarding intact)' "${rc}"
rc=0; has '! sudo --non-interactive systemctl is-active --quiet tor@default.service' "${out}" || rc=1
check 'gw_stop_tor POSITIVELY confirms Tor is inactive (fail-closed, not a probe-exit guess)' "${rc}"
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
rc=0; out="$(gw_start_tor 2>&1)" || rc=$?
check 'gw_start_tor succeeds when guestcontrol does' "${rc}"
rc=0; has 'leaprun sudo && sudo --non-interactive systemctl start tor@default.service' "${out}" || rc=1
check 'gw_start_tor restarts Tor (killswitch recovery) via leaprun sudo' "${rc}"
rc=0; has '--role user' "${out}" || rc=1
check 'gw_start_tor runs in the GW USER session' "${rc}"

## --- ws_flush_firewall: remove the WS firewall so leaks reach the GW (the real boundary) ------
rc=0; out="$(ws_flush_firewall 2>&1)" || rc=$?
check 'ws_flush_firewall succeeds when guestcontrol does' "${rc}"
rc=0; has 'nft flush ruleset' "${out}" || rc=1
check 'ws_flush_firewall flushes the WS nftables ruleset' "${rc}"
rc=0; has '--role sysmaint' "${out}" || rc=1
check 'ws_flush_firewall runs as sysmaint (passwordless sudo)' "${rc}"
rc=0; has 'nft list ruleset' "${out}" || rc=1
check 'ws_flush_firewall CONFIRMS the ruleset is empty (fail-closed proof)' "${rc}"
## Fail-closed: a WS whose firewall cannot be flushed could mask a leak -> SETUP, never a pass.
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
exit 1
STUB
chmod +x "${work}/vbe"
rc=0; ( ws_flush_firewall ) >/dev/null 2>&1 || rc=$?
check_fail 'ws_flush_firewall fails-closed (nonzero) when the flush cannot run' "${rc}"
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
printf '%s\n' "$*"
STUB
chmod +x "${work}/vbe"

## --- gw_positive_control: emit a known-good packet to the RESERVED guard's ORPort as clearnet ---
out="$(gw_positive_control 2>&1)"
rc=0; has '-u clearnet' "${out}" || rc=1
check 'gw_positive_control emits as the clearnet user (allowed direct clearnet TCP on the GW)' "${rc}"
rc=0; has "/dev/tcp/${GUARD_PC_IP4}/${GUARD_PC_PORT}" "${out}" || rc=1
check 'gw_positive_control dials the RESERVED guard real ORPort (allowlisted, legitimate, no leak)' "${rc}"
rc=0; for g in "${GUARD_PIN_IPS4[@]}"; do has "/dev/tcp/${g}/" "${out}" && rc=1; done
check 'gw_positive_control does NOT dial an entry guard (separation: pc traffic is its own count)' "${rc}"
rc=0; has '--role user' "${out}" || rc=1
check 'gw_positive_control runs in the GW USER session' "${rc}"

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

## --- SETUP vs LEAK: a provisioning/infra failure exits SETUP_RC(2), never FAIL_RC(5) -------
## A false leak verdict (pass=false) on a provisioning gap is the bug this guards. A capable
## VBoxManage stub drives the paths without a real VM: showvminfo reports ${VBM_STATE};
## `snapshot <vm> restore <snap>` exits ${VBM_SNAP_RC}.
cat > "${work}/vbm2" <<'STUB'
#!/bin/bash
case "$1" in
   showvminfo) printf 'VMState="%s"\n' "${VBM_STATE:-poweroff}" ;;
   snapshot) [ "$3" = 'restore' ] && exit "${VBM_SNAP_RC:-0}"; exit 0 ;;
   *) exit 0 ;;
esac
STUB
chmod +x "${work}/vbm2"
VBOXMANAGE="${work}/vbm2"
export VBM_STATE VBM_SNAP_RC

## restore_fresh: a missing clean-live snapshot is a PROVISIONING failure -> SETUP_RC, not a
## leak. Canary: old code died FAIL_RC(5), so this rc check fails on it.
VBM_STATE='poweroff'; VBM_SNAP_RC=1
rc=0; ( restore_fresh 'X' ) >/dev/null 2>&1 || rc=$?
check "restore_fresh: snapshot-restore failure exits SETUP_RC(${SETUP_RC}), not a leak verdict" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## assert_vm_running: a crashed/aborted VM is an infra failure -> SETUP_RC, not a leak.
VBM_STATE='aborted'; VBM_SNAP_RC=0
rc=0; ( assert_vm_running 'X' 'setup-vs-leak test' ) >/dev/null 2>&1 || rc=$?
check "assert_vm_running: a crashed VM exits SETUP_RC(${SETUP_RC}), not a leak verdict" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

unset VBM_STATE VBM_SNAP_RC
VBOXMANAGE="${work}/VBoxManage"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
