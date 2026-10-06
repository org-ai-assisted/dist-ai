#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-whonix-pair pure-logic unit tests (no VM) for the deny-by-default GW-NIC ALLOWLIST: the ONLY
## clearnet dsts permitted leaving the GW are CURRENT Tor relays/authorities (from the GW's own
## cached consensus) + link infra; ANY other clearnet dst is a LEAK (Tor-only by default, no
## host-DNS carve-out). A Tor relay -- a pinned guard, another guard, or a V2Dir/directory relay --
## is not a leak (EntryNodes/StrictNodes pins circuit ENTRY, not directory connections). Also:
## genuine Tor guard traffic and the reserved-guard POSITIVE CONTROL are counted SEPARATELY; the
## guard-pin assembly (gw_pin_guards); and the --print-guards / --print-pc-filter / --print-allow-
## filter single sources. Sources the real dm-whonix-pair with a stubbed tcpdump/vbox-exec-local.

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

## Stub tcpdump. The canary issues these read kinds; classify by filter text (most specific first):
##   infra-exclude : has "169.254" -> emit the pcap's clearnet DST LINES (STUB_DIR/dsts), the input
##                   to the consensus-relay set-diff (deny-by-default: anything not a relay/infra).
##   pc    : has "tcp dst port" -> STUB_DIR/pc  (reserved guard on its ORPort = positive control)
##   deny  : has "dst host"     -> STUB_DIR/hits (fixed watched-target denylist)
##   tor   : has "host "        -> STUB_DIR/tor  (entry guards = genuine Tor guard traffic)
##   full  : no filter          -> STUB_DIR/total
## infra is matched FIRST (its DHCP term also contains "dst host 255.255.255.255"); pc before deny
## (pc_bpf also contains "dst host"). A missing count file reads as 0.
cat > "${work}/tcpdump" <<'STUB'
#!/bin/bash
mode=full
for a in "$@"; do case "$a" in *"169.254"*)      mode=infra; break ;; esac; done
if [ "${mode}" = full ]; then for a in "$@"; do case "$a" in *"tcp dst port"*) mode=pc;   printf '%s' "$a" > "${STUB_DIR}/last_filter_pc"; break ;; esac; done; fi
if [ "${mode}" = full ]; then for a in "$@"; do case "$a" in *"dst host"*)     mode=deny; printf '%s' "$a" > "${STUB_DIR}/last_filter"; break ;; esac; done; fi
if [ "${mode}" = full ]; then for a in "$@"; do case "$a" in *"host "*)        mode=tor;  printf '%s' "$a" > "${STUB_DIR}/last_filter_tor"; break ;; esac; done; fi
## A FILTERED run exits nonzero when STUB_DIR/filter_fail exists -- models a non-compiling BPF,
## which must be SETUP, not a clean 0.
if [ "${mode}" != full ] && [ -e "${STUB_DIR}/filter_fail" ]; then exit 1; fi
if [ "${mode}" = infra ]; then cat -- "${STUB_DIR}/dsts" 2>/dev/null; exit 0; fi
case "${mode}" in
   full) f="${STUB_DIR}/total" ;;
   deny) f="${STUB_DIR}/hits" ;;
   tor)  f="${STUB_DIR}/tor" ;;
   pc)   f="${STUB_DIR}/pc" ;;
esac
n="$(cat -- "${f}" 2>/dev/null || printf 0)"
i=0
while [ "${i}" -lt "${n}" ]; do printf 'pkt\n'; i=$(( i + 1 )); done
STUB
chmod +x "${work}/tcpdump"
export STUB_DIR="${work}"

## Stub vbox-exec-local, faithful to privleap: `leaprun sudo` GRANTS sudo, then only a
## following `sudo --non-interactive <cmd>` runs as root -- `leaprun sudo <cmd>` does NOT run
## <cmd> (privleap ignores trailing argv), so a 700 consensus file stays unreadable. Hence the
## relay set is emitted ONLY for a real root read; a mis-built `leaprun sudo grep` reads nothing
## (live SETUP). Other calls echo args so gw_pin_guards's assembled --cmd is captured.
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
case "$*" in
   *"sudo --non-interactive grep"*cached-microdesc-consensus*) cat -- "${STUB_DIR}/relay_ips" 2>/dev/null ;;
   *cached-microdesc-consensus*) : ;;
   *) printf '%s\n' "$*" ;;
esac
STUB
chmod +x "${work}/vbe"

printf '#!/bin/bash\nexit 0\n' > "${work}/VBoxManage"; chmod +x "${work}/VBoxManage"
printf '#!/bin/bash\nexit 0\n' > "${work}/sleep";       chmod +x "${work}/sleep"

export PATH="${work}:${PATH}"
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

nictrace_pcap="${work}/pcap"
printf 'x\n' > "${nictrace_pcap}"   ## non-empty so the [ -s ] guard passes
## The canary reads the consensus relay set from the gw_relay_cache file that main() populates
## (while the GW is up) BEFORE the poweroff; point it at the test's relay-set fixture.
gw_relay_cache="${work}/relay_ips"

## The GW consensus relay set the canary classifies against: the pinned guards + the reserved pc
## guard (all real relays) + an extra unrelated V2Dir relay, so a DIRECTORY connection to a
## non-guard relay is NOT a leak.
RELAY_DIR='147.135.129.138'
set_relay_set() { printf '%s\n' "${GUARD_PIN_IPS4[@]}" "${GUARD_PC_IP4}" "${RELAY_DIR}" > "${work}/relay_ips"; }

## total, denylist-hits; liveness defaults tor=20 (>= GUARD_MIN_PKTS), pc=1 (>= 1); relay set + dst
## lines default to clean (every dst is a relay). A case overrides ${work}/dsts to inject a leak.
set_counts() {
   printf '%s\n' "$1" > "${work}/total"
   printf '%s\n' "$2" > "${work}/hits"
   printf '20\n' > "${work}/tor"
   printf '1\n'  > "${work}/pc"
   set_relay_set
   { printf 'IP 10.0.2.15.5 > %s.9001:\n' "${GUARD_PIN_IPS4[0]}"
     printf 'IP 10.0.2.15.6 > %s.9200:\n' "${RELAY_DIR}"; } > "${work}/dsts"
}

## --- allowlist verdicts --------------------------------------------------------------------
## Clean: every clearnet dst is a current Tor relay (a guard AND a non-guard V2Dir/directory
## relay) -> PASS. The directory connection to a non-guard relay must NOT be a leak.
set_counts 10 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check 'allowlist clean (every dst is a Tor relay incl a non-guard dir relay) -> PASS' "${rc}"

## Injected NON-relay clearnet dst (e.g. host-DNS 10.0.2.3 / a random clearnet host) -> a proven
## LEAK (FAIL_RC), even with NO watched denylist target. This is the gap the allowlist closes.
set_counts 10 0
printf 'IP 10.0.2.15.7 > 10.0.2.3.53:\n' >> "${work}/dsts"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "allowlist CATCHES a non-relay clearnet dst -> FAIL_RC(${FAIL_RC}), a proven leak" "$([ "${rc}" = "${FAIL_RC}" ] && printf 0 || printf 1)"

## The leak message names the offending non-relay dst (not a relay IP).
set_counts 10 0
printf 'IP 10.0.2.15.7 > 203.0.113.9.443:\n' >> "${work}/dsts"
out="$( ( canary_gateway_pcap ) 2>&1 || true )"
rc=0; { has '203.0.113.9' "${out}" && ! has "${RELAY_DIR}" "${out}"; } || rc=1
check 'leak message names the non-relay dst, not the allowed relay dsts' "${rc}"

## Defense-in-depth: the fixed denylist still fires first on a watched target (forged-source too).
set_counts 10 2
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "denylist still catches a watched target -> FAIL_RC(${FAIL_RC}) (defense-in-depth kept)" "$([ "${rc}" = "${FAIL_RC}" ] && printf 0 || printf 1)"

## Blind capture (no traffic at all) -> inconclusive, never a pass -- before any allowlist read.
set_counts 0 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "blind capture -> SETUP_RC(${SETUP_RC}), inconclusive not a leak" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## --- the leak filter is deny-by-default (infra-exclude) + the host-DNS is NOT carved out --------
## The canary reads ALL clearnet dsts (everything except link infra) and leaks any that are not a
## consensus relay; there is no host-resolver carve-out. The relay set comes from the GW consensus.
set_counts 10 0
infra="$(infra_bpf)"
rc=0; has 'not (' "$(printf '(ip or ip6) and not ( %s )' "${infra}")" || rc=1
check 'leak read is deny-by-default (infra-exclude: a "not (...)" over link infra)' "${rc}"
rc=0; for term in 'udp port 67 and udp port 68 and dst host 255.255.255.255' 'dst net 224.0.0.0/4' 'dst net 169.254.0.0/16'; do has "${term}" "${infra}" || rc=1; done
check 'infra exclusion covers scoped DHCP, 224/4 multicast, link-local' "${rc}"
rc=0; has '10.0.2.3' "${infra}" && rc=1 || rc=0
check 'infra does NOT carve out the host resolver 10.0.2.3 (Tor-only by default)' "${rc}"

## --- fail-closed: an empty relay set cannot form an allowlist -> inconclusive, not a pass -------
set_counts 10 0
printf '' > "${work}/relay_ips"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "empty consensus relay set -> SETUP_RC(${SETUP_RC}), inconclusive not a pass (fail-closed)" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## --- fail-closed: a filter that does not COMPILE is SETUP, never a vacuous 0-leak "canary OK" ----
set_counts 10 0
printf '' > "${work}/filter_fail"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "non-compiling filter -> SETUP_RC(${SETUP_RC}), not a vacuous no-leak" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"
safe-rm --force -- "${work}/filter_fail" 2>/dev/null || true

## --- liveness floor: GENUINE Tor guard traffic (guards MINUS the reserved pc guard) ------------
set_counts 10 0
printf '3\n' > "${work}/tor"   ## below GUARD_MIN_PKTS -- an undercounting / near-blind tap
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "too few genuine Tor guard pkts (undercount) -> SETUP_RC(${SETUP_RC}) (liveness floor)" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## --- positive control counted SEPARATELY: the deliberate emit MUST be captured ----------------
set_counts 10 0
printf '0\n' > "${work}/pc"   ## Tor floor fine (tor=20), but the positive-control emit went unseen
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "positive-control emit unseen (pc=0) despite a healthy Tor floor -> SETUP_RC(${SETUP_RC})" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## Ordering: a DETECTED leak is definitive (FAIL), never downgraded to SETUP just because the
## reserved-guard liveness flow is absent. Leak present + pc unseen -> FAIL (leak-check first).
set_counts 10 0
printf 'IP 10.0.2.15.7 > 10.0.2.3.53:\n' >> "${work}/dsts"
printf '0\n' > "${work}/pc"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "a real leak with the pc emit absent -> FAIL_RC(${FAIL_RC}), never SETUP-masked (leak-check first)" "$([ "${rc}" = "${FAIL_RC}" ] && printf 0 || printf 1)"

## The Tor floor must NOT be satisfiable by the positive-control packet alone (separation).
set_counts 10 0
printf '0\n'  > "${work}/tor"
printf '50\n' > "${work}/pc"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "pc traffic does NOT count toward the Tor floor (tor=0, pc=50) -> SETUP_RC(${SETUP_RC})" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## The genuine-Tor-guard read is `guards AND NOT pc` and the pc read is the reserved guard only.
set_counts 10 0
( canary_gateway_pcap ) >/dev/null 2>&1 || true
tor_filt="$(cat -- "${work}/last_filter_tor" 2>/dev/null || true)"
pc_filt="$(cat -- "${work}/last_filter_pc" 2>/dev/null || true)"
rc=0; for g in "${GUARD_PIN_IPS4[@]}"; do has "host ${g}" "${tor_filt}" || rc=1; done
check 'Tor-guard read is the ENTRY guards (host-match)' "${rc}"
rc2=0; has "host ${GUARD_PC_IP4}" "${tor_filt}" && rc2=1 || rc2=0
check 'Tor-guard read EXCLUDES the reserved pc guard (separate count)' "${rc2}"
rc=0; { has "host ${GUARD_PC_IP4}" "${pc_filt}" && has "tcp dst port ${GUARD_PC_PORT}" "${pc_filt}"; } || rc=1
check 'positive-control read matches the reserved pc guard on its ORPort (host + tcp port)' "${rc}"
rc=0; for g in "${GUARD_PIN_IPS4[@]}"; do has "host ${g}" "${pc_filt}" && rc=1; done
check 'positive-control read does NOT include any entry guard (separation)' "${rc}"

## --- gw_tor_relay_ips: reads the GW consensus as root in the user session ----------------------
rc=0; gw_tor_relay_ips >/dev/null 2>&1 || rc=$?
check 'gw_tor_relay_ips succeeds when guestcontrol does' "${rc}"
rc=0; relay_out="$(gw_tor_relay_ips)" || rc=1
rc2=0; [ -n "${relay_out}" ] || rc2=1
check 'gw_tor_relay_ips emits the relay set (faithful privleap stub -> real root read)' "$(( rc + rc2 ))"

## Regression: gw_tor_relay_ips must GRANT sudo then read as root
## (`leaprun sudo && ... sudo --non-interactive grep ...`), NEVER misuse `leaprun sudo grep ...`
## -- privleap ignores trailing argv, so that form runs nothing and the 700 consensus stays
## unread (the live SETUP rc=2 this guards against). Capture the assembled --cmd via an echo stub.
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
printf '%s\n' "$*"
STUB
chmod +x "${work}/vbe"
relaycmd="$(gw_tor_relay_ips)"
rc=0; has 'sudo --non-interactive grep' "${relaycmd}" || rc=1
check 'gw_tor_relay_ips reads the consensus as root (sudo --non-interactive grep)' "${rc}"
rc=0; has 'leaprun sudo &&' "${relaycmd}" || rc=1
check 'gw_tor_relay_ips grants sudo before reading (leaprun sudo &&)' "${rc}"
rc=0; has 'leaprun sudo grep' "${relaycmd}" && rc=1 || rc=0
check 'gw_tor_relay_ips does NOT misuse leaprun sudo as a command prefix' "${rc}"

## Ordering regression: the consensus MUST be read while the GW is still up (into gw_relay_cache,
## in main, BEFORE the poweroff), never live inside the canary -- the canary runs AFTER the GW
## poweroff that flushes the pcap, when guestcontrol cannot reach the GW (the live SETUP rc=2 bug).
canary_body="$(awk '/^canary_gateway_pcap\(\) \{/,/^}/' "${tool}")"
rc=0; has 'gw_tor_relay_ips' "${canary_body}" && rc=1 || rc=0
check 'canary_gateway_pcap does NOT read the consensus live (uses the pre-poweroff cache)' "${rc}"
rc=0; has 'gw_relay_cache' "${canary_body}" || rc=1
check 'canary_gateway_pcap classifies against gw_relay_cache' "${rc}"
## $-free grep patterns (SC2016): match the population's `gw_tor_relay_ips >` redirect, the
## canary call line, and the last `poweroff >/dev/null` before it.
ln_cache="$(grep -n 'gw_tor_relay_ips >' "${tool}" | head -1 | cut -d: -f1)"
ln_canarycall="$(grep -n 'canary_gateway_pcap$' "${tool}" | tail -1 | cut -d: -f1)"
ln_poweroff="$(grep -n 'poweroff >/dev/null' "${tool}" | awk -F: -v c="${ln_canarycall:-0}" '$1<c{last=$1} END{print last}')"
rc=0; { [ -n "${ln_cache}" ] && [ -n "${ln_poweroff}" ] && [ -n "${ln_canarycall}" ] && [ "${ln_cache}" -lt "${ln_poweroff}" ] && [ "${ln_poweroff}" -lt "${ln_canarycall}" ]; } || rc=1
check 'main populates gw_relay_cache BEFORE the GW poweroff that precedes the canary' "${rc}"

## restore the faithful dispatching stub
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
case "$*" in
   *"sudo --non-interactive grep"*cached-microdesc-consensus*) cat -- "${STUB_DIR}/relay_ips" 2>/dev/null ;;
   *cached-microdesc-consensus*) : ;;
   *) printf '%s\n' "$*" ;;
esac
STUB
chmod +x "${work}/vbe"
set_relay_set   ## the stub consensus branch returns relay_ips; restore after the gw_pin stub swap

## --- gw_pin_guards: EntryNodes + StrictNodes 1 drop-in via leaprun sudo, GW user session --------
rc=0; out="$(gw_pin_guards 2>&1)" || rc=$?
check 'gw_pin_guards succeeds when guestcontrol does' "${rc}"
rc=0; has 'leaprun sudo' "${out}" || rc=1
check 'gw_pin_guards writes the pin via leaprun sudo (GW stays in its user session)' "${rc}"
rc=0; has '--role user' "${out}" || rc=1
check 'gw_pin_guards runs in the GW USER session (forwarding intact)' "${rc}"
rc=0; has 'EntryNodes %s' "${out}" && has 'StrictNodes 1' "${out}" || rc=1
check 'gw_pin_guards sets EntryNodes + StrictNodes 1' "${rc}"
csv_expect="$(IFS=','; printf '%s' "${GUARD_PIN_IPS4[*]}")"
rc=0; has "${csv_expect}" "${out}" || rc=1
check 'gw_pin_guards pins exactly the GUARD_PIN_IPS4 entry set (CSV, derived -- no drift)' "${rc}"
rc=0; has "${GUARD_PC_IP4}" "${out}" && rc=1 || rc=0
check 'gw_pin_guards does NOT pin the reserved positive-control guard as an EntryNode' "${rc}"
rc=0; has "${GW_TORRC_PIN}" "${out}" || rc=1
check 'gw_pin_guards writes the torrc.d drop-in path Whonix %includes' "${rc}"

## Fail-closed: a GW whose pin cannot be written is not measurable -> nonzero (SETUP), never a pass.
printf '#!/bin/bash\nexit 1\n' > "${work}/vbe"; chmod +x "${work}/vbe"
rc=0; ( gw_pin_guards ) >/dev/null 2>&1 || rc=$?
check_fail 'gw_pin_guards fails-closed (nonzero) when the pin write cannot run' "${rc}"
## restore the dispatching stub for anything after
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
case "$*" in
   *"sudo --non-interactive grep"*cached-microdesc-consensus*) cat -- "${STUB_DIR}/relay_ips" 2>/dev/null ;;
   *cached-microdesc-consensus*) : ;;
   *) printf '%s\n' "$*" ;;
esac
STUB
chmod +x "${work}/vbe"

## --- --print-guards: the single source the host-wire oracle consumes (one IP per line) ----------
rc=0; guards_out="$("${tool}" --print-guards)" || rc=$?
check '--print-guards exits 0' "${rc}"
rc=0
for g in "${GUARD_PIN_IPS4[@]}" "${GUARD_PIN_IPS6[@]}"; do grep --quiet --line-regexp --fixed-strings -- "${g}" <<< "${guards_out}" || rc=1; done
check '--print-guards prints every ENTRY guard IP (v4 + v6)' "${rc}"
rc=0; grep --quiet --line-regexp --fixed-strings -- "${GUARD_PC_IP4}" <<< "${guards_out}" && rc=1 || rc=0
check '--print-guards does NOT print the reserved pc guard (its own count via --print-pc-filter)' "${rc}"
rc=0; [ "$(grep -c . <<< "${guards_out}")" = "$(( ${#GUARD_PIN_IPS4[@]} + ${#GUARD_PIN_IPS6[@]} ))" ] || rc=1
check '--print-guards prints ONLY the entry guards (no extra lines)' "${rc}"

## --- --print-allow-filter + --print-pc-filter: single sources for the host-wire oracle ---------
rc=0; filt_out="$("${tool}" --print-allow-filter)" || rc=$?
check '--print-allow-filter exits 0' "${rc}"
rc=0; [ "${filt_out}" = "$(allowlist_bpf)" ] || rc=1
check '--print-allow-filter output is byte-identical to allowlist_bpf (single source)' "${rc}"
rc=0; pc_out="$("${tool}" --print-pc-filter)" || rc=$?
check '--print-pc-filter exits 0' "${rc}"
rc=0; { has "host ${GUARD_PC_IP4}" "${pc_out}" && has "tcp dst port ${GUARD_PC_PORT}" "${pc_out}"; } || rc=1
check '--print-pc-filter names the reserved pc guard on its ORPort' "${rc}"
rc=0; [ "${pc_out}" = "$(pc_bpf)" ] || rc=1
check '--print-pc-filter output is byte-identical to pc_bpf (single source)' "${rc}"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
