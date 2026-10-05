#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-whonix-pair pure-logic unit tests (no VM) for the deny-by-default GW-NIC ALLOWLIST: the ONLY
## clearnet dsts permitted leaving the GW are the pinned guards (+ link infra); ANY other clearnet
## dst is a LEAK (Tor-only by default, no host-DNS carve-out). Also: genuine Tor guard traffic and
## the reserved-guard POSITIVE CONTROL are counted SEPARATELY (neither masks the other); the
## guard-pin assembly (gw_pin_guards -> EntryNodes + StrictNodes 1 via leaprun sudo, EXCLUDING the
## reserved guard); and the --print-guards / --print-pc-filter single sources the host-wire oracle
## reads. Sources the real dm-whonix-pair (its source-guard keeps main() from running) with a
## stubbed tcpdump/vbox-exec-local.

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

## Stub tcpdump. The canary issues FIVE read kinds; classify by the filter text (most specific
## first), record a per-kind count file, and capture the filter string for the assertions:
##   allow : has "169.254"  -> STUB_DIR/allow  (deny-by-default allowlist leaks)
##   deny  : has "dst host" -> STUB_DIR/hits   (fixed watched-target denylist)
##   tor   : has "not ("    -> STUB_DIR/tor    (guards AND NOT pc = genuine Tor guard traffic)
##   pc    : has "host "    -> STUB_DIR/pc     (reserved-guard positive control, host-only)
##   full  : no filter      -> STUB_DIR/total
## A missing count file reads as 0.
cat > "${work}/tcpdump" <<'STUB'
#!/bin/bash
mode=full
for a in "$@"; do case "$a" in *"169.254"*)  mode=allow; printf '%s' "$a" > "${STUB_DIR}/last_filter_allow"; break ;; esac; done
if [ "${mode}" = full ]; then
   for a in "$@"; do case "$a" in *"dst host"*) mode=deny;  printf '%s' "$a" > "${STUB_DIR}/last_filter"; break ;; esac; done
fi
if [ "${mode}" = full ]; then
   for a in "$@"; do case "$a" in *"not ("*)    mode=tor;   printf '%s' "$a" > "${STUB_DIR}/last_filter_tor"; break ;; esac; done
fi
if [ "${mode}" = full ]; then
   for a in "$@"; do case "$a" in *"host "*)     mode=pc;    printf '%s' "$a" > "${STUB_DIR}/last_filter_pc"; break ;; esac; done
fi
case "${mode}" in
   full)  f="${STUB_DIR}/total" ;;
   allow) f="${STUB_DIR}/allow" ;;
   deny)  f="${STUB_DIR}/hits" ;;
   tor)   f="${STUB_DIR}/tor" ;;
   pc)    f="${STUB_DIR}/pc" ;;
esac
## A FILTERED run (any mode but full) exits nonzero when STUB_DIR/filter_fail exists -- models a
## filter that does not COMPILE (libpcap missing a primitive / malformed BPF), which must be
## SETUP, not a clean 0.
if [ "${mode}" != full ] && [ -e "${STUB_DIR}/filter_fail" ]; then exit 1; fi
n="$(cat -- "${f}" 2>/dev/null || printf 0)"
i=0
while [ "${i}" -lt "${n}" ]; do
   printf 'pkt\n'
   i=$(( i + 1 ))
done
STUB
chmod +x "${work}/tcpdump"
export STUB_DIR="${work}"

## Stub vbox-exec-local: echo its args so gw_pin_guards's assembled --cmd is captured.
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
printf '%s\n' "$*"
STUB
chmod +x "${work}/vbe"

## Stub VBoxManage / sleep: no real VBox here; the killswitch/settle sleeps must not slow the test.
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

## total, denylist-hits, allowlist-leaks. Defaults for the separate liveness signals: tor=20
## (>= GUARD_MIN_PKTS) and pc=1 (>= 1) so a run is clean unless a case overrides them.
set_counts() {
   printf '%s\n' "$1" > "${work}/total"
   printf '%s\n' "$2" > "${work}/hits"
   printf '%s\n' "$3" > "${work}/allow"
   printf '20\n' > "${work}/tor"
   printf '1\n'  > "${work}/pc"
}

## --- allowlist verdicts --------------------------------------------------------------------
## Clean: traffic present, 0 watched-target hits, 0 non-guard dsts (guard-only + DHCP) -> PASS.
set_counts 10 0 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check 'allowlist clean (guard-only + infra, 0 non-guard dsts) -> PASS' "${rc}"

## Injected NON-guard clearnet packet (e.g. host-DNS 10.0.2.3 / NTP) -> a proven LEAK (FAIL_RC),
## even though NO watched denylist target appears. This is the gap the allowlist closes.
set_counts 10 0 4
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "allowlist CATCHES a non-guard clearnet dst -> FAIL_RC(${FAIL_RC}), a proven leak" "$([ "${rc}" = "${FAIL_RC}" ] && printf 0 || printf 1)"

## Defense-in-depth: the fixed denylist still fires first on a watched target (forged-source too).
set_counts 10 2 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "denylist still catches a watched target -> FAIL_RC(${FAIL_RC}) (defense-in-depth kept)" "$([ "${rc}" = "${FAIL_RC}" ] && printf 0 || printf 1)"

## Blind capture (no traffic at all) -> inconclusive, never a pass -- before any allowlist read.
set_counts 0 0 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "blind capture -> SETUP_RC(${SETUP_RC}), inconclusive not a leak" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## --- allowlist filter is deny-by-default + names every pinned guard + the infra exclusions ----
set_counts 10 0 0
( canary_gateway_pcap ) >/dev/null 2>&1 || true
filt="$(cat -- "${work}/last_filter_allow" 2>/dev/null || true)"
rc=0; has 'not (' "${filt}" || rc=1
check 'allowlist filter is deny-by-default (a "not (...)" exclusion)' "${rc}"
rc=0
for g in "${GUARD_PIN_IPS4[@]}" "${GUARD_PIN_IPS6[@]}" "${GUARD_PC_IP4}" "${GUARD_PC_IP6}"; do has "host ${g}" "${filt}" || rc=1; done
check 'allowlist permits EVERY guard IP (entry + reserved pc, v4 + v6), either direction (host)' "${rc}"
rc=0
for term in 'udp port 67 and udp port 68 and dst host 255.255.255.255' 'dst net 224.0.0.0/4' 'dst net 169.254.0.0/16'; do has "${term}" "${filt}" || rc=1; done
check 'allowlist excludes structural link infra (scoped DHCP, 224/4 multicast, link-local)' "${rc}"
rc=0; has '10.0.2.3' "${filt}" && rc=1 || rc=0
check 'allowlist does NOT carve out the host resolver 10.0.2.3 (Tor-only by default)' "${rc}"

## --- fail-closed: an empty ENTRY-guard set cannot form an allowlist -> inconclusive, not a pass -
set_counts 10 0 0
saved_guards=( "${GUARD_PIN_IPS4[@]}" )
GUARD_PIN_IPS4=()
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "empty entry-guard set -> SETUP_RC(${SETUP_RC}), inconclusive not a pass (fail-closed)" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"
GUARD_PIN_IPS4=( "${saved_guards[@]}" )

## --- fail-closed: a filter that does not COMPILE is SETUP, never a vacuous 0-leak "canary OK" ----
## (A piped `tcpdump | wc -l` hid tcpdump's rc; the fix captures it, so a compile failure dies
## SETUP. On the old code this aborted with tcpdump's exit, NOT SETUP_RC -- this asserts SETUP_RC.)
set_counts 10 0 0
printf '' > "${work}/filter_fail"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "non-compiling filter -> SETUP_RC(${SETUP_RC}), not a vacuous no-leak" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"
safe-rm --force -- "${work}/filter_fail" 2>/dev/null || true

## --- liveness floor: GENUINE Tor guard traffic (guards MINUS the reserved pc guard) ------------
## (traffic present + 0 watched + 0 non-guard could still be a tap that never saw the GW's egress;
## require a real Tor-guard floor so a leak would actually be observable, not a 0 from a dead tap.)
set_counts 10 0 0
printf '3\n' > "${work}/tor"   ## below GUARD_MIN_PKTS -- an undercounting / near-blind tap
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "too few genuine Tor guard pkts (undercount) -> SETUP_RC(${SETUP_RC}) (liveness floor)" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## --- positive control counted SEPARATELY: the deliberate emit MUST be captured ----------------
## The reserved-guard emit cannot be satisfied by Tor's own traffic (counted apart); a 0 here with
## a healthy Tor floor still means the tap missed the deliberate canary -> inconclusive, not a pass.
set_counts 10 0 0
printf '0\n' > "${work}/pc"   ## Tor floor fine (tor=20), but the positive-control emit went unseen
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "positive-control emit unseen (pc=0) despite a healthy Tor floor -> SETUP_RC(${SETUP_RC})" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## The Tor floor must NOT be satisfiable by the positive-control packet alone (separation): a run
## with tor below the floor but pc present is still SETUP, proving pc does not inflate the floor.
set_counts 10 0 0
printf '0\n'  > "${work}/tor"
printf '50\n' > "${work}/pc"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "pc traffic does NOT count toward the Tor floor (tor=0, pc=50) -> SETUP_RC(${SETUP_RC})" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"

## The genuine-Tor-guard read is `guards AND NOT pc` and the pc read is the reserved guard only.
set_counts 10 0 0
( canary_gateway_pcap ) >/dev/null 2>&1 || true
tor_filt="$(cat -- "${work}/last_filter_tor" 2>/dev/null || true)"
pc_filt="$(cat -- "${work}/last_filter_pc" 2>/dev/null || true)"
rc=0; { has 'not (' "${tor_filt}" && has "host ${GUARD_PC_IP4}" "${tor_filt}"; } || rc=1
check 'Tor-guard read excludes the reserved pc guard ("... and not ( host <pc> ... )")' "${rc}"
rc=0; has "host ${GUARD_PC_IP4}" "${pc_filt}" || rc=1
rc2=0; has 'not (' "${pc_filt}" && rc2=1 || rc2=0
check 'positive-control read matches ONLY the reserved pc guard (host, no "not (")' "$([ "${rc}" = 0 ] && [ "${rc2}" = 0 ] && printf 0 || printf 1)"
rc=0; for g in "${GUARD_PIN_IPS4[@]}"; do has "host ${g}" "${pc_filt}" && rc=1; done
check 'positive-control read does NOT include any entry guard (separation by host)' "${rc}"

## --- gw_pin_guards: EntryNodes + StrictNodes 1 drop-in via leaprun sudo, GW user session --------
rc=0; out="$(gw_pin_guards 2>&1)" || rc=$?
check 'gw_pin_guards succeeds when guestcontrol does' "${rc}"
rc=0; has 'leaprun sudo' "${out}" || rc=1
check 'gw_pin_guards writes the pin via leaprun sudo (GW stays in its user session)' "${rc}"
rc=0; has '--role user' "${out}" || rc=1
check 'gw_pin_guards runs in the GW USER session (forwarding intact)' "${rc}"
rc=0; has 'EntryNodes %s' "${out}" && has 'StrictNodes 1' "${out}" || rc=1
check 'gw_pin_guards sets EntryNodes + StrictNodes 1' "${rc}"
## CSV is DERIVED from GUARD_PIN_IPS4 (single source, no hardcoded drift).
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
## restore the echoing stub for anything after
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
printf '%s\n' "$*"
STUB
chmod +x "${work}/vbe"

## --- --print-guards: the single source the host-wire oracle consumes (one IP per line) ----------
rc=0; guards_out="$("${tool}" --print-guards)" || rc=$?
check '--print-guards exits 0' "${rc}"
rc=0
for g in "${GUARD_PIN_IPS4[@]}" "${GUARD_PIN_IPS6[@]}" "${GUARD_PC_IP4}" "${GUARD_PC_IP6}"; do grep --quiet --line-regexp --fixed-strings -- "${g}" <<< "${guards_out}" || rc=1; done
check '--print-guards prints every allowlisted guard IP (entry + reserved pc, v4 + v6)' "${rc}"
rc=0; [ "$(grep -c . <<< "${guards_out}")" = "$(( ${#GUARD_PIN_IPS4[@]} + ${#GUARD_PIN_IPS6[@]} + 2 ))" ] || rc=1
check '--print-guards prints ONLY the allowlisted guards (entry + 2 pc, no extra lines)' "${rc}"

## --- --print-allow-filter: the host-wire oracle reuses the SAME allowlist BPF (single source) --
rc=0; filt_out="$("${tool}" --print-allow-filter)" || rc=$?
check '--print-allow-filter exits 0' "${rc}"
rc=0; { has 'not (' "${filt_out}" && has '169.254.0.0/16' "${filt_out}"; } || rc=1
for g in "${GUARD_PIN_IPS4[@]}" "${GUARD_PIN_IPS6[@]}" "${GUARD_PC_IP4}" "${GUARD_PC_IP6}"; do has "host ${g}" "${filt_out}" || rc=1; done
check '--print-allow-filter emits the deny-by-default BPF with every guard + infra (reused verbatim)' "${rc}"
rc=0; [ "${filt_out}" = "$(allowlist_bpf)" ] || rc=1
check '--print-allow-filter output is byte-identical to the canary allowlist_bpf (single source)' "${rc}"

## --- --print-pc-filter: the host-wire oracle reuses the SAME pc discriminator (single source) --
rc=0; pc_out="$("${tool}" --print-pc-filter)" || rc=$?
check '--print-pc-filter exits 0' "${rc}"
rc=0; has "host ${GUARD_PC_IP4}" "${pc_out}" && has "host ${GUARD_PC_IP6}" "${pc_out}" || rc=1
check '--print-pc-filter names ONLY the reserved pc guard (v4 + v6)' "${rc}"
rc=0; for g in "${GUARD_PIN_IPS4[@]}"; do has "host ${g}" "${pc_out}" && rc=1; done
check '--print-pc-filter excludes every entry guard (clean separation)' "${rc}"
rc=0; [ "${pc_out}" = "$(pc_bpf)" ] || rc=1
check '--print-pc-filter output is byte-identical to the canary pc_bpf (single source)' "${rc}"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
