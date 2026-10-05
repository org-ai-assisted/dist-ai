#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-whonix-pair pure-logic unit tests (no VM) for the deny-by-default GW-NIC ALLOWLIST: the ONLY
## clearnet dsts permitted leaving the GW are the pinned entry guards (+ link infra); ANY other
## clearnet dst is a LEAK (Tor-only by default, no host-DNS carve-out). Also the guard-pin command
## assembly (gw_pin_guards -> EntryNodes + StrictNodes 1 via leaprun sudo) and the --print-guards
## single source the host-wire oracle reads. Sources the real dm-whonix-pair (its source-guard
## keeps main() from running) with a stubbed tcpdump/vbox-exec-local.

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

## Stub tcpdump, three filter kinds (canary runs the denylist AND the allowlist read):
##   - ALLOWLIST (deny-by-default) -> has the unique "169.254" infra term -> emit STUB_DIR/allow
##     lines, capture the filter to last_filter_allow.
##   - DENYLIST (watched targets) -> has "dst host", no 169.254 -> emit STUB_DIR/hits.
##   - full read (no filter) -> emit STUB_DIR/total.
## A missing count file reads as 0.
cat > "${work}/tcpdump" <<'STUB'
#!/bin/bash
mode=full
for a in "$@"; do case "$a" in *"169.254"*) mode=allow; printf '%s' "$a" > "${STUB_DIR}/last_filter_allow" ;; esac; done
if [ "${mode}" = full ]; then
   for a in "$@"; do case "$a" in *"dst host"*) mode=deny; printf '%s' "$a" > "${STUB_DIR}/last_filter" ;; esac; done
fi
case "${mode}" in
   allow) f="${STUB_DIR}/allow" ;;
   deny)  f="${STUB_DIR}/hits" ;;
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

## total, denylist-hits, allowlist-leaks.
set_counts() { printf '%s\n' "$1" > "${work}/total"; printf '%s\n' "$2" > "${work}/hits"; printf '%s\n' "$3" > "${work}/allow"; }

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
for g in "${GUARD_PIN_IPS4[@]}" "${GUARD_PIN_IPS6[@]}"; do has "host ${g}" "${filt}" || rc=1; done
check 'allowlist permits EVERY pinned guard IP (v4 + v6), either direction (host, not dst-only)' "${rc}"
rc=0
for term in 'udp port 67 and udp port 68 and dst host 255.255.255.255' 'dst net 224.0.0.0/4' 'dst net 169.254.0.0/16'; do has "${term}" "${filt}" || rc=1; done
check 'allowlist excludes structural link infra (scoped DHCP, 224/4 multicast, link-local)' "${rc}"
rc=0; has '10.0.2.3' "${filt}" && rc=1 || rc=0
check 'allowlist does NOT carve out the host resolver 10.0.2.3 (Tor-only by default)' "${rc}"

## --- fail-closed: an empty guard set cannot form an allowlist -> inconclusive, never a pass -----
set_counts 10 0 0
saved_guards=( "${GUARD_PIN_IPS4[@]}" )
GUARD_PIN_IPS4=()
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check "empty pinned-guard set -> SETUP_RC(${SETUP_RC}), inconclusive not a pass (fail-closed)" "$([ "${rc}" = "${SETUP_RC}" ] && printf 0 || printf 1)"
GUARD_PIN_IPS4=( "${saved_guards[@]}" )

## --- gw_pin_guards: EntryNodes + StrictNodes 1 drop-in via leaprun sudo, GW user session --------
out="$(gw_pin_guards 2>&1)"; rc=$?
check 'gw_pin_guards succeeds when guestcontrol does' "${rc}"
rc=0; has 'leaprun sudo' "${out}" || rc=1
check 'gw_pin_guards writes the pin via leaprun sudo (GW stays in its user session)' "${rc}"
rc=0; has '--role user' "${out}" || rc=1
check 'gw_pin_guards runs in the GW USER session (forwarding intact)' "${rc}"
rc=0; has 'EntryNodes %s' "${out}" && has 'StrictNodes 1' "${out}" || rc=1
check 'gw_pin_guards sets EntryNodes + StrictNodes 1' "${rc}"
rc=0; has '185.220.100.242,148.251.33.107,88.99.7.87,185.107.57.64,94.130.133.51' "${out}" || rc=1
check 'gw_pin_guards pins exactly the GUARD_PIN_IPS4 set (CSV, single source)' "${rc}"
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
guards_out="$("${tool}" --print-guards)"; rc=$?
check '--print-guards exits 0' "${rc}"
rc=0
for g in "${GUARD_PIN_IPS4[@]}" "${GUARD_PIN_IPS6[@]}"; do grep --quiet --line-regexp --fixed-strings -- "${g}" <<< "${guards_out}" || rc=1; done
check '--print-guards prints every pinned guard IP, one per line (v4 + v6)' "${rc}"
rc=0; [ "$(grep -c . <<< "${guards_out}")" = "$(( ${#GUARD_PIN_IPS4[@]} + ${#GUARD_PIN_IPS6[@]} ))" ] || rc=1
check '--print-guards prints ONLY the pinned guards (no extra lines)' "${rc}"

## --- --print-allow-filter: the host-wire oracle reuses the SAME allowlist BPF (single source) --
filt_out="$("${tool}" --print-allow-filter)"; rc=$?
check '--print-allow-filter exits 0' "${rc}"
rc=0; { has 'not (' "${filt_out}" && has '169.254.0.0/16' "${filt_out}"; } || rc=1
for g in "${GUARD_PIN_IPS4[@]}" "${GUARD_PIN_IPS6[@]}"; do has "host ${g}" "${filt_out}" || rc=1; done
check '--print-allow-filter emits the deny-by-default BPF with every guard + infra (reused verbatim)' "${rc}"
rc=0; [ "${filt_out}" = "$(allowlist_bpf)" ] || rc=1
check '--print-allow-filter output is byte-identical to the canary allowlist_bpf (single source)' "${rc}"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
