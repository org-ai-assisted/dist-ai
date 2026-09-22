#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Shared harness for the whonix-firewall leak-test suite.
##
## Builds a three-namespace model of a Non-Qubes-Whonix gateway that has real
## IPv6 clearnet (the accept_ra end-state) and loads the REAL generated
## whonix-gateway-firewall ruleset, so each case exercises the shipped rules,
## not a hand-written copy:
##
##   ws  --(internal eth1)-->  gw  --(external eth0, global IPv6 + default route)-->  up
##
## ws  = Whonix-Workstation (injects probe packets, L2, on eth1's peer)
## gw  = Whonix-Gateway (runs the ruleset + a stub Tor TransPort listener)
## up  = upstream/ISP sink (stands in for sys-leaktest; sees whatever gw EMITS)
##
## A leak = a probe-tagged packet reaching 'up'. Every case also runs a POSITIVE
## CONTROL: a legitimate workstation TCP connection must still be transparently
## redirected to the Tor port and answered -- so a "no leak" verdict cannot come
## from a wedged topology where nothing works at all.
##
## Needs REAL root: nf_nat/conntrack REDIRECT is not faithful in an unprivileged
## user namespace (the reply-egress path differs), so a rootless run would report
## false PASSes. A non-root invocation exits 77 (SKIPPED), never a false pass.
##
## Reusability: the probe/observe helpers are the seam. Against this netns model
## they inject on a veth peer and capture on the sink; the same case logic can
## later drive a real Workstation and capture on a real sys-leaktest by swapping
## these helpers, without touching the per-case assertions.

## Resolved by the runner; the library only reads them.
##   WHONIX_FIREWALL_REPO -> gateway ruleset at
##     ${WHONIX_FIREWALL_REPO}/test-output/new/gateway-default.nft

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Internal (Whonix) addressing, matches whonix-gateway-firewall Non-Qubes defaults.
INT_GW_IP4='10.152.152.10'
INT_WS_IP4='10.152.152.11'
INT_GW_IP6='fd19:c33d:88bc::10'
INT_WS_IP6='fd19:c33d:88bc::11'
## External (clearnet) addressing -- the global IPv6 default route is the point.
EXT_GW_IP4='10.0.2.15'
EXT_UP_IP4='10.0.2.2'
EXT_GW_IP6='2001:db8:aaaa::2'
EXT_UP_IP6='2001:db8:aaaa::1'
## Probe tags (RFC 3849 / RFC 5737 documentation space; never routable).
## PROBE_SRC_IP6 / PROBE_DST_IP4 are consumed by sourcing test files, not here.
# shellcheck disable=SC2034
PROBE_SRC_IP6='2001:db8:beef::99'
PROBE_DST_IP6='2001:db8:dead::1'
# shellcheck disable=SC2034
PROBE_DST_IP4='198.51.100.7'

## Broad egress oracle: capture ANY packet reaching the sink except the benign
## external-link chatter (the gw<->up neighbor discovery + multicast/ARP). A leak
## to an UNEXPECTED destination is caught too, not only the probe's dest -- a BPF
## filtered to the known dest would miss a rewritten/redirected leak.
LEAKTEST_EGRESS_BPF="(ip or ip6) and not (host ${EXT_UP_IP6} or host ${EXT_GW_IP6} or net 10.0.2.0/24 or ip6 multicast or ip multicast or arp)"

LEAKTEST_LISTENER_PID=''
LEAKTEST_TCPDUMP_PID=''

msg() {
   printf '%s\n' "$*"
}

fail_case() {
   printf '%s\n' "FAIL: $*" >&2
   return 1
}

skip_case() {
   printf '%s\n' "SKIP: $*" >&2
   ## Callers use this only for genuinely OPTIONAL targets: no root (netns
   ## unavailable) or no whonix-firewall checkout (nothing to load).
   ## style-ok: allow-skip: optional target absent (no root / no whonix-firewall)
   exit 77
}

## Guard: real root and a ruleset to test, or skip. Required tools (ip, nft,
## tcpdump, python3, unshare) are assumed present per dist-ai convention -- a
## missing one fails loudly at first use, it is not a silent skip.
leaktest_preconditions() {
   ## netns needs real root; the runner self-elevates, so reaching here as
   ## non-root means sudo was unavailable -- a capability absence.
   if [ "$(id -u)" != '0' ]; then
      skip_case 'requires real root (netns + nf_nat); run under sudo'
   fi
   ## The whonix-firewall checkout is an optional target (like other dist-ai
   ## suites that exit 77 when their subject is absent).
   if [ -z "${WHONIX_FIREWALL_REPO:-}" ]; then
      skip_case 'WHONIX_FIREWALL_REPO is unset (no gateway ruleset to test)'
   fi
   ruleset_file="${WHONIX_FIREWALL_REPO}/test-output/new/gateway-default.nft"
   if [ ! -r "${ruleset_file}" ]; then
      skip_case "gateway ruleset not readable: ${ruleset_file}"
   fi
}

## helpers dir (ships beside this library)
leaktest_helpers_dir() {
   printf '%s\n' "$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/helpers"
}

leaktest_teardown() {
   if [ -n "${LEAKTEST_LISTENER_PID}" ]; then
      kill "${LEAKTEST_LISTENER_PID}" 2>/dev/null || true
      LEAKTEST_LISTENER_PID=''
   fi
   local ns
   for ns in ws gw up; do
      ip netns delete "${ns}" 2>/dev/null || true
   done
   ip link delete gw_e0 2>/dev/null || true
   ip link delete ws_e 2>/dev/null || true
}

## Build the topology and load the given ruleset into gw. Starts a stub Tor
## TransPort listener on gw:9040 and gw:5300 (DNS). Idempotent teardown first.
leaktest_setup() {
   local ruleset="$1"
   leaktest_teardown

   local ns
   for ns in ws gw up; do
      ip netns add "${ns}"
   done

   ip link add ws_e type veth peer name gw_e1
   ip link add gw_e0 type veth peer name up_e
   ip link set ws_e netns ws
   ip link set gw_e1 netns gw
   ip link set gw_e0 netns gw
   ip link set up_e netns up

   ip netns exec ws ip link set ws_e name eth0
   ip netns exec gw ip link set gw_e1 name eth1
   ip netns exec gw ip link set gw_e0 name eth0
   ip netns exec up ip link set up_e name eth0
   for ns in ws gw up; do
      ip netns exec "${ns}" ip link set lo up
   done

   ## internal link
   ip netns exec ws ip link set eth0 up
   ip netns exec gw ip link set eth1 up
   ip netns exec ws ip address add "${INT_WS_IP4}/24" dev eth0
   ip netns exec gw ip address add "${INT_GW_IP4}/24" dev eth1
   ip netns exec ws ip -6 address add "${INT_WS_IP6}/96" dev eth0 nodad
   ip netns exec gw ip -6 address add "${INT_GW_IP6}/96" dev eth1 nodad

   ## external link (global IPv6 + default route == accept_ra end-state)
   ip netns exec gw ip link set eth0 up
   ip netns exec up ip link set eth0 up
   ip netns exec gw ip address add "${EXT_GW_IP4}/24" dev eth0
   ip netns exec up ip address add "${EXT_UP_IP4}/24" dev eth0
   ip netns exec gw ip -6 address add "${EXT_GW_IP6}/64" dev eth0 nodad
   ip netns exec up ip -6 address add "${EXT_UP_IP6}/64" dev eth0 nodad

   ip netns exec ws ip route add default via "${INT_GW_IP4}"
   ip netns exec ws ip -6 route add default via "${INT_GW_IP6}"
   ip netns exec gw ip route add default via "${EXT_UP_IP4}"
   ip netns exec gw ip -6 route add default via "${EXT_UP_IP6}"

   ip netns exec gw sysctl --quiet --write net.ipv4.ip_forward=1
   ip netns exec gw sysctl --quiet --write net.ipv6.conf.all.forwarding=1
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.all.rp_filter=1
   ip netns exec up sysctl --quiet --write net.ipv6.conf.all.forwarding=1

   ## Disable segmentation/offload on the egress + capture path so a host capture
   ## reflects the wire (GSO/GRO can make a capture look clean while the NIC emits
   ## different bytes). Best-effort: veth may not support every knob.
   ip netns exec gw ethtool --offload eth0 tso off gso off gro off tx off rx off >/dev/null 2>&1 || true
   ip netns exec up ethtool --offload eth0 tso off gso off gro off tx off rx off >/dev/null 2>&1 || true

   ## Fail-closed cases pass 'nolistener' to leave the Tor TransPort dead.
   if [ "${2:-}" != 'nolistener' ]; then
      ip netns exec gw python3 "$(leaktest_helpers_dir)/stub_transport.py" &
      LEAKTEST_LISTENER_PID="$!"
      sleep 1
   fi

   if ! ip netns exec gw nft --file "${ruleset}"; then
      fail_case "could not load ruleset into gw netns: ${ruleset}"
      return 1
   fi
}

## Capture probe-tagged traffic egressing gw (arrives at 'up') for <secs>.
## Prints the pcap-summary lines to stdout. <bpf> is a tcpdump filter.
leaktest_capture_up() {
   local bpf="$1" secs="$2" outfile="$3"
   ## Keep tcpdump's stderr ("listening on ...") so a capture that never bound
   ## (bad interface / BPF, permission failure) is distinguishable from a real
   ## zero-packet result -- otherwise both look like "0 egress" (a false PASS).
   ip netns exec up timeout "${secs}" tcpdump --no-promiscuous-mode -nni eth0 -l "${bpf}" \
      >"${outfile}" 2>"${outfile}.err" &
   LEAKTEST_TCPDUMP_PID="$!"
}

## Wait for the backgrounded capture (bounded by its own timeout) to finish.
leaktest_capture_wait() {
   if [ -n "${LEAKTEST_TCPDUMP_PID}" ]; then
      wait "${LEAKTEST_TCPDUMP_PID}" 2>/dev/null || true
      LEAKTEST_TCPDUMP_PID=''
   fi
}

## Count captured packets. Each tcpdump line begins with a timestamp, so count
## timestamped lines -- protocol-decode independent (port 123 prints as "NTPv5",
## 443 as "https", etc.). The BPF filter is what scopes the capture to the probe.
leaktest_egress_count() {
   local outfile="$1" count
   count="$(grep --count --extended-regexp '^[0-9][0-9]:[0-9][0-9]:[0-9][0-9][.]' "${outfile}" 2>/dev/null || true)"
   ## Always emit a well-formed integer: an empty/absent file must read 0, never
   ## an empty string that would break a later '[ ... -ne 0 ]' into a false PASS.
   printf '%s' "${count:-0}"
}

## True if the capture at <outfile> actually bound and listened (tcpdump printed
## "listening on ..."). A capture that never started must not read as "no leak".
leaktest_capture_bound() {
   grep --quiet 'listening on' "$1.err" 2>/dev/null
}

## Derive a permissive-forward ruleset from a real one, so a forward-leak canary
## actually egresses -- proving the probe + capture detect a leak when one exists.
leaktest_permissive_ruleset() {
   local infile="$1" outfile="$2"
   sed \
      -e 's/hook forward priority 0; policy drop/hook forward priority 0; policy accept/' \
      -e '/add rule inet filter forward counter reject/d' \
      "${infile}" >"${outfile}"
}

## Fire a non-redirected probe from ws and print "<egress-count> <capture-live>":
## the count of ANY packet reaching the sink (broad oracle: a leak to an
## unexpected destination is caught too, not only the probe's dest) plus 1/0 for
## whether the capture actually bound. Runs in a command substitution, so it
## returns these by VALUE. Callers must treat capture-live=0 as a hard failure,
## never "no leak". Extra inject.py args after the fixed ones.
##
## Delivery is proven by the per-case permissive canary (the same inject MUST
## egress once the rules permit), not a firewall counter: nft drop/reject counters
## are polluted by the netns's own post-setup ND/MLD settling, so a counter delta
## cannot distinguish this probe from ambient traffic.
leaktest_fire_forward_probe() {
   local proto="$1" src="$2" dst="$3" capture_file="$4"
   shift 4
   leaktest_capture_up "${LEAKTEST_EGRESS_BPF}" 6 "${capture_file}"
   sleep 1
   ip netns exec ws python3 "$(leaktest_helpers_dir)/inject.py" \
      --proto "${proto}" --iface eth0 --gw4 "${INT_GW_IP4}" \
      --src "${src}" --dst "${dst}" "$@" >/dev/null 2>&1
   sleep 3
   leaktest_capture_wait
   local live=0
   leaktest_capture_bound "${capture_file}" && live=1
   printf '%s %s\n' "$(leaktest_egress_count "${capture_file}")" "${live}"
}

## Assert the primary leg BLOCKED: a live capture that saw zero probe packets.
## <count> <live> come from leaktest_fire_forward_probe. Returns 0 on pass.
leaktest_assert_blocked() {
   local label="$1" count="$2" live="$3"
   if [ "${live}" != '1' ]; then
      fail_case "${label}: capture did not bind -- result untrustworthy"
      return 1
   fi
   if [ "${count}" -ne 0 ]; then
      fail_case "${label}: egressed the gateway (${count} pkt(s))"
      return 1
   fi
   msg "PASS: ${label} blocked (0 egress)"
}

## Assert the canary leg LEAKED: a live capture that saw the probe -- proving the
## harness detects a leak when one exists (teeth). Returns 0 on pass.
leaktest_assert_leaked() {
   local label="$1" count="$2" live="$3"
   if [ "${live}" != '1' ]; then
      fail_case "${label} canary: capture did not bind -- cannot prove teeth"
      return 1
   fi
   if [ "${count}" -gt 0 ]; then
      msg "PASS: ${label} canary egressed (${count} pkt(s)); test has teeth"
      return 0
   fi
   fail_case "${label} canary: leak did NOT reproduce -- harness proves nothing"
   return 1
}

## Generic probe-leak case with an EXPLICIT source: a non-redirected probe must
## not egress under the shipped ruleset (the gateway rejects forwarding), a
## positive control must still work, and a permissive-forward canary must egress.
## Args: <label> <proto> <src> <dst> [inject args]. Returns 0 if all hold.
leaktest_probe_case() {
   local label="$1" proto="$2" src="$3" dst="$4"
   shift 4
   local capture_file permissive count live rc=0
   capture_file="$(mktemp)"

   leaktest_setup "${ruleset_file}"
   read -r count live < <(leaktest_fire_forward_probe "${proto}" "${src}" "${dst}" "${capture_file}" "$@")
   leaktest_assert_blocked "${label}" "${count}" "${live}" || rc=1
   if leaktest_positive_control; then
      msg "PASS: positive control (legit torified TCP path works)"
   else
      rc=1
   fi

   permissive="$(mktemp --suffix=.nft)"
   leaktest_permissive_ruleset "${ruleset_file}" "${permissive}"
   leaktest_setup "${permissive}"
   read -r count live < <(leaktest_fire_forward_probe "${proto}" "${src}" "${dst}" "${capture_file}" "$@")
   leaktest_assert_leaked "${label} (permissive forward)" "${count}" "${live}" || rc=1

   return "${rc}"
}

## Back-compat: forward-leak from the workstation's legitimate IPv6 source.
## Args: <label> <proto> <dst> [inject args].
leaktest_forward_leak_case() {
   local label="$1" proto="$2" dst="$3"
   shift 3
   leaktest_probe_case "${label}" "${proto}" "${INT_WS_IP6}" "${dst}" "$@"
}

## Positive control: a legitimate-source workstation TCP connection must be
## transparently redirected to the Tor port and answered. Returns 0 on success.
leaktest_positive_control() {
   local rc
   ## Pass the gateway IPv6 in (heredoc is single-quoted, so no shell interp);
   ## avoids duplicating INT_GW_IP6 as a literal that could silently diverge.
   rc="$(ip netns exec ws python3 - "${INT_GW_IP6}" <<'PY'
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], 443), 4)
    s.close()
    print("OK")
except Exception as exc:  # noqa: BLE001
    print("FAIL:%s" % type(exc).__name__)
PY
)"
   if [ "${rc}" = 'OK' ]; then
      return 0
   fi
   fail_case "positive control failed (legit torified path down): ${rc}"
   return 1
}

## Fail-closed case: with the Tor TransPort DEAD (nolistener), a workstation TCP
## connection must be DROPPED, never routed to the clearnet. The canary flushes
## the firewall entirely so the same traffic forwards out -- proving the harness
## detects a fail-OPEN. Returns 0 if both hold.
leaktest_fail_closed_case() {
   local rc=0 capture_file empty count live
   capture_file="$(mktemp)"

   leaktest_setup "${ruleset_file}" nolistener
   read -r count live < <(leaktest_fire_forward_probe tcp6 "${INT_WS_IP6}" "${PROBE_DST_IP6}" "${capture_file}")
   leaktest_assert_blocked 'fail-closed (Tor down -> workstation traffic dropped)' "${count}" "${live}" || rc=1

   empty="$(mktemp --suffix=.nft)"
   printf 'flush ruleset\n' >"${empty}"
   leaktest_setup "${empty}" nolistener
   read -r count live < <(leaktest_fire_forward_probe tcp6 "${INT_WS_IP6}" "${PROBE_DST_IP6}" "${capture_file}")
   leaktest_assert_leaked 'fail-closed (no firewall)' "${count}" "${live}" || rc=1

   return "${rc}"
}
