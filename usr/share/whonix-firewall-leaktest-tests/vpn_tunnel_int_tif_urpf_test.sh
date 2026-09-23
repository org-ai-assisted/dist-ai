#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a forged-source packet to the Tor DnsPort on the VPN-tunnel interface
## (INT_TIF = tun0, distinct from INT_IF = eth1) must not cause a non-Tor reply to
## egress.
##
## When the Workstation reaches the Gateway over a VPN tunnel, the Tor DnsPort /
## Control / Socks ports are ACCEPTED directly on the tunnel interface tun0 (INT_TIF)
## -- the generated rule is `iifname tun0 udp dport 5300 accept` -- while eth1
## (INT_IF) carries the TransPort/DnsPort REDIRECTs. The uRPF anti-spoof drop must
## guard tun0 too: else a forged-source packet arriving on tun0 at the DnsPort is
## accepted with no reverse-path check, the DnsPort answers, and the reply routes out
## the external interface to the forged clearnet source. This is the BEHAVIORAL
## companion to whonix-firewall's ruleset-level test_gateway_int_tif assertion (which
## only checks the rule text is generated).
##
## Loads the gateway-int-tif fixture (INT_IF=eth1 INT_TIF=tun0) into gw and adds a
## tun0 tunnel topology; the probe targets the gateway's own tun0 address at the
## DnsPort (5300). The canary strips the tun0 uRPF (and rp_filter for IPv4) so the
## reply DOES leak -- proving the harness detects a tun0 leak, so the blocked
## assertion is the tun0 uRPF working, not a dead path.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

lib_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
# shellcheck source=./leaktest_lib.sh
source "${lib_dir}/leaktest_lib.sh"

leaktest_preconditions

## The INT_TIF fixture is a distinct generated ruleset (INT_IF != INT_TIF). Skip
## cleanly if the pinned whonix-firewall checkout does not ship it yet -- it lands in
## a separate whonix-firewall change; this is a genuinely optional target, not the
## all-skip fabricated-green the runner guards against.
int_tif_ruleset="${WHONIX_FIREWALL_REPO:-}/test-output/new/gateway-int-tif.nft"
if [ ! -r "${int_tif_ruleset}" ]; then
   skip_case "INT_TIF (gateway-int-tif) fixture not present: ${int_tif_ruleset}"
fi

trap leaktest_teardown EXIT

capture_file="$(mktemp)"
rc=0

## Fire a forged-source packet to the gateway's Tor DnsPort (5300), ARRIVING ON tun0
## (the gateway's INT_TIF), via the fire-helper's inject-interface override. The dst
## is the gateway's OWN tun0 address (the port is accepted on INPUT, not forwarded).
fire_tun_dnsport() { # <proto> <src> <dst-gw-tun-addr>
   LEAKTEST_INJECT_IFACE='tun0' LEAKTEST_INJECT_GW4="${TUN_GW_IP4}" \
      leaktest_fire_forward_probe "$1" "$2" "$3" "${capture_file}" --dport 5300
}

## 1. Shipped INT_TIF ruleset: the tun0 uRPF drops the forged-source packet at
## prerouting (before the DnsPort accept), so nothing reaches the DnsPort -- for BOTH
## families (the uRPF rule `iifname tun0 fib saddr . iif oif missing` is a single
## dual-stack rule that keys on the reverse-path FIB, so a forged clearnet source of
## either family whose reverse path is eth0, not tun0, is dropped).
leaktest_setup_int_tif "${int_tif_ruleset}"
for spoof in "${PROBE_SRC_IP6}" '2001:db8:cafe::5'; do
   fire_tun_dnsport udp6 "${spoof}" "${TUN_GW_IP6}"
   leaktest_assert_blocked "forged-source DnsPort on tun0 IPv6 ${spoof}" \
      "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
done
for spoof in '203.0.113.55' '198.18.0.9'; do
   fire_tun_dnsport udp4 "${spoof}" "${TUN_GW_IP4}"
   leaktest_assert_blocked "forged-source DnsPort on tun0 IPv4 ${spoof}" \
      "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
done

## 2. Positive control (the standard eth1 TransPort path still works under this
## ruleset -- a family-scoped or INT_TIF-scoped breakage would show here).
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi

## 3. Canary (IPv6): strip the tun0 uRPF -> the forged-source packet reaches the
## DnsPort accept, the DnsPort answers, and the reply egresses to the forged clearnet
## source. This proves the harness detects a tun0 leak, so the blocked assertions
## above are the tun0 uRPF working, not a dead path. Since that uRPF is ONE dual-stack
## rule, this equally establishes the teeth for the IPv4 blocked assertions.
##
## The canary is IPv6 only by an unavoidable routing reality, NOT a coverage gap: a
## DIRECT DnsPort access is not DNAT'd, so the reply's source is the gateway's own
## tun0 address (private, 10.152.153.x for IPv4 / a ULA for IPv6). IPv4 will not
## egress a private-source packet to a clearnet destination, so an IPv4 reply never
## leaves the box even with uRPF stripped; the IPv6 ULA source does egress, so IPv6 is
## the family that can demonstrate the leak. (The IPv4 un-NAT reply path IS canaried
## end-to-end on the eth1 side by dns_forged_source_urpf_test.sh, where the redirect
## restores a clearnet reply source.)
stripped="$(mktemp --suffix=.nft)"
grep --invert-match 'iifname tun0 fib saddr . iif oif missing' "${int_tif_ruleset}" >"${stripped}"
leaktest_setup_int_tif "${stripped}"
fire_tun_dnsport udp6 "${PROBE_SRC_IP6}" "${TUN_GW_IP6}"
leaktest_assert_leaked 'forged-source DnsPort on tun0 IPv6 (tun0 uRPF stripped)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
