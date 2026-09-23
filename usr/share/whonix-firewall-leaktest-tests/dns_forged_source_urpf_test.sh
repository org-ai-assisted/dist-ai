#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a forged-source DNS query must not cause a non-Tor DnsPort reply to
## egress.
##
## Companion to the TCP forged-source uRPF case, for the UDP/53 DnsPort path, in
## BOTH families. A compromised Workstation L2-injects a UDP/53 query with a forged
## (off-subnet) source. Whonix redirects UDP/53 to Tor's DnsPort; the DnsPort
## answers, and the un-NAT'd reply is destined to the forged source -- so without an
## ingress anti-spoof check it routes out the external interface as non-Tor DNS
## traffic. The shipped protections must drop the forged query before it is ever
## redirected: the nft uRPF rule (both families) plus kernel rp_filter (IPv4 only).
##
## (The DnsPort stub replies FROM the address the query was sent to, as a real Tor
## DnsPort bound to a specific address does, so conntrack un-NATs the reply -- see
## helpers/stub_transport.py.)

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
trap leaktest_teardown EXIT

capture_file="$(mktemp)"
rc=0

fire_dns_from() { # <proto> <src> <dst>
   leaktest_fire_forward_probe "$1" "$2" "$3" "${capture_file}" --dport 53
}

## IPv4 has a SECOND anti-spoof layer (kernel rp_filter) beyond the nft uRPF rule, so
## the IPv4 canary must clear it too or rp_filter alone keeps dropping the forged
## query (kernel uses max(all, iface)). IPv6 has no rp_filter, so its canary needs
## only the nft rule stripped.
rpfilter_off() {
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.all.rp_filter=0
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.eth1.rp_filter=0
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.default.rp_filter=0
}

## 1. Shipped ruleset (uRPF present): the forged query is dropped at prerouting
## before the DNS redirect, so no DnsPort reply egresses -- BOTH families. IPv4 is a
## distinct path: it has two anti-spoof layers (kernel rp_filter AND the nft
## dual-stack uRPF rule) that IPv6 lacks, and the DnsPort reply is un-NAT'd via
## IP_PKTINFO source-pinning (helpers/stub_transport.py), a different code path from
## the IPv6 IPV6_PKTINFO one.
leaktest_setup "${ruleset_file}"
for spoof in "${PROBE_SRC_IP6}" '2001:db8:cafe::5'; do
   fire_dns_from udp6 "${spoof}" "${PROBE_DST_IP6}"
   leaktest_assert_blocked "forged-source DNS IPv6 ${spoof}" "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
done
for spoof in '203.0.113.55' '198.18.0.9'; do
   fire_dns_from udp4 "${spoof}" "${PROBE_DST_IP4}"
   leaktest_assert_blocked "forged-source DNS IPv4 ${spoof}" "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
done

## 2. Positive control on the same topology.
if leaktest_positive_control; then
   msg "PASS: positive control (legit torified TCP path works)"
else
   rc=1
fi

## 3. Canary: strip the uRPF rule; the un-NAT'd DnsPort reply to the forged source
## must leak -- for BOTH families. The IPv4 canary is load-bearing: it proves the
## IPv4 DnsPort un-NAT reply actually reproduces (the stub's IP_PKTINFO source-pin
## works and conntrack un-NATs it), so the IPv4 blocked assertions above are the uRPF
## rule working, not a dead path.
stripped_ruleset="$(mktemp --suffix=.nft)"
grep --invert-match 'fib saddr . iif oif missing' "${ruleset_file}" >"${stripped_ruleset}"
leaktest_setup "${stripped_ruleset}"
fire_dns_from udp6 "${PROBE_SRC_IP6}" "${PROBE_DST_IP6}"
leaktest_assert_leaked 'forged-source DNS IPv6 (uRPF stripped)' "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
leaktest_setup "${stripped_ruleset}"
rpfilter_off
fire_dns_from udp4 '203.0.113.55' "${PROBE_DST_IP4}"
leaktest_assert_leaked 'forged-source DNS IPv4 (uRPF stripped + rp_filter off)' "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
