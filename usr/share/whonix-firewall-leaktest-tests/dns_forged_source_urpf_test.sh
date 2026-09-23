#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a forged-source DNS query must not cause a non-Tor DnsPort reply to
## egress.
##
## Companion to the TCP forged-source uRPF case, for the UDP/53 DnsPort path. A
## compromised Workstation L2-injects a UDP/53 query with a forged (global) IPv6
## source. Whonix redirects UDP/53 to Tor's DnsPort; the DnsPort answers, and the
## un-NAT'd reply is destined to the forged global source -- so without an ingress
## uRPF check it routes out the external interface as non-Tor DNS traffic. The
## shipped uRPF rule must drop the forged query before it is ever redirected.
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

fire_dns_from() {
   leaktest_fire_forward_probe udp6 "$1" "${PROBE_DST_IP6}" "${capture_file}" --dport 53
}

## 1. Shipped ruleset (uRPF present): the forged query is dropped at prerouting
## before the DNS redirect, so no DnsPort reply egresses.
leaktest_setup "${ruleset_file}"
for spoof in "${PROBE_SRC_IP6}" '2001:db8:cafe::5'; do
   fire_dns_from "${spoof}"
   leaktest_assert_blocked "forged-source DNS ${spoof}" "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
done

## 2. Positive control on the same topology.
if leaktest_positive_control; then
   msg "PASS: positive control (legit torified TCP path works)"
else
   rc=1
fi

## 3. Canary: strip the uRPF rule; the DnsPort reply to the forged source must leak.
stripped_ruleset="$(mktemp --suffix=.nft)"
grep --invert-match 'fib saddr . iif oif missing' "${ruleset_file}" >"${stripped_ruleset}"
leaktest_setup "${stripped_ruleset}"
fire_dns_from "${PROBE_SRC_IP6}"
leaktest_assert_leaked 'forged-source DNS (uRPF stripped)' "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
