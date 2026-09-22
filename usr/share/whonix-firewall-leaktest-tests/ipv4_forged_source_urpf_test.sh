#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: forged-source IPv4 must not cause non-Tor egress.
##
## Companion to the IPv6 forged-source case. IPv4 has two independent
## anti-spoofing protections on a Whonix gateway: the kernel rp_filter (set by
## security-misc) AND the shipped dual-stack nft uRPF rule. A compromised
## Workstation can L2-inject an IPv4 TCP SYN with a forged (off-subnet) source; if
## it were redirected to Tor's TransPort, the un-NAT'd SYN-ACK would route out the
## external interface as non-Tor traffic. Both protections must drop it.
##
## Asserts:
##   1. shipped ruleset (uRPF + rp_filter) -> forged-source probes do NOT egress;
##   2. FIREWALL ALONE: with rp_filter disabled, the dual-stack uRPF rule still
##      drops the spoof -- the rule does not depend on the kernel knob;
##   3. POSITIVE CONTROL: a legitimate torified path still works;
##   4. CANARY: with BOTH protections removed (uRPF stripped + rp_filter off), the
##      SAME probe DOES egress -- so a pass above means the protections work, not
##      that the harness is inert.

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
## Off-subnet spoofs (documentation/benchmark ranges; never routable via eth1).
forged_srcs=('203.0.113.55' '198.18.0.9' '192.0.2.200')

fire4() {
   leaktest_fire_forward_probe tcp4 "$1" "${PROBE_DST_IP4}" "${capture_file}"
}

## Disable rp_filter on the ingress path so a scenario can isolate the nft uRPF
## rule (kernel uses max(all, iface), so both must be cleared).
rpfilter_off() {
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.all.rp_filter=0
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.eth1.rp_filter=0
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.default.rp_filter=0
}

## 1. Shipped ruleset -> no egress for the forged source and other off-subnet
## spoofs (uRPF is general, not keyed to one address).
leaktest_setup "${ruleset_file}"
for spoof in "${forged_srcs[@]}"; do
   read -r count live < <(fire4 "${spoof}")
   leaktest_assert_blocked "IPv4 spoofed source ${spoof}" "${count}" "${live}" || rc=1
done

## 2. Firewall alone: rp_filter disabled, the dual-stack uRPF rule still drops it.
leaktest_setup "${ruleset_file}"
rpfilter_off
read -r count live < <(fire4 "${forged_srcs[0]}")
leaktest_assert_blocked 'IPv4 spoof, rp_filter off (uRPF rule alone)' "${count}" "${live}" || rc=1

## 3. Positive control on the same topology.
if leaktest_positive_control; then
   msg "PASS: positive control (legit torified TCP path works)"
else
   rc=1
fi

## 4. Canary: remove BOTH protections; the same probe must now leak.
stripped_ruleset="$(mktemp --suffix=.nft)"
grep --invert-match 'fib saddr . iif oif missing' "${ruleset_file}" >"${stripped_ruleset}"
leaktest_setup "${stripped_ruleset}"
rpfilter_off
read -r count live < <(fire4 "${forged_srcs[0]}")
leaktest_assert_leaked 'IPv4 forged-source (uRPF stripped + rp_filter off)' "${count}" "${live}" || rc=1

exit "${rc}"
