#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: forged-source IPv6 must not cause non-Tor egress.
##
## IPv6 has no rp_filter kernel equivalent, so a compromised Workstation can
## L2-inject an IPv6 SYN with a forged (global) source address. On a gateway with
## a global IPv6 default route (Non-Qubes-Whonix + accept_ra), that SYN is
## redirected to Tor's TransPort and, absent an ingress uRPF check, the un-NAT'd
## reply routes out the external interface as non-Tor traffic. The shipped
## whonix-gateway-firewall uRPF rule must drop it.
##
## Asserts three things:
##   1. with the shipped ruleset, the forged-source probe does NOT egress;
##   2. POSITIVE CONTROL: a legitimate torified TCP path still works;
##   3. CANARY: with the uRPF rule stripped, the SAME probe DOES egress -- so a
##      pass in (1) means the rule works, not that the harness is inert.

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

## Fire a forged-source SYN from <src> against the currently-loaded topology,
## printing "<egress-count> <capture-live>" via the shared helper (broad egress
## oracle). Delivery is proven by the uRPF-stripped canary below.
fire_probe_from() {
   leaktest_fire_forward_probe tcp6 "$1" "${PROBE_DST_IP6}" "${capture_file}"
}

## 1. Shipped ruleset (uRPF present) -> no egress, for the forged source and for
## other off-subnet spoofs (uRPF is general, not keyed to one address).
leaktest_setup "${ruleset_file}"
for spoof in "${PROBE_SRC_IP6}" '2001:db8:cafe::5' '::ffff:203.0.113.5'; do
   read -r count live < <(fire_probe_from "${spoof}")
   leaktest_assert_blocked "spoofed source ${spoof}" "${count}" "${live}" || rc=1
done

## 2. Positive control on the same topology.
if leaktest_positive_control; then
   msg "PASS: positive control (legit torified TCP path works)"
else
   rc=1
fi

## 3. Canary: strip the uRPF rule; the same probe must now leak.
stripped_ruleset="$(mktemp --suffix=.nft)"
grep --invert-match 'fib saddr . iif oif missing' "${ruleset_file}" >"${stripped_ruleset}"
leaktest_setup "${stripped_ruleset}"
read -r count live < <(fire_probe_from "${PROBE_SRC_IP6}")
leaktest_assert_leaked 'forged-source (uRPF stripped)' "${count}" "${live}" || rc=1

exit "${rc}"
