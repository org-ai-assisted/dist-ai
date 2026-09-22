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

helpers_dir="$(leaktest_helpers_dir)"
capture_file="$(mktemp)"
probe_bpf="ip6 and (host ${PROBE_SRC_IP6} or host ${PROBE_DST_IP6}) and tcp"
rc=0

## Fire the forged-source probe against the currently-loaded topology and print
## how many probe-tagged packets reached the upstream sink.
fire_forged_probe() {
   leaktest_capture_up "${probe_bpf}" 6 "${capture_file}"
   sleep 1
   ip netns exec ws python3 "${helpers_dir}/inject.py" \
      --proto tcp6 --iface eth0 --gw4 "${INT_GW_IP4}" \
      --src "${PROBE_SRC_IP6}" --dst "${PROBE_DST_IP6}" >/dev/null 2>&1
   sleep 3
   leaktest_capture_wait
   leaktest_egress_count "${capture_file}"
}

## 1. Shipped ruleset (uRPF present) -> no egress.
leaktest_setup "${ruleset_file}"
egressed="$(fire_forged_probe)"
if [ "${egressed}" -ne 0 ]; then
   fail_case "forged-source IPv6 egressed the gateway (${egressed} pkt(s)) with the shipped ruleset" || rc=1
else
   msg "PASS: forged-source IPv6 blocked (0 egress)"
fi

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
egressed="$(fire_forged_probe)"
if [ "${egressed}" -gt 0 ]; then
   msg "PASS: canary reproduced the leak without uRPF (${egressed} pkt(s)); test has teeth"
else
   fail_case "canary: leak did NOT reproduce without the uRPF rule -- the harness proves nothing" || rc=1
fi

exit "${rc}"
