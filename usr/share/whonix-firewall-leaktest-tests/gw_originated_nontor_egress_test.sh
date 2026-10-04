#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: the GATEWAY's OWN traffic (filter OUTPUT chain) must not reach the
## clearnet non-Tor. Every other case in this suite is workstation-sourced
## (FORWARD chain); this is the only one exercising the gateway's own egress.
##
## Threat: a NON-Tor process on the Gateway (uid 0 -- not debian-tor / skuid 103)
## reaching the clearnet directly, bypassing Tor. The shipped Non-Qubes OUTPUT
## chain drops that, while deliberately ACCEPTING the Gateway's own traffic to the
## NON_TOR_GATEWAY destinations (host DNS proxy 10.0.2.3, the LAN 192.168.x) -- the
## documented "Deactivate Host DNS" / LAN exception, empty on Qubes. That accepted
## egress is a REAL non-Tor leak the netns oracle used to miss BY CONSTRUCTION (it
## excluded all 10.0.2.0/24 unicast); the oracle is now DHCP-scoped so it sees it.
##
## Must originate from a real kernel socket (leaktest_fire_gw_origin), not the
## anon-leak-inject AF_PACKET crafter, which bypasses the OUTPUT hook.
##
## Asserts:
##   1. shipped ruleset -> gw-originated clearnet (v4 + v6) does NOT egress (OUTPUT
##      reject);
##   2. ORACLE TEETH: gw-originated host-DNS 10.0.2.3:53 and LAN 192.168.1.5:53
##      (the NON_TOR OUTPUT exceptions) DO egress and the tightened oracle SEES
##      them -- the "Deactivate Host DNS" leak is now visible, not invisible;
##   3. ORACLE PRECISION: gw-originated DHCP (udp 68->67) stays EXCLUDED -- the
##      oracle tightening is DHCP-scoped, not "capture every 10.0.2.0/24 unicast";
##   4. POSITIVE CONTROL: a legitimate torified workstation path still works;
##   5. CANARY: with the OUTPUT chain made permissive, the SAME gw-originated
##      clearnet datagram DOES egress -- so the block in (1) is the firewall, not
##      an inert harness.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

lib_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
## The nonqubes extension sources leaktest_lib.sh itself.
# shellcheck source=./leaktest_lib_nonqubes.sh
source "${lib_dir}/leaktest_lib_nonqubes.sh"

leaktest_preconditions
trap leaktest_nonqubes_cleanup EXIT

capture_file="$(mktemp)"
rc=0

## 1. Shipped ruleset: a non-Tor gateway socket to the clearnet is rejected by the
## OUTPUT chain, both families.
leaktest_setup_gw_origin "${ruleset_file}"
leaktest_fire_gw_origin 4 "${PROBE_DST_IP4}" 443 0 "${capture_file}"
leaktest_assert_blocked 'GW-originated IPv4 clearnet (OUTPUT reject)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
leaktest_fire_gw_origin 6 "${PROBE_DST_IP6}" 443 0 "${capture_file}"
leaktest_assert_blocked 'GW-originated IPv6 clearnet (OUTPUT reject)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

## 2. Oracle teeth: the NON_TOR OUTPUT exceptions egress by design and the
## tightened oracle now SEES them (host DNS proxy + LAN).
leaktest_setup_gw_origin "${ruleset_file}"
leaktest_fire_gw_origin 4 '10.0.2.3' 53 0 "${capture_file}"
leaktest_assert_leaked 'GW-originated host-DNS 10.0.2.3:53 (NON_TOR exception, now visible)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
leaktest_fire_gw_origin 4 '192.168.1.5' 53 0 "${capture_file}"
leaktest_assert_leaked 'GW-originated LAN 192.168.1.5:53 (NON_TOR exception, visible)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

## 3. Oracle precision: DHCP between the link endpoints stays excluded (the
## tightening is DHCP-scoped, not blanket-/24). An absorber on up:67 stands in for
## the DHCP server so the probe is received, not port-closed (a closed port would
## emit an ICMP unreachable the oracle counts). Must read ZERO egress.
leaktest_setup_gw_origin "${ruleset_file}"
leaktest_up_udp_sink_start 67
leaktest_fire_gw_origin 4 "${EXT_UP_IP4}" 67 68 "${capture_file}"
leaktest_assert_blocked 'GW-originated DHCP (udp 68->67) stays oracle-excluded' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
leaktest_up_udp_sink_stop

## 4. Positive control on a fresh topology.
leaktest_setup_gw_origin "${ruleset_file}"
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi

## 5. Canary: OUTPUT made permissive -> the same clearnet datagram now egresses,
## BOTH families -- so a silently broken IPv6 harness (e.g. a swallowed routing
## error) cannot leave the v6 blocked leg above untested.
output_permissive="$(mktemp --suffix=.nft)"
leaktest_output_permissive_ruleset "${ruleset_file}" "${output_permissive}"
leaktest_setup_gw_origin "${output_permissive}"
leaktest_fire_gw_origin 4 "${PROBE_DST_IP4}" 443 0 "${capture_file}"
leaktest_assert_leaked 'GW-originated IPv4 clearnet (OUTPUT permissive)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
leaktest_fire_gw_origin 6 "${PROBE_DST_IP6}" 443 0 "${capture_file}"
leaktest_assert_leaked 'GW-originated IPv6 clearnet (OUTPUT permissive)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
