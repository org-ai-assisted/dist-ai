#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: an IPv4 packet bearing an LSRR source-route option (IHL>5) must not
## egress the gateway.
##
## Classic source-routing lets a host dictate the forwarding path, bypassing
## routing policy on a router that honors it. The Linux kernel already refuses to
## forward source-routed packets by default (net.ipv4.conf.*.accept_source_route=0
## -- verified: with the sysctl at its default, the packet does NOT forward even
## under a permissive firewall). That kernel sysctl is defense-in-depth, NOT the
## layer under test here: this test asserts the FIREWALL independently drops the
## packet, so a gateway that ever had source-routing re-enabled at the kernel
## (misconfig, downgrade, hostile sysctl) is STILL covered.
##
## To isolate the firewall, accept_source_route is turned ON in the gw netns for
## every fire (removing the kernel's own drop). The shipped forward policy-drop
## must then block the packet; the permissive-forward canary must egress it --
## which also proves the kernel really did forward it once permitted, so the
## blocked assertion is the firewall working, not the kernel silently dropping.
## The option is a COMPLETED route (pointer past the last entry), so the packet is
## a normal forward to dst that merely carries IP options (IHL>5): a forward rule
## accidentally keyed on IHL=5 would miss it.

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

## Enable source-route forwarding in gw so the KERNEL is not the thing dropping
## the packet -- the firewall is the sole barrier under test. Must run after every
## leaktest_setup (each rebuilds the netns and resets sysctls). accept_source_route
## is a logical AND of `all` and the ingress interface, so both are set.
enable_source_route() {
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.all.accept_source_route=1
   ip netns exec gw sysctl --quiet --write net.ipv4.conf.eth1.accept_source_route=1
}

fire_srcroute() {
   leaktest_fire_forward_probe srcroute4 "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
      "${capture_file}" --dport 123
}

## 1. Shipped ruleset (kernel source-route ON): the firewall must drop it.
leaktest_setup "${ruleset_file}"
enable_source_route
fire_srcroute
leaktest_assert_blocked 'IPv4 LSRR source-route (IHL>5) to clearnet' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

## 2. Positive control on a fresh topology.
leaktest_setup "${ruleset_file}"
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi

## 3. Canary: permissive forward + kernel source-route ON -> the packet egresses,
## proving the harness detects a source-routed leak (and that the kernel forwarded
## it once permitted, so the blocked case was the firewall's doing).
permissive="$(mktemp --suffix=.nft)"
leaktest_permissive_ruleset "${ruleset_file}" "${permissive}"
leaktest_setup "${permissive}"
enable_source_route
fire_srcroute
leaktest_assert_leaked 'IPv4 LSRR source-route (permissive forward)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
