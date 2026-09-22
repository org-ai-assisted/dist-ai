#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: arbitrary IP protocols and IP-in-IP tunnels must not egress.
##
## Tor carries only the transparently-proxied TCP (and DNS); every other IP
## protocol number must hit the gateway FORWARD drop, and the classic IPv6
## tunnels a "native IPv6 is blocked" assumption misses -- 6to4/SIT (IPv4
## protocol 41) and Teredo (IPv6 in UDP/3544) -- must be dropped too. Each case
## carries a positive control and a permissive-forward canary.

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

rc=0

## Representative non-TCP IPv6 protocols (GRE, ESP, OSPF): none may forward.
for protonum in 47 50 89; do
   leaktest_probe_case \
      "IPv6 protocol ${protonum} to clearnet" rawip6 "${INT_WS_IP6}" "${PROBE_DST_IP6}" \
      "ip6 and host ${PROBE_DST_IP6}" --protonum "${protonum}" || rc=$?
done

## 6to4 / SIT: IPv4 protocol 41 carrying IPv6.
leaktest_probe_case \
   '6to4 tunnel (IPv4 protocol 41) to clearnet' rawip4 "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
   "ip and host ${PROBE_DST_IP4}" --protonum 41 || rc=$?

## Teredo: IPv6 encapsulated in UDP/3544 to a relay.
leaktest_probe_case \
   'Teredo (UDP/3544) to clearnet' udp4 "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
   "ip and host ${PROBE_DST_IP4}" --dport 3544 || rc=$?

exit "${rc}"
