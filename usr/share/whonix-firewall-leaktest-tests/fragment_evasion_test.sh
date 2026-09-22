#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a fragmented IPv6 packet must not slip past the gateway.
##
## A packet carrying an IPv6 fragment extension header (here an atomic fragment
## wrapping a UDP datagram) is a classic firewall-evasion shape: a stateless
## filter that only inspects the first bytes can be tricked. The gateway must
## drop it like any other forwarded packet. Positive control + permissive-forward
## canary as in the other cases.

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
leaktest_probe_case \
   'fragmented IPv6 (fragment header) to clearnet' frag6 "${INT_WS_IP6}" "${PROBE_DST_IP6}" \
   "ip6 and host ${PROBE_DST_IP6}" --dport 443 || rc=$?
exit "${rc}"
