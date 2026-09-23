#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a UDP datagram SPLIT across two IPv6 fragments must not slip past
## the forward drop by fragmentation.
##
## conntrack loads nf_defrag_ipv6, which reassembles a fragmented datagram BEFORE
## the forward chain sees it -- so the ruleset acts on the reassembled datagram,
## not on the individual fragments. A filter that only inspected a lone fragment
## (the non-first one carries no L4 header) could be fooled into forwarding the
## pieces; the reassembly closes that. This fires a non-DNS UDP datagram
## (dport 123, NTP) as TWO fragments (offset 0 M=1 + offset 8 M=0, same id): the
## reassembled datagram must hit the forward reject, not egress.
##
## The permissive-forward canary is load-bearing here: it must egress the
## reassembled datagram, which proves the two fragments DID reassemble and
## forward -- so the blocked assertion above is the forward DROP working, not the
## fragments merely stalling in the reassembly buffer (which would be a silent
## false pass).

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

## frag6set emits both fragments back-to-back per fire; leaktest_probe_case does
## the blocked (shipped) + positive-control + permissive-canary sequence. dport
## 123 (NTP): Tor carries no UDP but DNS, so the reassembled datagram must drop.
leaktest_probe_case \
   'IPv6 multi-fragment UDP (reassembled) to clearnet' \
   frag6set "${INT_WS_IP6}" "${PROBE_DST_IP6}" --dport 123
