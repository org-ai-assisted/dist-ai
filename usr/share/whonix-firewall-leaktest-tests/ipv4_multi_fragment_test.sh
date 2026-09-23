#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: an IPv4 UDP datagram SPLIT across two fragments must not egress.
##
## IPv4 defrag has a SEPARATE ENTRY (ip_defrag / nf_defrag_ipv4) from the IPv6
## nf_defrag_ipv6 -- distinct trigger, header format, and CVE history (FragmentSmack,
## CVE-2018-5391), though it shares the overlap classification (inet_frag_queue_insert,
## rbtree-unified since kernel 4.18) -- so IPv4 is exercised in its own right here, not
## by analogy. The gw ruleset's nat/conntrack
## pulls in nf_defrag_ipv4, so the gateway DOES reassemble forwarded IPv4 fragments
## before the forward chain (re-fragmenting to the original boundaries on egress via
## frag_max_size, so a permissive egress still shows two fragments), exactly as the
## IPv6 side reassembles: splitting a datagram cannot smuggle it past the forward
## drop. Empirically confirmed -- a lone incomplete first fragment is HELD (never
## egresses), and only a completed set is forwarded. Overlap rejection is a distinct
## behavior and is covered separately (ipv4_fragment_overlap_test.sh).
##
## The permissive-forward canary is load-bearing: it egresses the reassembled set,
## proving the harness detects an IPv4 fragment leak -- so the blocked assertion is
## the forward drop working, not a dead path.

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

## frag4set emits both fragments back-to-back per fire; leaktest_probe_case does the
## blocked (shipped) + positive-control + permissive-canary sequence. dport 123
## (NTP): Tor carries no UDP but DNS, so the reassembled datagram must drop.
leaktest_probe_case \
   'IPv4 multi-fragment UDP (reassembled before forward) to clearnet' \
   frag4set "${INT_WS_IP4}" "${PROBE_DST_IP4}" --dport 123
