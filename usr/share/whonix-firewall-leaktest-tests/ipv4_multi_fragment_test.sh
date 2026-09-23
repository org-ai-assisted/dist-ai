#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: an IPv4 UDP datagram SPLIT across two fragments must not egress.
##
## IPv4 reassembly (ip_defrag) is a SEPARATE code path from the IPv6 nf_defrag_ipv6
## -- with its own overlap policy (RFC 791 predates RFC 5722's drop-on-overlap
## mandate) and its own CVE history (FragmentSmack, CVE-2018-5391) -- so IPv4 is
## exercised in its own right here, not by analogy. Empirically the gateway does NOT
## reassemble FORWARDED IPv4 fragments (unlike the IPv6 side): they pass through
## individually, each keeping the datagram's original IP id. So every fragment is a
## forwarded IP packet the forward drop must catch. Overlap rejection is a distinct
## behavior and is covered separately (ipv4_fragment_overlap_test.sh).
##
## The permissive-forward canary is load-bearing: it egresses the fragments, proving
## the harness detects an IPv4 fragment leak -- so the blocked assertion is the
## forward drop working, not a dead path.

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
## (NTP): Tor carries no UDP but DNS, so the forwarded fragments must drop.
leaktest_probe_case \
   'IPv4 multi-fragment UDP (forwarded individually) to clearnet' \
   frag4set "${INT_WS_IP4}" "${PROBE_DST_IP4}" --dport 123
