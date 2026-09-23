#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a TINY-FIRST-FRAGMENT set (RFC 7112) must not egress.
##
## RFC 7112 requires the first fragment to carry the entire header chain (through
## the L4 header) so a stateless inspector cannot be evaded by splitting the header
## across fragments. Linux nf_defrag_ipv6 does NOT reassemble such a set: the first
## fragment holds only 8 of the 20-byte TCP header, so its transport header is
## truncated and nf_ct_frag6_gather does not complete reassembly -- unlike a lone
## NON-first fragment (which is held), the truncated FIRST fragment is forwarded
## as-is. The forward chain therefore sees the fragment, not a reassembled
## datagram, and the shipped forward drop catches it. The permissive canary
## egresses that fragment, proving the forward chain (not a defrag stall) is what
## blocks it under the shipped ruleset.

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

leaktest_probe_case \
   'IPv6 tiny-first-fragment (truncated header, not reassembled) to clearnet' \
   frag6tinyfirst "${INT_WS_IP6}" "${PROBE_DST_IP6}" --dport 443
