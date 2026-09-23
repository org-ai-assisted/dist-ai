#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a TINY-FIRST-FRAGMENT set (RFC 7112) must not smuggle a datagram past
## the forward drop.
##
## RFC 7112 requires the first fragment to carry the entire header chain (through
## the L4 header) so a stateless inspector cannot be evaded by splitting the header
## across fragments. Linux nf_defrag_ipv6 does NOT reject such a set (verified: a
## first fragment holding only 8 of the 20 TCP header bytes is still reassembled),
## but that is safe here: conntrack reassembles BEFORE the forward chain, so the
## ruleset acts on the whole reassembled datagram, not the header-split fragments.
## The reassembled datagram (a non-SYN TCP segment -- not redirected) hits the
## forward drop; the permissive canary egresses it, proving the fragments really
## reassembled (so the blocked case is the forward drop, not a stalled reassembly).

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
   'IPv6 tiny-first-fragment (header split, reassembled) to clearnet' \
   frag6tinyfirst "${INT_WS_IP6}" "${PROBE_DST_IP6}" --dport 443
