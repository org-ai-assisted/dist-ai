#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: an OVERLAPPING IPv6 fragment set (RFC 5722) must not reassemble or
## egress.
##
## RFC 5722 requires a reassembler to DROP the entire datagram if any fragments
## overlap; nf_defrag_ipv6 (loaded by conntrack) implements this. So a workstation
## cannot smuggle a datagram past the forward filter by overlapping fragments to
## confuse reassembly -- the overlap is dropped before the forward chain.
##
## Under the shipped ruleset the forward policy-drop blocks it anyway, so the teeth
## are under a PERMISSIVE forward policy: a VALID two-fragment set (frag6overlap's
## non-overlapping sibling frag6set) DOES egress there, but the OVERLAPPING set
## still does NOT -- isolating nf_defrag's overlap rejection from a merely dead
## path. If a reassembler ever accepted overlaps, the overlapping set would egress
## under the permissive policy and this test would fail.

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

## 1. Shipped ruleset: the overlapping set does not egress.
leaktest_setup "${ruleset_file}"
leaktest_fire_forward_probe frag6overlap "${INT_WS_IP6}" "${PROBE_DST_IP6}" \
   "${capture_file}" --dport 123
leaktest_assert_blocked 'overlapping IPv6 fragments to clearnet' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

## 2. Positive control on a fresh topology.
leaktest_setup "${ruleset_file}"
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi

## 3. Permissive forward: the overlapping set STILL does not egress (nf_defrag
## drops it on overlap), while the VALID fragment set DOES -- proving the harness
## detects a fragment leak, so the overlap's non-egress is the reassembler
## rejecting the overlap, not a dead path.
permissive="$(mktemp --suffix=.nft)"
leaktest_permissive_ruleset "${ruleset_file}" "${permissive}"

leaktest_setup "${permissive}"
leaktest_fire_forward_probe frag6overlap "${INT_WS_IP6}" "${PROBE_DST_IP6}" \
   "${capture_file}" --dport 123
leaktest_assert_blocked 'overlapping IPv6 fragments (permissive forward -- nf_defrag drops)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

leaktest_setup "${permissive}"
leaktest_fire_forward_probe frag6set "${INT_WS_IP6}" "${PROBE_DST_IP6}" \
   "${capture_file}" --dport 123
leaktest_assert_leaked 'valid IPv6 fragment set (permissive forward -- reference)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
