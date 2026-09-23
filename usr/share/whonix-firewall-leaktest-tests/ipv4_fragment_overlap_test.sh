#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: an OVERLAPPING IPv4 fragment set must not reassemble or egress.
##
## IPv4 defrag has a SEPARATE ENTRY (ip_defrag / nf_defrag_ipv4) from nf_defrag_ipv6
## but shares the overlap classification (the common inet_frag_queue_insert, rbtree-
## unified since kernel 4.18) -- so IPv4 overlap handling is verified in its own right
## (distinct trigger + header format), though the overlap-drop rule is the same as
## IPv6's, not divergent. The overlapping fragment here EXTENDS past the first
## fragment's end ([0,16) MF=1 then
## [8,22) MF=0), so ip_defrag classifies it IPFRAG_OVERLAP and inet_frag_kill
## discards the whole datagram (RFC 5722) -- the genuine overlap-kill path, not the
## IPFRAG_DUP a mere subset [8,16) would degenerate into (first fragment merely left
## in an incomplete queue). Empirically confirmed: the gw reassembles forwarded IPv4
## fragments (nf_defrag_ipv4, via the ruleset's nat/conntrack), and the overlapping
## set does not egress while the valid sibling set does.
##
## Under the shipped ruleset the forward policy-drop blocks it anyway, so the teeth
## are under a PERMISSIVE forward policy: the VALID sibling set (frag4set) egresses
## there while the OVERLAPPING set does not -- isolating ip_defrag's overlap
## rejection from a merely dead path. If IPv4 reassembly ever accepted overlaps, the
## overlapping set would egress under the permissive policy and this test would fail.

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
leaktest_fire_forward_probe frag4overlap "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
   "${capture_file}" --dport 123
leaktest_assert_blocked 'overlapping IPv4 fragments to clearnet' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

## 2. Positive control on a fresh topology.
leaktest_setup "${ruleset_file}"
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi

## 3. Permissive forward: the overlapping set STILL does not egress (ip_defrag's
## IPFRAG_OVERLAP -> inet_frag_kill discards it), while the VALID set DOES -- proving
## the harness detects an IPv4 fragment leak, so the overlap's non-egress is the
## reassembler killing the overlap, not a dead path.
permissive="$(mktemp --suffix=.nft)"
leaktest_permissive_ruleset "${ruleset_file}" "${permissive}"

leaktest_setup "${permissive}"
leaktest_fire_forward_probe frag4overlap "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
   "${capture_file}" --dport 123
leaktest_assert_blocked 'overlapping IPv4 fragments (permissive forward -- inet_frag_kill)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

leaktest_setup "${permissive}"
leaktest_fire_forward_probe frag4set "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
   "${capture_file}" --dport 123
leaktest_assert_leaked 'valid IPv4 fragment set (permissive forward -- reference)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
