#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a TCP SYN hidden by a GENUINE two-fragment IPv4 split must still be
## caught by the transparent-proxy redirect.
##
## This is the classic transparent-proxy evasion: split the SYN so the TCP flags
## byte (offset 13 of the TCP header) lands in the SECOND fragment, so no single
## fragment on the wire shows a SYN. The multi-fragment cases elsewhere reassemble a
## UDP datagram (only the stateless forward DROP), and the ext-header hidden-SYN case
## hides the SYN via an ATOMIC fragment or an ext-header chain -- never a real
## MF=1/MF=0 two-fragment split, and with no IPv4 counterpart. Here ip_defrag (loaded
## by conntrack) must rebuild the SYN before the nat prerouting chain so the redirect
## rule (`tcp flags ... == syn ... redirect to :9040`) matches and torifies it.
##
## assert_blocked alone cannot tell "reassembled SYN correctly REDIRECTED to Tor"
## from "reassembled SYN silently DROPPED by the forward policy" (both = 0 egress),
## so the redirect-counter assertion is what actually guards the behavior. The canary
## strips the SYN redirect AND opens forward, so the reassembled SYN egresses
## un-torified -- proving the assertions would catch a reassembly/redirect miss.
##
## IPv4 ONLY, by an empirically-confirmed asymmetry: splitting the SYN to hide the
## flags leaves the first fragment with a TRUNCATED TCP header, and nf_defrag_ipv6
## refuses to reassemble a truncated-header fragment (thdr_truncated), so the IPv6
## header-split SYN is dropped as a tiny-first fragment (never reaching the redirect)
## -- already covered by ipv6_fragment_tinyfirst_test.sh. IPv4 ip_defrag has no such
## check and DOES reassemble+redirect it, which is the distinct behavior tested here.

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

## 1. Shipped ruleset: the fragmented SYN must be REDIRECTED (counter advances -- the
## ruleset reassembled and torified it) AND must not egress.
leaktest_setup "${ruleset_file}"

redirect_before="$(leaktest_transport_redirect_count)"
leaktest_fire_forward_probe frag4set "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
   "${capture_file}" --l4 tcp --dport 443
redirect_after="$(leaktest_transport_redirect_count)"
leaktest_assert_blocked 'hidden TCP SYN (IPv4 two-fragment split)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
leaktest_assert_redirected 'hidden TCP SYN (IPv4 two-fragment split)' \
   "${redirect_before}" "${redirect_after}" || rc=1

## 2. Positive control on the same topology.
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi

## 3. Canary: strip the SYN redirect AND open forward -> the reassembled hidden SYN
## egresses un-torified, proving the assertions above would catch a reassembly or
## redirect that let the fragmented SYN slip.
canary="$(mktemp --suffix=.nft)"
noredirect="$(mktemp --suffix=.nft)"
grep --invert-match 'redirect to :9040' "${ruleset_file}" >"${noredirect}"
leaktest_permissive_ruleset "${noredirect}" "${canary}"
leaktest_setup "${canary}"
leaktest_fire_forward_probe frag4set "${INT_WS_IP4}" "${PROBE_DST_IP4}" \
   "${capture_file}" --l4 tcp --dport 443
leaktest_assert_leaked 'hidden TCP SYN (IPv4 two-fragment, redirect stripped + forward open)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
