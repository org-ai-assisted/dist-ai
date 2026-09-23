#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: a TCP SYN hidden one hop down an IPv6 extension-header / fragment
## chain must still be caught by the transparent-proxy redirect.
##
## The ext-header and atomic-fragment cases elsewhere hide a UDP datagram, which
## exercises only the stateless forward DROP. The stateful redirect
## (`tcp flags ... == syn ... redirect to :9040`) is a more attractive target for
## the "hide the real L4 down the chain" evasion: if it failed to walk the chain to
## find the SYN, the SYN would be forwarded un-torified instead of redirected to
## Tor. The gateway must redirect it regardless of the header chain. Canary strips
## the SYN redirect AND opens forward, so the hidden SYN egresses -- proving the
## test would catch a redirect that mis-parses the chain.

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

## <proto> [extra inject flags, e.g. --exthdr routing]
fire_hidden_syn() {
   local proto="$1"
   shift
   leaktest_fire_forward_probe "${proto}" "${INT_WS_IP6}" "${PROBE_DST_IP6}" \
      "${capture_file}" "$@" --l4 tcp --dport 443
}

## 1. Shipped ruleset: each hidden-SYN shape is redirected to Tor (no clearnet egress).
leaktest_setup "${ruleset_file}"
for shape in "frag6" "exthdr6 --exthdr routing" "exthdr6 --exthdr hopopts" "exthdr6 --exthdr dstopts"; do
   # shellcheck disable=SC2086 # split the shape into proto + flags on purpose
   set -- ${shape}
   fire_hidden_syn "$@"
   leaktest_assert_blocked "hidden TCP SYN (${shape})" \
      "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1
done

## 2. Positive control on the same topology.
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi

## 3. Canary: strip the SYN redirect AND open forward -> the hidden SYN egresses,
## proving the assertions above would catch a redirect that mis-parses the chain.
canary="$(mktemp --suffix=.nft)"
noredirect="$(mktemp --suffix=.nft)"
grep --invert-match 'redirect to :9040' "${ruleset_file}" >"${noredirect}"
leaktest_permissive_ruleset "${noredirect}" "${canary}"
leaktest_setup "${canary}"
fire_hidden_syn exthdr6 --exthdr routing
leaktest_assert_leaked 'hidden TCP SYN (redirect stripped + forward open)' \
   "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
