#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit test: leaktest_transport_redirect_count must survive a TRANSIENT nft read
## failure and return the true counter, not 0.
##
## The redirect counter feeds leaktest_assert_redirected (after > before). If a
## transient `nft list chain` failure under sandbox load returned 0, then after=0
## would read as < before -- a FALSE "SYN did not reach the redirect" verdict on a
## SYN that was in fact torified (observed as a flaky hidden-SYN failure). The
## helper retries the read, so a flake resolves to the real count. This test drives
## the REAL helper with a mocked `ip` that fails the first reads then succeeds.
##
## Root-free: it only sources the library (function defs, no netns) and overrides
## `ip`; it does not build a topology.

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

rc=0

## A chain listing exactly as `nft list chain inet nat prerouting` prints the
## redirect rule, with a known packet count to parse.
fake_chain='table inet nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth1" tcp flags & (fin | syn | rst | ack) == syn counter packets 7 bytes 336 redirect to :9040
	}
}'

## Mock `ip`: fail the first two reads (transient), succeed on the third. The real
## helper reads via a command substitution -- a fresh subshell per attempt -- so
## the invocation counter must live in a FILE to persist across those subshells (a
## shell variable would reset to 0 every attempt).
## mktemp scratch (left for the ephemeral tmp, as the rest of the suite does).
call_counter="$(mktemp)"
printf '0' > "${call_counter}"
## shellcheck cannot see that the helper resolves bare `ip` to this function at
## runtime (via `ip netns exec ...` inside a command substitution), so it marks the
## body unreachable -- it is not.
# shellcheck disable=SC2317
ip() {
   local n
   n="$(cat -- "${call_counter}")"
   n=$((n + 1))
   printf '%s' "${n}" > "${call_counter}"
   if [ "${n}" -lt 3 ]; then
      return 1
   fi
   printf '%s\n' "${fake_chain}"
}

got="$(leaktest_transport_redirect_count)"
calls="$(cat -- "${call_counter}")"
if [ "${got}" = '7' ]; then
   printf '%s\n' "PASS: transient nft failure retried to true count (attempts=${calls}, count=${got})"
else
   printf '%s\n' "FAIL: transient nft failure returned '${got}', expected 7 (attempts=${calls})"
   rc=1
fi

## A genuinely unavailable read (never succeeds) must still return 0 without
## aborting the caller -- the non-fatal contract.
printf '0' > "${call_counter}"
# shellcheck disable=SC2317
ip() {
   local n
   n="$(cat -- "${call_counter}")"
   printf '%s' "$((n + 1))" > "${call_counter}"
   return 1
}

got="$(leaktest_transport_redirect_count)"
calls="$(cat -- "${call_counter}")"
if [ "${got}" = '0' ]; then
   printf '%s\n' "PASS: persistent nft failure returns 0 non-fatally (attempts=${calls})"
else
   printf '%s\n' "FAIL: persistent nft failure returned '${got}', expected 0"
   rc=1
fi

exit "${rc}"
