#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Workstation DNS (UDP/53) must be transparently REDIRECTED to the Tor DnsPort,
## not forwarded to a clearnet resolver -- over BOTH IPv4 and IPv6.
##
## Two independent assertions, each family:
##   POSITIVE CONTROL -- a legit UDP/53 query is answered by the DnsPort stub (the
##     DNAT rule is present and working);
##   NO EGRESS -- the query never reaches the upstream sink (it is redirected, not
##     forwarded to the clearnet), checked with the egress oracle.
## CANARY strips the UDP/53 redirect AND opens the forward policy: the query must
## then egress the gateway, proving both assertions would catch a removed redirect
## (nothing else in the suite sends UDP/53 -- udp_nondns_forward_test deliberately
## excludes it).

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

## Print OK if a legit UDP/53 query to <dst> (v4 or v6, inferred by python) is
## answered (redirected to the DnsPort stub and un-NAT'd back), else NOREPLY.
dns_answered() {
   ip netns exec ws python3 - "$1" <<'PY'
import socket, sys
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.settimeout(4)
try:
    sock.sendto(b"\x00\x00", (sys.argv[1], 53))
    sock.recvfrom(512)
    print("OK")
except Exception:  # noqa: BLE001
    print("NOREPLY")
finally:
    sock.close()
PY
}

rc=0

## Per-family: the DNS query is answered (redirect present) AND does not egress the
## gateway (redirected to DnsPort, not forwarded to the clearnet sink).
dns_family_check() {
   local proto="$1" ws_src="$2" dst="$3" frc=0
   if [ "$(dns_answered "${dst}")" = 'OK' ]; then
      msg "PASS: DNS positive control (${proto} UDP/53 redirected to DnsPort and answered)"
   else
      fail_case "DNS positive control: ${proto} UDP/53 was not redirected/answered"
      frc=1
   fi
   leaktest_fire_forward_probe "${proto}" "${ws_src}" "${dst}" "${capture_file}" --dport 53
   leaktest_assert_blocked "DNS ${proto} UDP/53 no clearnet egress" \
      "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || frc=1
   return "${frc}"
}

## 1. Shipped ruleset: redirect is present -> answered, and NOT forwarded to the sink.
leaktest_setup "${ruleset_file}"
if leaktest_positive_control; then
   msg 'PASS: positive control (legit torified TCP path works)'
else
   rc=1
fi
dns_family_check udp6 "${INT_WS_IP6}" "${PROBE_DST_IP6}" || rc=1
dns_family_check udp4 "${INT_WS_IP4}" "${PROBE_DST_IP4}" || rc=1

## 2. Canary: strip the UDP/53 redirect AND open forward -> the query must egress,
## proving the assertions above would catch a removed DNS DNAT rule.
canary="$(mktemp --suffix=.nft)"
noredirect="$(mktemp --suffix=.nft)"
grep --invert-match 'udp dport 53 counter redirect' "${ruleset_file}" >"${noredirect}"
leaktest_permissive_ruleset "${noredirect}" "${canary}"
leaktest_setup "${canary}"
leaktest_fire_forward_probe udp6 "${INT_WS_IP6}" "${PROBE_DST_IP6}" "${capture_file}" --dport 53
leaktest_assert_leaked 'DNS UDP/53 (redirect stripped + forward open)' "${LEAKTEST_EGRESS_COUNT}" "${LEAKTEST_CAPTURE_LIVE}" || rc=1

exit "${rc}"
