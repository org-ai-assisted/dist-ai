#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Positive control: Workstation DNS (UDP/53) must be transparently REDIRECTED to
## the gateway's Tor DnsPort, not dropped and not sent to the clearnet resolver.
##
## The forward-leak tests prove non-Tor traffic is blocked, but nothing otherwise
## asserts the DNS DNAT rule is PRESENT: if the "udp dport 53 redirect to DnsPort"
## rule were removed or broken, those tests would all still pass while DNS silently
## stopped resolving over Tor. This asserts a legit UDP/53 query is answered by the
## DnsPort stub (redirect works), and CANARIES by stripping that redirect rule --
## the query must then go unanswered, proving the test detects a broken redirect.

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

## Print OK if a legit UDP/53 query to <dst> is answered (redirected to the stub
## DnsPort and un-NAT'd back), else NOREPLY. Single-quoted heredoc: no shell interp.
dns_answered() {
   ip netns exec ws python3 - "$1" <<'PY'
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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

## 1. Shipped ruleset: the DNS redirect is present -> the query is answered.
leaktest_setup "${ruleset_file}"
if [ "$(dns_answered "${PROBE_DST_IP4}")" = 'OK' ]; then
   msg 'PASS: DNS positive control (UDP/53 redirected to DnsPort and answered)'
else
   fail_case 'DNS positive control: UDP/53 was not redirected/answered' || rc=1
fi

## 2. Canary: strip the UDP/53 redirect rule -> the query must go unanswered,
## proving this test would catch a removed/broken DNS DNAT rule.
noredirect="$(mktemp --suffix=.nft)"
grep --invert-match 'udp dport 53 counter redirect' "${ruleset_file}" >"${noredirect}"
leaktest_setup "${noredirect}"
if [ "$(dns_answered "${PROBE_DST_IP4}")" = 'NOREPLY' ]; then
   msg 'PASS: DNS canary (query unanswered once the redirect is stripped); test has teeth'
else
   fail_case 'DNS canary: query still answered with the redirect stripped -- test proves nothing' || rc=1
fi

exit "${rc}"
