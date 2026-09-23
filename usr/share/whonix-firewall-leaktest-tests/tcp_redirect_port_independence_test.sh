#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Positive control: the transparent-proxy TCP redirect is PORT-INDEPENDENT.
##
## Every other TCP case targets port 443, so nothing proves the redirect to Tor's
## TransPort catches all TCP dports rather than being keyed to 443. A legit TCP
## connection from the Workstation to a clearnet address on assorted ports (HTTP 80,
## SSH 22, a high ephemeral port) must be transparently redirected to the TransPort
## stub and complete. Canary strips the redirect rule -- the connection must then
## fail, proving the test detects a broken/port-keyed redirect.

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

## Print OK if a TCP connect from ws to <dst>:<port> completes (redirected to the
## TransPort stub and answered), else FAIL. Single-quoted heredoc: no shell interp.
tcp_connect() {
   ip netns exec ws python3 - "$1" "$2" <<'PY'
import socket, sys
try:
    conn = socket.create_connection((sys.argv[1], int(sys.argv[2])), 4)
    conn.close()
    print("OK")
except Exception:  # noqa: BLE001
    print("FAIL")
PY
}

rc=0

## 1. Shipped ruleset: a clearnet TCP connection on each port is redirected + answered.
leaktest_setup "${ruleset_file}"
for port in 80 22 12345; do
   if [ "$(tcp_connect "${PROBE_DST_IP6}" "${port}")" = 'OK' ]; then
      msg "PASS: TCP redirect is port-independent (clearnet port ${port} redirected + answered)"
   else
      fail_case "TCP to clearnet port ${port} was NOT redirected -- redirect appears port-keyed" || rc=1
   fi
done

## 2. Canary: strip the TransPort redirect -> the same connection must fail, proving
## the positive control above would catch a removed/port-keyed redirect.
noredirect="$(mktemp --suffix=.nft)"
grep --invert-match 'redirect to :9040' "${ruleset_file}" >"${noredirect}"
leaktest_setup "${noredirect}"
if [ "$(tcp_connect "${PROBE_DST_IP6}" 80)" = 'FAIL' ]; then
   msg 'PASS: canary (no TransPort redirect -> port 80 connect fails); test has teeth'
else
   fail_case 'canary: port 80 still connected with the redirect stripped -- test proves nothing' || rc=1
fi

exit "${rc}"
