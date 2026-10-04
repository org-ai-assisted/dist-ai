#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Non-Qubes-Whonix extensions to the leak-test harness: the GATEWAY's OWN egress
## (filter OUTPUT chain) and its EXTERNAL-side port reachability (filter INPUT
## chain) -- neither exercised by the workstation-sourced FORWARD cases. Sourced
## by the gw-origin and external-input test files AFTER leaktest_lib.sh, whose
## topology, capture oracle, assert helpers and LEAKTEST_* globals it reuses.
##
## Why a real socket, not anon-leak-inject: the injector sends via AF_PACKET,
## which bypasses the local IP stack and so NEVER traverses the filter OUTPUT /
## INPUT hooks. A gateway-origination or gateway-reachability case must go through
## the kernel socket path, so these helpers do.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## This extension depends on the base harness: source it so its topology, oracle,
## assert helpers and LEAKTEST_* / EXT_* / INT_* globals are defined (and so a case
## file need only source THIS file). Re-sourcing when the case already loaded it is
## harmless -- it only re-defines functions and re-initialises pristine globals.
nonqubes_lib_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
# shellcheck source=./leaktest_lib.sh
source "${nonqubes_lib_dir}/leaktest_lib.sh"

## proc_dead / proc_diag: a readiness wait must tell a bound-and-serving helper
## from one that DIED during startup, and a bare 'kill -0' reports a killed-but-
## unreaped zombie as alive (false survivor under a slow-reaping CI-container PID 1).
nonqubes_proc_lib="${nonqubes_lib_dir}/../dist-ai-tests-common/proc-lib.bash"
if [ ! -r "${nonqubes_proc_lib}" ]; then
   printf '%s\n' "FATAL: proc-lib.bash not found: ${nonqubes_proc_lib}" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/proc-lib.bash
source "${nonqubes_proc_lib}"

## Wait (bounded, ~5s) until a backgrounded helper has BOUND its socket(s): the
## helper creates READY_FILE only AFTER every bind succeeds, so its presence is
## positive proof the port is absorbing -- not a fixed 'sleep' that returns before
## the bind and lets a probe measure an unbound port. Fail the setup loudly if the
## helper (PID) dies first or never signals, so a harness miss never masquerades as
## a firewall verdict. Mirrors the leaktest_assert_* 'fail_case; return 1' idiom.
leaktest_wait_ready() {
   local pid="$1" ready_file="$2" label="$3" _
   for _ in $(seq 1 50); do
      if [ -e "${ready_file}" ]; then
         return 0
      fi
      if proc_dead "${pid}"; then
         fail_case "${label} exited before binding its socket(s)"
         return 1
      fi
      sleep 0.1
   done
   proc_diag "${label}" "${pid}"
   fail_case "${label} did not signal readiness within 5s"
   return 1
}

## Reused scratch file for leaktest_fire_gw_origin's stderr (allocated once).
LEAKTEST_GW_SEND_ERR=''

## leaktest_setup + static neighbors so a REAL gw-originated socket can egress to
## the external sink without racing ARP/ND. The kernel does its own next-hop
## resolution for a real socket (unlike the injector's pre-resolved L2), so pin
## every external next hop to the up sink's MAC: an ALLOWED gw egress then
## actually reaches the oracle, while a BLOCKED one is dropped at the OUTPUT hook
## BEFORE the wire (the firewall verdict, never an ARP miss masquerading as "no
## leak"). The host DNS proxy 10.0.2.3 is on-link (same /24, unanswered in the
## model); 192.168.x and clearnet route via the up next hop EXT_UP_IP4 / EXT_UP_IP6.
leaktest_setup_gw_origin() {
   local ruleset="$1" up_mac
   leaktest_setup "${ruleset}"
   up_mac="$(ip netns exec up ip link show eth0 | awk '/link\/ether/ { print $2 }')"
   ip netns exec gw ip neigh replace '10.0.2.3' lladdr "${up_mac}" nud permanent dev eth0
   ip netns exec gw ip neigh replace "${EXT_UP_IP4}" lladdr "${up_mac}" nud permanent dev eth0
   ip netns exec gw ip -6 neigh replace "${EXT_UP_IP6}" lladdr "${up_mac}" nud permanent dev eth0
}

## Fire ONE real UDP datagram from a kernel socket inside gw (traverses the filter
## OUTPUT hook), then read the egress oracle. Sets LEAKTEST_EGRESS_COUNT /
## LEAKTEST_CAPTURE_LIVE exactly like leaktest_fire_forward_probe, so the shared
## leaktest_assert_blocked / leaktest_assert_leaked apply unchanged. A send the
## OUTPUT reject bounces (EPERM/EACCES) is the BLOCKED outcome, not a harness
## error: it is swallowed and the oracle count is the sole source of truth (the
## permissive canary proves an allowed send DOES egress -- the teeth).
## Args: <family 4|6> <dst> <dport> <sport> <capture_file>  (sport 0 = ephemeral)
leaktest_fire_gw_origin() {
   local family="$1" dst="$2" dport="$3" sport="$4" capture_file="$5"
   ## One reused scratch file (root-owned mktemp), not one per fire -- a many-probe
   ## run must not accumulate temp files.
   [ -n "${LEAKTEST_GW_SEND_ERR}" ] || LEAKTEST_GW_SEND_ERR="$(mktemp)"
   local send_err="${LEAKTEST_GW_SEND_ERR}"
   LEAKTEST_PROBE_ERROR=''
   leaktest_capture_up "${LEAKTEST_EGRESS_BPF}" 6 "${capture_file}"
   sleep 1
   ## A send the OUTPUT reject bounces (EPERM/EACCES) is the BLOCKED outcome (exit
   ## 0 -> the oracle confirms zero egress). ANY OTHER OSError -- a broken route
   ## (ENETUNREACH), a bad address (gaierror) -- is a HARNESS failure, not a
   ## firewall block: the datagram never left, so a zero count would be a FALSE
   ## pass. Exit 3 on it and surface it via LEAKTEST_PROBE_ERROR so assert_blocked
   ## FAILS with a clear reason instead of a silent green.
   if ! ip netns exec gw python3 - "${family}" "${dst}" "${dport}" "${sport}" 2>"${send_err}" <<'PY'
import errno
import socket
import sys
fam = socket.AF_INET6 if sys.argv[1] == '6' else socket.AF_INET
dst = sys.argv[2]
dport = int(sys.argv[3])
sport = int(sys.argv[4])
sock = socket.socket(fam, socket.SOCK_DGRAM)
if sport:
    bind_addr = '::' if fam == socket.AF_INET6 else '0.0.0.0'
    sock.bind((bind_addr, sport))
try:
    sock.sendto(b'leaktest-probe', (dst, dport))
except OSError as exc:
    if exc.errno not in (errno.EPERM, errno.EACCES):
        print('unexpected send error: %s' % errno.errorcode.get(exc.errno, exc.errno), file=sys.stderr)
        sys.exit(3)
PY
   then
      LEAKTEST_PROBE_ERROR="gw-origin send failed (not a firewall block): $(tr '\n' ' ' <"${send_err}" 2>/dev/null)"
   fi
   sleep 3
   leaktest_capture_wait
   LEAKTEST_CAPTURE_LIVE=0
   leaktest_capture_bound && LEAKTEST_CAPTURE_LIVE=1
   LEAKTEST_EGRESS_COUNT="$(leaktest_egress_count "${capture_file}")"
}

## Derive an OUTPUT-permissive ruleset (sibling of leaktest_permissive_ruleset,
## which does the FORWARD chain): flip the filter OUTPUT policy to accept and drop
## its final catch-all reject, so a gw-originated clearnet datagram egresses -- the
## canary that proves the gw-origin oracle has teeth.
leaktest_output_permissive_ruleset() {
   local infile="$1" outfile="$2"
   sed \
      -e 's/hook output priority 0; policy drop/hook output priority 0; policy accept/' \
      -e '/add rule inet filter output counter reject/d' \
      "${infile}" >"${outfile}"
}

## leaktest_setup with NO stub listener (the external listener below provides every
## probed port) plus a static neighbor so the upstream sink can reach the gateway's
## external IP without racing ARP/ND.
leaktest_setup_ext_input() {
   local ruleset="$1" gw_ext_mac
   leaktest_setup "${ruleset}" nolistener
   gw_ext_mac="$(ip netns exec gw ip link show eth0 | awk '/link\/ether/ { print $2 }')"
   ip netns exec up ip neigh replace "${EXT_GW_IP4}" lladdr "${gw_ext_mac}" nud permanent dev eth0
   ip netns exec up ip -6 neigh replace "${EXT_GW_IP6}" lladdr "${gw_ext_mac}" nud permanent dev eth0
   leaktest_ext_listener_start
}

LEAKTEST_UP_SINK_PID=''

## Start a UDP absorber in the up namespace on <port>, so a gw-originated DHCP
## probe to that port is received (not port-closed) and provokes NO ICMP
## port-unreachable reply -- which the oracle, correctly, would count (it is ICMP,
## not the excluded DHCP). A real network has a DHCP server/relay here; this stands
## in for it, so the DHCP-exclusion precision leg measures the BPF, not an artifact.
leaktest_up_udp_sink_start() {
   local port="$1" ready_dir ready_file rc=0
   leaktest_up_udp_sink_stop
   ## A mktemp DIR + a not-yet-existing sentinel inside it: the helper creates the
   ## sentinel only AFTER bind, so its presence is real proof. A bare 'mktemp' file
   ## would already EXIST, making the readiness check pass on the first poll (handshake
   ## defeated, bind race back).
   ready_dir="$(mktemp --directory)"
   ready_file="${ready_dir}/ready"
   ip netns exec up python3 - "${port}" "${ready_file}" <<'PY' &
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', int(sys.argv[1])))
open(sys.argv[2], 'w').close()
while True:
    try:
        sock.recvfrom(4096)
    except OSError:
        break
PY
   LEAKTEST_UP_SINK_PID="$!"
   ## Confirm the sink actually bound port <port> before returning: a failed bind
   ## (port in use) or a startup abort would otherwise leave a dead PID and the
   ## caller would probe with NO absorber, provoking an ICMP port-unreachable the
   ## egress oracle counts -- a harness artifact failing the DHCP-precision leg.
   ## PROPAGATE the readiness verdict: masking it with the always-0 cleanup would
   ## re-hide exactly the failed-bind case this guards.
   leaktest_wait_ready "${LEAKTEST_UP_SINK_PID}" "${ready_file}" 'up UDP sink' || rc=1
   safe-rm --recursive --force -- "${ready_dir}"
   return "${rc}"
}

leaktest_up_udp_sink_stop() {
   if [ -n "${LEAKTEST_UP_SINK_PID}" ]; then
      kill "${LEAKTEST_UP_SINK_PID}" 2>/dev/null || true
      LEAKTEST_UP_SINK_PID=''
   fi
}

LEAKTEST_EXT_LISTENER_PID=''

## Start the external-side port listener in gw, bound WIDE (0.0.0.0 / ::) so a
## reachability probe measures the INPUT chain, not a dead port -- and models the
## worst case the audit guards against (a Tor port bound to 0.0.0.0). Kills any
## prior instance first (idempotent across re-setups, which delete gw's netns).
leaktest_ext_listener_start() {
   local ready_dir ready_file rc=0
   leaktest_ext_listener_stop
   ## mktemp DIR + a not-yet-existing sentinel (see leaktest_up_udp_sink_start): a bare
   ## 'mktemp' file already exists and defeats the readiness check.
   ready_dir="$(mktemp --directory)"
   ready_file="${ready_dir}/ready"
   ip netns exec gw python3 "$(leaktest_helpers_dir)/ext_listener.py" '0.0.0.0' '::' "${ready_file}" &
   LEAKTEST_EXT_LISTENER_PID="$!"
   ## Block until EVERY listener socket is bound AND listening (ext_listener.py signals
   ## readiness only after all binds + listens succeed): a transient bind miss on one
   ## port would else let its probe read 'blocked' and pass the unreachable assertion
   ## for the wrong reason, since the canary rebuilds the namespace with a fresh
   ## listener. PROPAGATE the verdict, do not mask it with the always-0 cleanup.
   leaktest_wait_ready "${LEAKTEST_EXT_LISTENER_PID}" "${ready_file}" 'external listener' || rc=1
   safe-rm --recursive --force -- "${ready_dir}"
   return "${rc}"
}

leaktest_ext_listener_stop() {
   if [ -n "${LEAKTEST_EXT_LISTENER_PID}" ]; then
      kill "${LEAKTEST_EXT_LISTENER_PID}" 2>/dev/null || true
      LEAKTEST_EXT_LISTENER_PID=''
   fi
}

## Probe whether <addr>:<port> is reachable from netns <ns>. TCP = a bounded
## connect; UDP = a datagram whose echo must return within the timeout. Prints the
## literal 'reachable' or 'blocked' (a dropped SYN / unanswered datagram = blocked).
## Args: <ns> <proto tcp|udp> <family 4|6> <addr> <port>
leaktest_reach_probe() {
   local ns="$1" proto="$2" family="$3" addr="$4" port="$5"
   ip netns exec "${ns}" python3 - "${proto}" "${family}" "${addr}" "${port}" <<'PY'
import socket, sys
proto = sys.argv[1]
fam = socket.AF_INET6 if sys.argv[2] == '6' else socket.AF_INET
addr = sys.argv[3]
port = int(sys.argv[4])
if proto == 'tcp':
    sock = socket.socket(fam, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((addr, port))
        sock.close()
        print('reachable')
    except OSError:
        print('blocked')
else:
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(b'leaktest-reach', (addr, port))
        sock.recvfrom(4096)
        print('reachable')
    except OSError:
        print('blocked')
PY
}

## Assert an external-side port probe came back BLOCKED (the firewall dropped it).
## Returns 0 on pass, 1 on fail.
leaktest_assert_unreachable() {
   local label="$1" result="$2"
   if [ "${result}" = 'blocked' ]; then
      msg "PASS: ${label} not reachable from the external side"
      return 0
   fi
   fail_case "${label}: REACHABLE from the external side (result='${result}')"
   return 1
}

## Assert an external-side port probe came back REACHABLE: the canary that proves
## the probe + listener detect an exposed port (so a 'blocked' above is the
## firewall, not a dead port). Returns 0 on pass, 1 on fail.
leaktest_assert_reachable() {
   local label="$1" result="$2"
   if [ "${result}" = 'reachable' ]; then
      msg "PASS: ${label} canary reachable (firewall flushed); probe has teeth"
      return 0
   fi
   fail_case "${label} canary: NOT reachable with the firewall flushed -- probe proves nothing (dead listener?)"
   return 1
}

## Combined EXIT cleanup for the nonqubes cases: stop the helper processes THIS
## extension starts (the external listener, the up UDP sink) -- the shared
## leaktest_teardown only knows about the stub listener -- then run the standard
## teardown. Idempotent: each stop is a no-op when its pid is empty.
leaktest_nonqubes_cleanup() {
   leaktest_ext_listener_stop
   leaktest_up_udp_sink_stop
   leaktest_teardown
}
