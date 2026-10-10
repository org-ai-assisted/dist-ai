#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## REAL-tcpdump semantic regression for the deny-by-default allowlist BPF (allowlist_bpf, shared by
## canary_gateway_pcap and --print-allow-filter). Crafts tiny pcaps with python3 stdlib (no scapy)
## and runs the ACTUAL filter via the ACTUAL tcpdump, asserting the exact failing inputs an
## ai-review surfaced are now caught: a clearnet packet merely TOUCHING udp port 67/68, or with a
## link-local/loopback SOURCE, must count as a leak; genuine DHCP (both ports), guard traffic in
## EITHER direction, multicast, and loopback/link-local DESTINATIONS must not. Would have been RED
## on the pre-fix either-port / either-direction infra filter.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${here}/../../bin/dm-whonix-pair"
[ -x "${tool}" ] || { printf '%s\n' "FAIL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

## tcpdump + python3 are required deps of the real script; call them directly (assume present).

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"
filter="$(allowlist_bpf)"

## python3 stdlib pcap writer: build_pcap <outfile> <pkt>... where each pkt is
## "src,dst,sport,dport[,proto]" (IPv4 or IPv6 literal addresses; proto = udp (default) or tcp;
## zero checksums -- BPF matches headers regardless). Ethernet + IPv4/IPv6 + UDP/TCP, EN10MB.
cat > "${work}/mkpcap.py" <<'PY'
#!/usr/bin/python3 -Bsu
import ipaddress, struct, sys

PROTO = {"udp": 17, "tcp": 6}

def udp(sport, dport, payload=b"\x00\x00\x00\x00"):
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload

def tcp(sport, dport):
    ## minimal 20-byte header, SYN set, data offset 5 words; zero seq/ack/window/checksum
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x02, 0, 0, 0)

def ipv4(src, dst, l4, proto):
    total = 20 + len(l4)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return b"\x08\x00", hdr + l4

def ipv6(src, dst, l4, proto):
    hdr = struct.pack("!IHBB16s16s", 0x60000000, len(l4), proto, 64,
                      ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed)
    return b"\x86\xdd", hdr + l4

def frame(src, dst, sport, dport, proto):
    l4 = tcp(sport, dport) if proto == "tcp" else udp(sport, dport)
    ip = ipaddress.ip_address(src)
    ethertype, l3 = (ipv6(src, dst, l4, PROTO[proto]) if ip.version == 6 else ipv4(src, dst, l4, PROTO[proto]))
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + ethertype
    return eth + l3

out = sys.argv[1]
with open(out, "wb") as f:
    f.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # pcap global header, EN10MB
    for spec in sys.argv[2:]:
        parts = spec.split(",")
        src, dst, sport, dport = parts[:4]
        proto = parts[4] if len(parts) > 4 else "udp"
        data = frame(src, dst, int(sport), int(dport), proto)
        f.write(struct.pack("!IIII", 0, 0, len(data), len(data)) + data)
PY
chmod +x "${work}/mkpcap.py"

pass=0
fail=0
## Build a one-packet pcap for SPEC, count allowlist-matching (leak) packets, assert == WANT.
leaks_for() {
   "${work}/mkpcap.py" "${work}/p.pcap" "$1" >/dev/null
   tcpdump -nr "${work}/p.pcap" "${filter}" 2>/dev/null | wc -l
}
check() {
   local desc="$1" spec="$2" want="$3" got
   got="$(leaks_for "${spec}")"
   if [ "${got}" = "${want}" ]; then
      pass=$(( pass + 1 )); printf '%s\n' "PASS: ${desc} (leaks=${got})"
   else
      fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${desc} -- leaks=${got}, wanted ${want}"
   fi
}

guard4="${GUARD_PIN_IPS4[0]}"

## LEAKS (must count 1) -- the exact failing inputs the reviewers gave, now caught:
check 'clearnet pkt with src udp port 68 (not DHCP) is a LEAK'  "10.0.2.15,8.8.8.8,68,4444" 1
check 'DHCP-port pkt (67+68) to a CLEARNET dst is a LEAK'       "10.0.2.15,8.8.8.8,68,67" 1
check 'link-local SOURCE to a clearnet dst is a LEAK'           "169.254.5.5,8.8.8.8,40000,53" 1
check 'GW host-DNS to 10.0.2.3 is a LEAK (no carve-out)'        "10.0.2.15,10.0.2.3,40000,53" 1
check 'ordinary non-guard clearnet dst is a LEAK'              "10.0.2.15,1.1.1.1,40000,53" 1
check 'loopback dst is a LEAK (slirp delivers 127/8 to the host)' "10.0.2.15,127.0.0.1,40000,53" 1
check 'NON-DHCP broadcast is a LEAK (slirp maps it to host 127.0.0.1)' "10.0.2.15,255.255.255.255,9,4444" 1
check 'pseudo-multicast 240.0.0.0/4 is a LEAK (not real multicast)' "10.0.2.15,240.0.0.1,40000,53" 1

## ALLOWED (must count 0) -- genuine infra + guard traffic, either direction:
check 'genuine DHCP broadcast (67+68 to 255.255.255.255) is allowed' "0.0.0.0,255.255.255.255,68,67" 0
check 'egress to a pinned entry guard is allowed (any port)'   "10.0.2.15,${guard4},40000,443" 0
check 'a pinned entry guard REPLY (guard as source) is allowed' "${guard4},10.0.2.15,443,40000" 0
check 'TCP to the reserved pc guard ORPort is allowed'         "10.0.2.15,${GUARD_PC_IP4},40000,${GUARD_PC_PORT},tcp" 0
## The reserved guard is NOT an EntryNode -- allowed ONLY on its ORPort over TCP. Anything else is a LEAK:
check 'TCP to the reserved pc guard on a NON-ORPort is a LEAK'  "10.0.2.15,${GUARD_PC_IP4},40000,53,tcp" 1
check 'UDP to the reserved pc guard (even on the ORPort) is a LEAK' "10.0.2.15,${GUARD_PC_IP4},40000,${GUARD_PC_PORT},udp" 1
## The pc guard's REPLY (src=guard:ORPort -> local) must be allowed (dst-only scoping would flag it).
check 'reply FROM the reserved pc guard ORPort is allowed'     "${GUARD_PC_IP4},10.0.2.15,${GUARD_PC_PORT},40000,tcp" 0
## Port-scoped to the GUARD side: a packet whose OTHER endpoint uses 9100 (guard not on the ORPort
## side) is a LEAK -- the bare either-side `tcp port` would have wrongly allowed it.
check 'ORPort on the NON-guard side (to the pc guard) is a LEAK' "8.8.8.8,${GUARD_PC_IP4},${GUARD_PC_PORT},40000,tcp" 1
check 'real multicast 224.0.0.0/4 destination is allowed'      "10.0.2.15,224.0.0.251,5353,5353" 0
check 'link-local DESTINATION (not routed off-link) is allowed' "10.0.2.15,169.254.169.254,40000,80" 0

## Combined pcap: the eight leak datagrams together -> exactly 8.
"${work}/mkpcap.py" "${work}/multi.pcap" \
   "10.0.2.15,8.8.8.8,68,4444" "10.0.2.15,8.8.8.8,68,67" "169.254.5.5,8.8.8.8,40000,53" \
   "10.0.2.15,10.0.2.3,40000,53" "10.0.2.15,1.1.1.1,40000,53" "10.0.2.15,127.0.0.1,40000,53" \
   "10.0.2.15,255.255.255.255,9,4444" "10.0.2.15,240.0.0.1,40000,53" >/dev/null
multi="$(tcpdump -nr "${work}/multi.pcap" "${filter}" 2>/dev/null | wc -l)"
if [ "${multi}" = 8 ]; then
   pass=$(( pass + 1 )); printf '%s\n' "PASS: a mixed pcap counts exactly the 8 leak datagrams"
else
   fail=$(( fail + 1 )); printf '%s\n' "FAIL: mixed pcap counted ${multi} leaks, wanted 8"
fi

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
