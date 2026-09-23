#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
L2 packet injector for the leak-test harness.

Builds a frame from scratch and injects it via AF_PACKET at the gateway's MAC,
bypassing the workstation's own IP stack -- so the gateway processes exactly the
crafted packet (a forged source, an odd protocol, a fragment) a normal socket
could never send.

--proto values:
  tcp6   IPv6 TCP SYN (forged-source uRPF probe; --flags to vary TCP flags)
  tcp4   IPv4 TCP SYN (forged-source rp_filter/uRPF probe; --flags to vary flags)
  icmp6  IPv6 ICMP echo request
  icmp4  IPv4 ICMP echo request (ping)
  udp6   IPv6 UDP datagram to --dport
  udp4   IPv4 UDP datagram to --dport (e.g. Teredo UDP/3544)
  frag4set  IPv4 UDP datagram split across two fragments (ip_defrag reassembles)
  frag4overlap  Two overlapping IPv4 fragments (ip_defrag kills the set, RFC 5722)
  srcroute4  IPv4 UDP datagram bearing a completed (inert) LSRR option (IHL>5)
  srcroute4active  IPv4 UDP with an ACTIVE LSRR: dst=--gw4, next hop=--dst (a router
          honoring source routes rewrites dst and forwards it on)
  rawip6 IPv6 with an arbitrary next-header (--protonum), tiny payload
  rawip4 IPv4 with an arbitrary protocol (--protonum), tiny payload (e.g. 41 = 6to4)
  frag6  IPv6 atomic fragment (fragment ext-header) hiding an L4 (--l4 udp|tcp)
  frag6set  Two IPv6 fragments of ONE UDP datagram (offset 0 M=1 + offset 8 M=0);
            nf_defrag_ipv6 reassembles before the forward chain
  frag6overlap  Two OVERLAPPING IPv6 fragments (RFC 5722); nf_defrag_ipv6 must drop
            the whole datagram, so nothing reassembles or forwards
  frag6tinyfirst  First fragment too small for the L4 header (RFC 7112); the header
            chain is split across fragments and must be dropped, not reassembled
  exthdr6 IPv6 extension-header chain (--exthdr routing|hopopts|dstopts) hiding an
          L4 (--l4 udp|tcp; tcp = a SYN, to probe the redirect's chain-walking)
"""

import argparse
import socket
import struct
import subprocess
import sys
import time

ETH_P_IPV6 = b"\x86\xdd"
ETH_P_IPV4 = b"\x08\x00"
PROBE_PAYLOAD = b"leaktest-probe"
## null = no flags; fin = FIN only; xmas = FIN+PSH+URG; synfin = SYN+FIN (probes the
## redirect's `flags & (fin|syn|rst|ack) == syn` match, which SYN+FIN must NOT satisfy).
TCP_FLAGS = {
    "syn": 0x02, "ack": 0x10, "synack": 0x12, "finack": 0x11, "rstack": 0x14,
    "null": 0x00, "fin": 0x01, "xmas": 0x29, "synfin": 0x03,
}


def a6(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, addr)


def a4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total = (total >> 16) + (total & 0xFFFF)
    return (~total) & 0xFFFF


def ip6_pseudo(src: str, dst: str, length: int, next_header: int) -> bytes:
    return a6(src) + a6(dst) + struct.pack("!I", length) + struct.pack("!I", next_header)


def ip4_pseudo(src: str, dst: str, length: int, proto: int) -> bytes:
    return a4(src) + a4(dst) + struct.pack("!BBH", 0, proto, length)


def tcp6(src: str, dst: str, sport: int, dport: int, seq: int, flags: int) -> bytes:
    segment = struct.pack(
        "!HHIIHHHH", sport, dport, seq, 0, (5 << 12) | flags, 8192, 0, 0
    )
    csum = checksum16(ip6_pseudo(src, dst, len(segment), 6) + segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def icmp6_echo(src: str, dst: str) -> bytes:
    body = struct.pack("!BBHHH", 128, 0, 0, 0x1337, 1) + PROBE_PAYLOAD
    csum = checksum16(ip6_pseudo(src, dst, len(body), 58) + body)
    return body[:2] + struct.pack("!H", csum) + body[4:]


def udp6_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = checksum16(ip6_pseudo(src, dst, len(header) + len(payload), 17) + header + payload)
    return header[:6] + struct.pack("!H", csum or 0xFFFF) + payload


def udp6(src: str, dst: str, sport: int, dport: int) -> bytes:
    return udp6_datagram(src, dst, sport, dport, PROBE_PAYLOAD)


def icmp4_echo() -> bytes:
    ## ICMPv4 echo request (type 8). Checksum is over the ICMP message only (no
    ## pseudo-header, unlike ICMPv6).
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1337, 1) + PROBE_PAYLOAD
    csum = checksum16(body)
    return body[:2] + struct.pack("!H", csum) + body[4:]


def tcp4_segment(src: str, dst: str, sport: int, dport: int, seq: int, flags: int) -> bytes:
    segment = struct.pack(
        "!HHIIHHHH", sport, dport, seq, 0, (5 << 12) | flags, 8192, 0, 0
    )
    csum = checksum16(ip4_pseudo(src, dst, len(segment), 6) + segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def udp4_segment(src: str, dst: str, sport: int, dport: int) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(PROBE_PAYLOAD), 0)
    csum = checksum16(ip4_pseudo(src, dst, len(header) + len(PROBE_PAYLOAD), 17) + header + PROBE_PAYLOAD)
    return header[:6] + struct.pack("!H", csum or 0xFFFF) + PROBE_PAYLOAD


def ip6_header(src: str, dst: str, payload_len: int, next_header: int) -> bytes:
    return (
        b"\x60\x00\x00\x00"
        + struct.pack("!HBB", payload_len, next_header, 64)
        + a6(src)
        + a6(dst)
    )


def ip4_header_opts(src: str, dst: str, payload_len: int, proto: int, options: bytes = b"") -> bytes:
    ## IHL counts 32-bit words, so the options blob MUST be 4-byte-aligned; the
    ## checksum covers the whole header (base + options) with the csum field zeroed.
    if len(options) % 4:
        raise ValueError("IPv4 options must be 4-byte-aligned, got %d" % len(options))
    ihl = 5 + len(options) // 4
    total = 4 * ihl + payload_len
    base = struct.pack("!BBHHHBBH", 0x40 | ihl, 0, total, 0x1234, 0x4000, 64, proto, 0)
    base += a4(src) + a4(dst)
    full = base + options
    return full[:10] + struct.pack("!H", checksum16(full)) + full[12:]


def ip4_header(src: str, dst: str, payload_len: int, proto: int) -> bytes:
    ## No options (IHL=5) -- the common path; ip4_header_opts with empty options is
    ## byte-identical to a hand-built 0x45 header.
    return ip4_header_opts(src, dst, payload_len, proto)


## Loose Source and Record Route (LSRR, option type 131) / Strict (SSRR, 137). The
## `pointer` is a 1-based offset into the option; pointer > length means the source
## route is already COMPLETE (fully traversed), so the packet forwards to its final
## dst like a normal datagram while still carrying the option (IHL>5).
IP4_OPT_LSRR = 131
IP4_OPT_SSRR = 137


def ip4_srcroute_option(route: list[str], pointer: int, opt_type: int = IP4_OPT_LSRR) -> bytes:
    data = b"".join(a4(hop) for hop in route)
    length = 3 + len(data)  # type + length + pointer + route entries
    opt = struct.pack("!BBB", opt_type, length, pointer) + data
    ## Pad to a 4-byte boundary; option type 0 (End of Option List) is the pad.
    opt += b"\x00" * ((-len(opt)) % 4)
    return opt


## Base IPv4 fragment ids (bytes 4-5 of the IP header; a fragment's members share
## one). The send loop adds the iteration index so successive datagrams never share
## a reassembly id. IPv4 defrag has a SEPARATE ENTRY (ip_defrag / nf_defrag_ipv4)
## from the IPv6 side, but both funnel through the SAME overlap classification
## (inet_frag_queue_insert, rbtree-unified since kernel 4.18) -- so the overlap-drop
## policy is shared, not divergent. IPv4 is still exercised in its own right because
## the defrag trigger and header format differ, not because the overlap rule does.
FRAG4_SET_ID = 0x0000BE01
FRAG4_OVERLAP_ID = 0x0000BE02


def ip4_header_frag(src: str, dst: str, payload_len: int, proto: int, ip_id: int, flags_offset: int) -> bytes:
    ## IPv4 header for one fragment: flags_offset packs the 3 flag bits (MF=0x2000,
    ## DF=0x4000) with the 13-bit fragment offset (in 8-byte units) in one field.
    total = 20 + payload_len
    base = struct.pack("!BBHHHBBH", 0x45, 0, total, ip_id, flags_offset, 64, proto, 0)
    base += a4(src) + a4(dst)
    return base[:10] + struct.pack("!H", checksum16(base)) + base[12:]


def frag4_set(src: str, dst: str, dport: int, ip_id: int) -> list[bytes]:
    ## Complete IPv4 UDP datagram split across two fragments (offset 0 MF=1 + offset
    ## 16 MF=0), same id. The gw ruleset's nat/conntrack pulls in nf_defrag_ipv4, so
    ## ip_defrag reassembles the set before the forward chain (re-fragmenting to the
    ## original boundaries on egress via frag_max_size) -- splitting a datagram
    ## cannot smuggle it past the forward drop. ip_id varies per iteration so a later
    ## datagram never joins an earlier reassembly queue.
    payload = udp4_segment(src, dst, 41600, dport)  # 8 hdr + PROBE_PAYLOAD = 22 bytes
    first, second = payload[:16], payload[16:]  # 16 (2 units, MF=1) + 6 (last)
    frag1 = ip4_header_frag(src, dst, len(first), 17, ip_id, 0x2000) + first    # off 0, MF=1
    frag2 = ip4_header_frag(src, dst, len(second), 17, ip_id, 0x0002) + second  # off 16B, MF=0
    return [frag1, frag2]


def frag4_overlap(src: str, dst: str, dport: int, ip_id: int) -> list[bytes]:
    ## Two GENUINELY OVERLAPPING IPv4 fragments: fragment 1 claims [0,16) MF=1,
    ## fragment 2 claims [8,22) at offset 8 MF=0 -- it overlaps [8,16) AND extends
    ## past fragment 1's end. That newcomer-end (22) > existing-run-end (16) is what
    ## makes ip_defrag classify it IPFRAG_OVERLAP -> inet_frag_kill (RFC 5722, whole
    ## datagram discarded), not the IPFRAG_DUP a mere subset [8,16) degenerates into
    ## (new skb dropped, first fragment left in an incomplete queue -- never the
    ## overlap-kill this case is meant to exercise). frag4_set is the valid reference
    ## that egresses under the same permissive policy. ip_id varies per iteration.
    payload = udp4_segment(src, dst, 41600, dport)  # 22 bytes
    first, second = payload[:16], payload[8:22]  # [0,16) MF=1 ; [8,22) overlaps + extends MF=0
    frag1 = ip4_header_frag(src, dst, len(first), 17, ip_id, 0x2000) + first    # off 0, MF=1
    frag2 = ip4_header_frag(src, dst, len(second), 17, ip_id, 0x0001) + second  # off 8B, MF=0, ends at 22
    return [frag1, frag2]


## The L4 hidden one hop down an ext-header / fragment chain: UDP (17) by default,
## or a TCP SYN (6) -- the transparent-proxy REDIRECT is a stateful, more attractive
## target for "hide the real L4 down the chain" than the stateless forward drop.
def _hidden_l4(src: str, dst: str, dport: int, l4: str, sport: int = 41600) -> tuple[int, bytes]:
    if l4 == "tcp":
        return 6, tcp6(src, dst, sport, dport, 601, TCP_FLAGS["syn"])
    return 17, udp6(src, dst, sport, dport)


def frag6_atomic(src: str, dst: str, dport: int, l4: str = "udp", sport: int = 41600) -> bytes:
    ## IPv6 fragment extension header (next-header 44) carrying the L4 as a single
    ## atomic fragment (offset 0, M=0): exercises the fragment-header path.
    next_l4, l4bytes = _hidden_l4(src, dst, dport, l4, sport)
    frag_hdr = struct.pack("!BBHI", next_l4, 0, 0, 0xABCD)  # nexthdr, offset0, M=0
    payload = frag_hdr + l4bytes
    return ip6_header(src, dst, len(payload), 44) + payload


## Base fragment id for the multi-fragment set; the send loop adds the iteration
## index so successive datagrams never share a reassembly id (RFC 8200: recently
## sent fragmented packets with the same src/dst need distinct ids, else a later
## iteration's fragments could join an earlier iteration's reassembly queue).
FRAG6_MULTI_ID = 0x00BEEF01


def frag6_multi(src: str, dst: str, dport: int, frag_id: int) -> list[bytes]:
    ## Two IPv6 fragments of ONE UDP datagram, split on an 8-byte boundary
    ## (fragment 1: offset 0, M=1; fragment 2: offset 8 bytes, M=0), sharing this
    ## datagram's fragment id. nf_defrag_ipv6 (loaded by conntrack) reassembles
    ## BEFORE the forward chain, so splitting a datagram cannot smuggle it past the
    ## forward drop -- the ruleset sees the reassembled datagram, not the
    ## fragments. An 8-byte UDP payload keeps the split 8-byte-aligned (fragment
    ## offsets are in 8-byte units); only the first fragment carries the UDP header.
    datagram = udp6_datagram(src, dst, 41600, dport, b"leaktest")  # 8 hdr + 8 payload
    first, second = datagram[:8], datagram[8:]
    frag_hdr1 = struct.pack("!BBHI", 17, 0, (0 << 3) | 1, frag_id)  # off 0, M=1
    frag_hdr2 = struct.pack("!BBHI", 17, 0, (1 << 3) | 0, frag_id)  # off 8B, M=0
    frag1 = ip6_header(src, dst, len(frag_hdr1) + len(first), 44) + frag_hdr1 + first
    frag2 = ip6_header(src, dst, len(frag_hdr2) + len(second), 44) + frag_hdr2 + second
    return [frag1, frag2]


## Fragment id for the overlapping set (distinct from the clean multi-fragment id).
FRAG6_OVERLAP_ID = 0x00BEEF77
FRAG6_TINYFIRST_ID = 0x00BEEF78


def frag6_tinyfirst(src: str, dst: str, dport: int) -> list[bytes]:
    ## First fragment too SMALL to hold the complete L4 header (RFC 7112): a TCP
    ## header is 20 bytes, but fragment 1 carries only its first 8, so the header is
    ## split across fragments. A conformant reassembler drops the set (the header
    ## chain is not complete in the first fragment). A non-SYN (ACK) flag is used so
    ## that a reassembled datagram would be FORWARDED, not redirected -- making the
    ## permissive-forward canary meaningful (it would egress if wrongly reassembled).
    data = tcp6(src, dst, 41600, dport, 601, TCP_FLAGS["ack"])  # 20-byte header, valid checksum
    first, second = data[:8], data[8:]  # 8 (partial header, 8-byte aligned) + 12 (rest of header)
    frag_hdr1 = struct.pack("!BBHI", 6, 0, (0 << 3) | 1, FRAG6_TINYFIRST_ID)  # nh=TCP, off0, M=1
    frag_hdr2 = struct.pack("!BBHI", 6, 0, (1 << 3) | 0, FRAG6_TINYFIRST_ID)  # off 8B, M=0
    frag1 = ip6_header(src, dst, len(frag_hdr1) + len(first), 44) + frag_hdr1 + first
    frag2 = ip6_header(src, dst, len(frag_hdr2) + len(second), 44) + frag_hdr2 + second
    return [frag1, frag2]


def frag6_overlap(src: str, dst: str, dport: int, frag_id: int) -> list[bytes]:
    ## Two GENUINELY OVERLAPPING IPv6 fragments (RFC 5722): fragment 1 claims [0,16)
    ## with M=1, fragment 2 claims [8,24) at offset 8 with M=0 -- it overlaps [8,16)
    ## AND extends past fragment 1's end (24 > 16). That newcomer-end past the
    ## existing run-end is what makes the reassembler classify it IPFRAG_OVERLAP and
    ## inet_frag_kill the WHOLE datagram, not the IPFRAG_DUP a mere subset [8,16)
    ## degenerates into (new skb dropped, first fragment left in an incomplete queue
    ## that merely times out -- never the RFC 5722 overlap-kill this case must
    ## exercise). nf_defrag_ipv6 shares that classification with ip_defrag (the common
    ## inet_frag_queue_insert since the rbtree unification), so nothing reassembles or
    ## forwards even under a permissive forward policy. The clean (non-overlapping)
    ## frag6set egressing under the same permissive policy is the reference that proves
    ## this is the overlap rejection, not a dead path. frag_id varies per iteration.
    datagram = udp6_datagram(src, dst, 41600, dport, b"leaktestleaktest")  # 8 hdr + 16 payload = 24
    first, second = datagram[:16], datagram[8:24]  # [0,16) M=1 ; [8,24) overlaps + extends M=0
    frag_hdr1 = struct.pack("!BBHI", 17, 0, (0 << 3) | 1, frag_id)  # off 0, M=1
    frag_hdr2 = struct.pack("!BBHI", 17, 0, (1 << 3) | 0, frag_id)  # off 8B, M=0, ends at 24
    frag1 = ip6_header(src, dst, len(frag_hdr1) + len(first), 44) + frag_hdr1 + first
    frag2 = ip6_header(src, dst, len(frag_hdr2) + len(second), 44) + frag_hdr2 + second
    return [frag1, frag2]


## IPv6 extension header TYPES; the 8-byte header itself is built with the hidden
## L4's protocol as its next-header (a classic way to slip past a filter that only
## inspects the first next-header).
EXTHDR6_TYPE = {"routing": 43, "hopopts": 0, "dstopts": 60}


def _exthdr6_body(kind: str, next_header: int) -> bytes:
    if kind == "routing":
        ## Routing header, type 0, segments-left 0 (the RH0 shape).
        return struct.pack("!BBBBI", next_header, 0, 0, 0, 0)
    ## Hop-by-Hop (0) / Destination (60) options: a PadN option filling the 8 bytes.
    return struct.pack("!BBBB", next_header, 0, 1, 4) + b"\x00\x00\x00\x00"


def exthdr6(src: str, dst: str, dport: int, kind: str, l4: str = "udp", sport: int = 41600) -> bytes:
    ## `kind` may be a comma-separated CHAIN (e.g. "hopopts,routing,dstopts"): the
    ## headers nest outermost-first, each one's next-header pointing at the next in
    ## the chain, the innermost at the hidden L4. A deep chain probes whether the
    ## transparent-proxy redirect (and the forward path) walk far enough to still
    ## find + torify the SYN, rather than letting it slip past on chain depth.
    kinds = kind.split(",")
    for one in kinds:
        if one not in EXTHDR6_TYPE:
            raise ValueError("unknown ext-header kind %r (want %s)" % (one, ", ".join(sorted(EXTHDR6_TYPE))))
    next_l4, l4bytes = _hidden_l4(src, dst, dport, l4, sport)
    payload = l4bytes
    next_header = next_l4
    for one in reversed(kinds):
        payload = _exthdr6_body(one, next_header) + payload
        next_header = EXTHDR6_TYPE[one]
    return ip6_header(src, dst, len(payload), next_header) + payload


def resolve_gw_mac(gw4: str) -> bytes:
    proc = subprocess.run(
        ["ip", "neigh", "show", gw4], capture_output=True, text=True, check=False
    )
    if "lladdr" not in proc.stdout:
        subprocess.run(["ping", "-c1", "-W1", gw4], capture_output=True, check=False)
        time.sleep(0.3)
        proc = subprocess.run(
            ["ip", "neigh", "show", gw4], capture_output=True, text=True, check=False
        )
    if "lladdr" not in proc.stdout:
        print("inject: could not resolve gateway MAC for %s" % gw4, file=sys.stderr)
        sys.exit(1)
    return bytes.fromhex(proc.stdout.split("lladdr")[1].split()[0].replace(":", ""))


def own_mac(iface: str) -> bytes:
    ## Read the MAC via netlink (`ip link`), which is netns-aware -- NOT
    ## /sys/class/net. inject.py runs inside `ip netns exec ws`, but ip netns exec
    ## does NOT remount sysfs, so /sys still shows the HOST's interfaces: reading
    ## /sys/class/net/eth0/address returns the host NIC's MAC (wrong), or raises
    ## FileNotFoundError and aborts every case on a host whose root netns has no
    ## eth0. A subprocess inherits the ws netns, so `ip link show <iface>` returns
    ## the ws veth's own MAC.
    proc = subprocess.run(
        ["ip", "link", "show", iface], capture_output=True, text=True, check=False
    )
    if "link/ether" not in proc.stdout:
        print("inject: could not read MAC for interface %s" % iface, file=sys.stderr)
        sys.exit(1)
    return bytes.fromhex(proc.stdout.split("link/ether")[1].split()[0].replace(":", ""))


def build_l3(args: argparse.Namespace) -> tuple[bytes, bytes]:
    """Return (ethertype, L3 packet) for the requested protocol."""
    if args.proto == "tcp6":
        payload = tcp6(args.src, args.dst, args.sport, args.dport, 601, TCP_FLAGS[args.flags])
        return ETH_P_IPV6, ip6_header(args.src, args.dst, len(payload), 6)[:40] + payload
    if args.proto == "icmp6":
        payload = icmp6_echo(args.src, args.dst)
        return ETH_P_IPV6, ip6_header(args.src, args.dst, len(payload), 58)[:40] + payload
    if args.proto == "icmp4":
        payload = icmp4_echo()
        return ETH_P_IPV4, ip4_header(args.src, args.dst, len(payload), 1) + payload
    if args.proto == "udp6":
        payload = udp6(args.src, args.dst, args.sport, args.dport)
        return ETH_P_IPV6, ip6_header(args.src, args.dst, len(payload), 17)[:40] + payload
    if args.proto == "frag6":
        return ETH_P_IPV6, frag6_atomic(args.src, args.dst, args.dport, args.l4, args.sport)
    if args.proto == "exthdr6":
        return ETH_P_IPV6, exthdr6(args.src, args.dst, args.dport, args.exthdr, args.l4, args.sport)
    if args.proto == "rawip6":
        return ETH_P_IPV6, ip6_header(args.src, args.dst, len(PROBE_PAYLOAD), args.protonum)[:40] + PROBE_PAYLOAD
    if args.proto == "tcp4":
        payload = tcp4_segment(args.src, args.dst, args.sport, args.dport, 601, TCP_FLAGS[args.flags])
        return ETH_P_IPV4, ip4_header(args.src, args.dst, len(payload), 6) + payload
    if args.proto == "udp4":
        payload = udp4_segment(args.src, args.dst, args.sport, args.dport)
        return ETH_P_IPV4, ip4_header(args.src, args.dst, len(payload), 17) + payload
    if args.proto == "srcroute4":
        ## IPv4 UDP datagram bearing a COMPLETED LSRR option (IHL>5): the source
        ## route is already traversed (pointer past the last entry), so the kernel
        ## forwards it to dst like a normal packet -- but it exercises the
        ## options-bearing (IHL>5) forward path. A forward rule accidentally keyed
        ## on IHL=5 would miss it; the shipped policy-drop must catch it regardless.
        payload = udp4_segment(args.src, args.dst, args.sport, args.dport)
        option = ip4_srcroute_option([args.dst], pointer=8, opt_type=IP4_OPT_LSRR)
        return ETH_P_IPV4, ip4_header_opts(args.src, args.dst, len(payload), 17, option) + payload
    if args.proto == "srcroute4active":
        ## IPv4 UDP datagram bearing an ACTIVE (unexhausted) LSRR option: IP dst is
        ## the GATEWAY itself (--gw4) and the route's first unvisited hop (pointer 4)
        ## is the real clearnet target (--dst). A router that honors source routing
        ## rewrites the IP dst to the next hop and forwards it on -- the attacker-
        ## DIRECTED source-routing case, distinct from srcroute4's inert completed
        ## route. The UDP checksum is over the FINAL target (--dst), not the
        ## immediate gateway dst: a forwarding router does not recompute the L4
        ## checksum, so covering the post-rewrite destination is what makes the
        ## egressed packet a valid datagram the real endpoint would accept (a
        ## faithful leak, not one the endpoint would discard on a bad checksum).
        payload = udp4_segment(args.src, args.dst, args.sport, args.dport)
        option = ip4_srcroute_option([args.dst], pointer=4, opt_type=IP4_OPT_LSRR)
        return ETH_P_IPV4, ip4_header_opts(args.src, args.gw4, len(payload), 17, option) + payload
    ## rawip4
    return ETH_P_IPV4, ip4_header(args.src, args.dst, len(PROBE_PAYLOAD), args.protonum) + PROBE_PAYLOAD


def build_frames(args: argparse.Namespace, index: int = 0) -> tuple[bytes, list[bytes]]:
    """Return (ethertype, [L3 packet, ...]). Most protos emit ONE frame; frag6set
    emits the two fragments of a single UDP datagram (sent as two frames of one
    logical packet, which nf_defrag_ipv6 reassembles before the forward chain),
    with a fresh fragment id per iteration so datagrams do not share one."""
    if args.proto == "frag6set":
        return ETH_P_IPV6, frag6_multi(args.src, args.dst, args.dport, FRAG6_MULTI_ID + index)
    if args.proto == "frag6overlap":
        return ETH_P_IPV6, frag6_overlap(args.src, args.dst, args.dport, FRAG6_OVERLAP_ID + index)
    if args.proto == "frag6tinyfirst":
        return ETH_P_IPV6, frag6_tinyfirst(args.src, args.dst, args.dport)
    if args.proto == "frag4set":
        return ETH_P_IPV4, frag4_set(args.src, args.dst, args.dport, FRAG4_SET_ID + index)
    if args.proto == "frag4overlap":
        return ETH_P_IPV4, frag4_overlap(args.src, args.dst, args.dport, FRAG4_OVERLAP_ID + index)
    ethertype, l3 = build_l3(args)
    return ethertype, [l3]


def ranged_int(low: int, high: int):
    """argparse type: an int in [low, high], else a clean usage error (not a
    struct.error traceback deep in packet construction)."""
    def parse(text: str) -> int:
        value = int(text)
        if not low <= value <= high:
            raise argparse.ArgumentTypeError("must be %d..%d, got %d" % (low, high, value))
        return value
    return parse


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--proto", required=True,
        choices=["tcp6", "tcp4", "icmp6", "icmp4", "udp6", "frag6", "frag6set", "frag6overlap", "frag6tinyfirst", "exthdr6", "rawip6", "udp4", "frag4set", "frag4overlap", "srcroute4", "srcroute4active", "rawip4"],
    )
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--gw4", required=True, help="gateway IPv4 for MAC resolution")
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--sport", type=ranged_int(0, 0xFFFF), default=41444)
    parser.add_argument("--dport", type=ranged_int(0, 0xFFFF), default=443)
    parser.add_argument("--flags", default="syn", choices=sorted(TCP_FLAGS))
    parser.add_argument("--protonum", type=ranged_int(0, 0xFF), default=47, help="IP proto / next-header for rawip*")
    parser.add_argument("--exthdr", default="routing", help="ext-header(s) for exthdr6; comma-separated builds a nested chain (routing|hopopts|dstopts)")
    parser.add_argument("--l4", default="udp", choices=["udp", "tcp"], help="L4 hidden in frag6/exthdr6")
    parser.add_argument("--count", type=ranged_int(1, 10000), default=4)
    args = parser.parse_args()

    ## Resolve the L2 addresses ONCE (MAC resolution runs a subprocess); the L3
    ## bytes are rebuilt per iteration -- cheap struct packing, and it lets a
    ## multi-frame proto vary its fragment id per datagram.
    l2 = resolve_gw_mac(args.gw4) + own_mac(args.iface)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    for index in range(args.count):
        ethertype, l3_list = build_frames(args, index)
        ## A multi-frame proto (frag6set) sends all its frames back-to-back so the
        ## fragments arrive within one reassembly window before the inter-probe gap.
        for l3 in l3_list:
            sock.send(l2 + ethertype + l3)
        print("inject %d: %s %s -> %s" % (index + 1, args.proto, args.src, args.dst))
        time.sleep(0.4)


if __name__ == "__main__":
    main()
