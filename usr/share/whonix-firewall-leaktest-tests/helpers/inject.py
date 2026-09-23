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
  rawip6 IPv6 with an arbitrary next-header (--protonum), tiny payload
  rawip4 IPv4 with an arbitrary protocol (--protonum), tiny payload (e.g. 41 = 6to4)
  frag6  IPv6 atomic fragment (fragment ext-header) hiding an L4 (--l4 udp|tcp)
  frag6set  Two IPv6 fragments of ONE UDP datagram (offset 0 M=1 + offset 8 M=0);
            nf_defrag_ipv6 reassembles before the forward chain
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
TCP_FLAGS = {"syn": 0x02, "ack": 0x10, "synack": 0x12, "finack": 0x11, "rstack": 0x14}


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


def ip4_header(src: str, dst: str, payload_len: int, proto: int) -> bytes:
    total = 20 + payload_len
    header = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, 0x4000, 64, proto, 0)
    header += a4(src) + a4(dst)
    return header[:10] + struct.pack("!H", checksum16(header)) + header[12:]


## The L4 hidden one hop down an ext-header / fragment chain: UDP (17) by default,
## or a TCP SYN (6) -- the transparent-proxy REDIRECT is a stateful, more attractive
## target for "hide the real L4 down the chain" than the stateless forward drop.
def _hidden_l4(src: str, dst: str, dport: int, l4: str) -> tuple[int, bytes]:
    if l4 == "tcp":
        return 6, tcp6(src, dst, 41600, dport, 601, TCP_FLAGS["syn"])
    return 17, udp6(src, dst, 41600, dport)


def frag6_atomic(src: str, dst: str, dport: int, l4: str = "udp") -> bytes:
    ## IPv6 fragment extension header (next-header 44) carrying the L4 as a single
    ## atomic fragment (offset 0, M=0): exercises the fragment-header path.
    next_l4, l4bytes = _hidden_l4(src, dst, dport, l4)
    frag_hdr = struct.pack("!BBHI", next_l4, 0, 0, 0xABCD)  # nexthdr, offset0, M=0
    payload = frag_hdr + l4bytes
    return ip6_header(src, dst, len(payload), 44) + payload


## Fragment id shared by both fragments of the multi-fragment set so
## nf_defrag_ipv6 reassembles them into one datagram.
FRAG6_MULTI_ID = 0x00BEEF01


def frag6_multi(src: str, dst: str, dport: int) -> list[bytes]:
    ## Two IPv6 fragments of ONE UDP datagram, split on an 8-byte boundary
    ## (fragment 1: offset 0, M=1; fragment 2: offset 8 bytes, M=0), same
    ## fragment id. nf_defrag_ipv6 (loaded by conntrack) reassembles BEFORE the
    ## forward chain, so splitting a datagram cannot smuggle it past the forward
    ## drop -- the ruleset sees the reassembled datagram, not the fragments. An
    ## 8-byte UDP payload keeps the split 8-byte-aligned (fragment offsets are in
    ## 8-byte units); only the first fragment carries the UDP header.
    datagram = udp6_datagram(src, dst, 41600, dport, b"leaktest")  # 8 hdr + 8 payload
    first, second = datagram[:8], datagram[8:]
    frag_hdr1 = struct.pack("!BBHI", 17, 0, (0 << 3) | 1, FRAG6_MULTI_ID)  # off 0, M=1
    frag_hdr2 = struct.pack("!BBHI", 17, 0, (1 << 3) | 0, FRAG6_MULTI_ID)  # off 8B, M=0
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


def exthdr6(src: str, dst: str, dport: int, kind: str, l4: str = "udp") -> bytes:
    next_l4, l4bytes = _hidden_l4(src, dst, dport, l4)
    payload = _exthdr6_body(kind, next_l4) + l4bytes
    return ip6_header(src, dst, len(payload), EXTHDR6_TYPE[kind]) + payload


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
    with open("/sys/class/net/%s/address" % iface, encoding="ascii") as handle:
        return bytes.fromhex(handle.read().strip().replace(":", ""))


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
        return ETH_P_IPV6, frag6_atomic(args.src, args.dst, args.dport, args.l4)
    if args.proto == "exthdr6":
        return ETH_P_IPV6, exthdr6(args.src, args.dst, args.dport, args.exthdr, args.l4)
    if args.proto == "rawip6":
        return ETH_P_IPV6, ip6_header(args.src, args.dst, len(PROBE_PAYLOAD), args.protonum)[:40] + PROBE_PAYLOAD
    if args.proto == "tcp4":
        payload = tcp4_segment(args.src, args.dst, args.sport, args.dport, 601, TCP_FLAGS[args.flags])
        return ETH_P_IPV4, ip4_header(args.src, args.dst, len(payload), 6) + payload
    if args.proto == "udp4":
        payload = udp4_segment(args.src, args.dst, args.sport, args.dport)
        return ETH_P_IPV4, ip4_header(args.src, args.dst, len(payload), 17) + payload
    ## rawip4
    return ETH_P_IPV4, ip4_header(args.src, args.dst, len(PROBE_PAYLOAD), args.protonum) + PROBE_PAYLOAD


def build_frames(args: argparse.Namespace) -> tuple[bytes, list[bytes]]:
    """Return (ethertype, [L3 packet, ...]). Most protos emit ONE frame; frag6set
    emits the two fragments of a single UDP datagram (sent as two frames of one
    logical packet, which nf_defrag_ipv6 reassembles before the forward chain)."""
    if args.proto == "frag6set":
        return ETH_P_IPV6, frag6_multi(args.src, args.dst, args.dport)
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
        choices=["tcp6", "tcp4", "icmp6", "icmp4", "udp6", "frag6", "frag6set", "exthdr6", "rawip6", "udp4", "rawip4"],
    )
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--gw4", required=True, help="gateway IPv4 for MAC resolution")
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--sport", type=ranged_int(0, 0xFFFF), default=41444)
    parser.add_argument("--dport", type=ranged_int(0, 0xFFFF), default=443)
    parser.add_argument("--flags", default="syn", choices=sorted(TCP_FLAGS))
    parser.add_argument("--protonum", type=ranged_int(0, 0xFF), default=47, help="IP proto / next-header for rawip*")
    parser.add_argument("--exthdr", default="routing", choices=sorted(EXTHDR6_TYPE), help="ext-header for exthdr6")
    parser.add_argument("--l4", default="udp", choices=["udp", "tcp"], help="L4 hidden in frag6/exthdr6")
    parser.add_argument("--count", type=ranged_int(1, 10000), default=4)
    args = parser.parse_args()

    ethertype, l3_list = build_frames(args)
    l2 = resolve_gw_mac(args.gw4) + own_mac(args.iface) + ethertype
    frames = [l2 + l3 for l3 in l3_list]

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    for index in range(args.count):
        ## A multi-frame proto (frag6set) sends all its frames back-to-back so the
        ## fragments arrive within one reassembly window before the inter-probe gap.
        for frame in frames:
            sock.send(frame)
        print("inject %d: %s %s -> %s" % (index + 1, args.proto, args.src, args.dst))
        time.sleep(0.4)


if __name__ == "__main__":
    main()
