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
  frag6  IPv6 atomic fragment (fragment ext-header) carrying a UDP datagram
  exthdr6 IPv6 extension-header chain (--exthdr routing|hopopts|dstopts) over UDP
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


def udp6(src: str, dst: str, sport: int, dport: int) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(PROBE_PAYLOAD), 0)
    csum = checksum16(ip6_pseudo(src, dst, len(header) + len(PROBE_PAYLOAD), 17) + header + PROBE_PAYLOAD)
    return header[:6] + struct.pack("!H", csum or 0xFFFF) + PROBE_PAYLOAD


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


def frag6_atomic(src: str, dst: str, dport: int) -> bytes:
    ## IPv6 fragment extension header (next-header 44) carrying a UDP datagram as a
    ## single atomic fragment (offset 0, M=0): exercises the fragment-header path.
    udp = udp6(src, dst, 41500, dport)
    frag_hdr = struct.pack("!BBHI", 17, 0, 0, 0xABCD)  # nexthdr=UDP, offset0, M=0
    payload = frag_hdr + udp
    return ip6_header(src, dst, len(payload), 44) + payload


## IPv6 extension headers (8-byte minimal forms), each declaring next-header=UDP
## so the L4 is hidden one hop down the chain -- a classic way to try to slip past
## a stateless filter that only inspects the first next-header.
EXTHDR6 = {
    ## Routing header (nexthdr 43), type 0, segments-left 0 (the RH0 shape).
    "routing": (43, struct.pack("!BBBBI", 17, 0, 0, 0, 0)),
    ## Hop-by-Hop options (nexthdr 0) with a PadN option filling the 8 bytes.
    "hopopts": (0, struct.pack("!BBBB", 17, 0, 1, 4) + b"\x00\x00\x00\x00"),
    ## Destination options (nexthdr 60), same PadN filler.
    "dstopts": (60, struct.pack("!BBBB", 17, 0, 1, 4) + b"\x00\x00\x00\x00"),
}


def exthdr6(src: str, dst: str, dport: int, kind: str) -> bytes:
    next_header, header = EXTHDR6[kind]
    payload = header + udp6(src, dst, 41600, dport)
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
        return ETH_P_IPV6, frag6_atomic(args.src, args.dst, args.dport)
    if args.proto == "exthdr6":
        return ETH_P_IPV6, exthdr6(args.src, args.dst, args.dport, args.exthdr)
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--proto", required=True,
        choices=["tcp6", "tcp4", "icmp6", "icmp4", "udp6", "frag6", "exthdr6", "rawip6", "udp4", "rawip4"],
    )
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--gw4", required=True, help="gateway IPv4 for MAC resolution")
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--sport", type=int, default=41444)
    parser.add_argument("--dport", type=int, default=443)
    parser.add_argument("--flags", default="syn", choices=sorted(TCP_FLAGS))
    parser.add_argument("--protonum", type=int, default=47, help="IP proto / next-header for rawip*")
    parser.add_argument("--exthdr", default="routing", choices=sorted(EXTHDR6), help="ext-header for exthdr6")
    parser.add_argument("--count", type=int, default=4)
    args = parser.parse_args()

    ethertype, l3 = build_l3(args)
    frame = resolve_gw_mac(args.gw4) + own_mac(args.iface) + ethertype + l3

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    for index in range(args.count):
        sock.send(frame)
        print("inject %d: %s %s -> %s" % (index + 1, args.proto, args.src, args.dst))
        time.sleep(0.4)


if __name__ == "__main__":
    main()
