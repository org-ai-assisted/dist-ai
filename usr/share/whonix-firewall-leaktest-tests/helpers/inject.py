#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
L2 packet injector for the leak-test harness.

Builds a frame from scratch and injects it via AF_PACKET at the gateway's MAC,
bypassing the workstation's own IP stack -- so the gateway processes exactly the
crafted packet (e.g. a forged source address a normal socket could never send).

Supported --proto values:
  tcp6   IPv6 TCP SYN (forged-source uRPF probe; --flags to vary TCP flags)
  icmp6  IPv6 ICMP echo request (non-TCP forward-leak probe)
  udp6   IPv6 UDP datagram to --dport (non-DNS UDP forward-leak probe)
"""

import argparse
import socket
import struct
import subprocess
import sys
import time


def a6(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, addr)


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total = (total >> 16) + (total & 0xFFFF)
    return (~total) & 0xFFFF


def ip6_pseudo(src: str, dst: str, length: int, next_header: int) -> bytes:
    return a6(src) + a6(dst) + struct.pack("!I", length) + struct.pack("!I", next_header)


def tcp6(src: str, dst: str, sport: int, dport: int, seq: int, flags: int) -> bytes:
    segment = struct.pack(
        "!HHIIHHHH", sport, dport, seq, 0, (5 << 12) | flags, 8192, 0, 0
    )
    csum = checksum16(ip6_pseudo(src, dst, len(segment), 6) + segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def icmp6_echo(src: str, dst: str) -> bytes:
    body = struct.pack("!BBHHH", 128, 0, 0, 0x1337, 1) + b"leaktest-probe"
    csum = checksum16(ip6_pseudo(src, dst, len(body), 58) + body)
    return body[:2] + struct.pack("!H", csum) + body[4:]


def udp6(src: str, dst: str, sport: int, dport: int) -> bytes:
    payload = b"leaktest-probe"
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = checksum16(ip6_pseudo(src, dst, len(header) + len(payload), 17) + header + payload)
    return header[:6] + struct.pack("!H", csum or 0xFFFF) + payload


TCP_FLAGS = {"syn": 0x02, "ack": 0x10, "synack": 0x12, "finack": 0x11, "rstack": 0x14}


def resolve_gw_mac(gw4: str) -> bytes:
    proc = subprocess.run(
        ["ip", "neigh", "show", gw4], capture_output=True, text=True, check=False
    )
    if "lladdr" not in proc.stdout:
        subprocess.run(
            ["ping", "-c1", "-W1", gw4], capture_output=True, check=False
        )
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proto", required=True, choices=["tcp6", "icmp6", "udp6"])
    parser.add_argument("--iface", default="eth0")
    parser.add_argument("--gw4", required=True, help="gateway IPv4 for MAC resolution")
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--sport", type=int, default=41444)
    parser.add_argument("--dport", type=int, default=443)
    parser.add_argument("--flags", default="syn", choices=sorted(TCP_FLAGS))
    parser.add_argument("--count", type=int, default=4)
    args = parser.parse_args()

    gw_mac = resolve_gw_mac(args.gw4)
    src_mac = own_mac(args.iface)

    if args.proto == "tcp6":
        payload = tcp6(args.src, args.dst, args.sport, args.dport, 601, TCP_FLAGS[args.flags])
        next_header = 6
    elif args.proto == "icmp6":
        payload = icmp6_echo(args.src, args.dst)
        next_header = 58
    else:
        payload = udp6(args.src, args.dst, args.sport, args.dport)
        next_header = 17
    ip6 = b"\x60\x00\x00\x00" + struct.pack("!HBB", len(payload), next_header, 64)
    ip6 += a6(args.src) + a6(args.dst)
    frame = gw_mac + src_mac + b"\x86\xdd" + ip6 + payload

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    for index in range(args.count):
        sock.send(frame)
        print(
            "inject %d: %s %s -> %s" % (index + 1, args.proto, args.src, args.dst)
        )
        time.sleep(0.4)


if __name__ == "__main__":
    main()
