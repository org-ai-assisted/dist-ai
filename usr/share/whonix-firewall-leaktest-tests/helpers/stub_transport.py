#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Stub Tor TransPort / DnsPort for the leak-test harness.

A listening TCP socket is enough for the kernel to emit SYN-ACK on an incoming
SYN (before accept()), which is what the transparent-proxy path and the leak
reply-egress both depend on. Binds TCP 9040 (TransPort) and UDP 5300 (DnsPort),
IPv4 and IPv6. Runs until killed. Never talks to a real network.
"""

import socket
import threading
import time


def serve_tcp(family: int, addr: str) -> None:
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((addr, 9040))
    sock.listen(64)
    while True:
        try:
            conn, _ = sock.accept()
            conn.close()
        except OSError:
            break


def serve_udp(family: int, addr: str) -> None:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        ## Reply FROM the address the query was sent to (the redirect's DNAT target),
        ## as a real Tor DnsPort bound to a specific address does -- NOT from a
        ## route-chosen source. Only then does conntrack recognise the reply and
        ## un-NAT it, so a forged-source DnsPort reply egresses (the leak under test).
        ## A wildcard bind that lets the kernel pick the source would silently mask it.
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        sock.bind((addr, 5300))
        while True:
            try:
                _data, ancdata, _flags, peer = sock.recvmsg(4096, socket.CMSG_SPACE(64))
                reply_anc = []
                for level, ctype, cdata in ancdata:
                    if level == socket.IPPROTO_IPV6 and ctype == socket.IPV6_PKTINFO:
                        ## keep the 16-byte dst address as the reply SOURCE; zero the
                        ## ifindex so the kernel still routes the reply normally.
                        reply_anc = [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO,
                                      cdata[:16] + b"\x00\x00\x00\x00")]
                        break
                sock.sendmsg([b""], reply_anc, 0, peer)
            except OSError:
                break
        return
    sock.bind((addr, 5300))
    while True:
        try:
            _data, peer = sock.recvfrom(4096)
            sock.sendto(b"", peer)
        except OSError:
            break


def main() -> None:
    for target, family, addr in (
        (serve_tcp, socket.AF_INET6, "::"),
        (serve_tcp, socket.AF_INET, "0.0.0.0"),
        (serve_udp, socket.AF_INET6, "::"),
        (serve_udp, socket.AF_INET, "0.0.0.0"),
    ):
        threading.Thread(target=target, args=(family, addr), daemon=True).start()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
