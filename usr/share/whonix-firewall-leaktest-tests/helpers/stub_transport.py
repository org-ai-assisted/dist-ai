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
    sock.bind((addr, 5300))
    while True:
        try:
            data, peer = sock.recvfrom(4096)
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
