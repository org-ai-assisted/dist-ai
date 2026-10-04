#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
External-side port listener for the gateway INPUT reachability leak test.

Binds the Tor-facing ports (SocksPort, TransPort, ControlPort) and ssh plus the
DnsPort on the given addresses, so the firewall -- not a dead port -- is what a
reachability probe from the upstream/NAT side measures. Binding WIDE (0.0.0.0 /
::) on purpose: it models the worst case the audit guards against (a Tor port
bound to 0.0.0.0), so a probe that still cannot reach the port from the external
namespace proves the INPUT chain drops it regardless of bind address.

argv: <ipv4-bind-address> <ipv6-bind-address>  (e.g. 0.0.0.0 ::)

TCP ports accept-and-close; the UDP DnsPort echoes, so a probe can tell a dropped
datagram (no echo) from a delivered one (echo). Runs until killed; never talks to
a real network.
"""

import socket
import sys
import threading
import time

## SocksPort 9050, TransPort 9040, ControlPort 9051, ssh 22 -- every port the
## gateway must NOT expose on its external (upstream/NAT) side.
TCP_PORTS = (22, 9040, 9050, 9051)
## DnsPort 5300.
UDP_PORTS = (5300,)


def bind_socket(family: int, kind: int, addr: str, port: int) -> socket.socket:
    sock = socket.socket(family, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((addr, port))
    return sock


def serve_tcp(sock: socket.socket) -> None:
    sock.listen(64)
    while True:
        try:
            conn, _peer = sock.accept()
            conn.close()
        except OSError:
            break


def serve_udp(sock: socket.socket) -> None:
    while True:
        try:
            data, peer = sock.recvfrom(4096)
            sock.sendto(data, peer)
        except OSError:
            break


def main() -> None:
    if len(sys.argv) not in (3, 4):
        print("ext_listener: usage: ext_listener.py <ipv4-bind> <ipv6-bind> [ready-file]",
              file=sys.stderr)
        sys.exit(1)
    addr4, addr6 = sys.argv[1], sys.argv[2]
    ready_file = sys.argv[3] if len(sys.argv) == 4 else None
    ## Bind EVERY socket up front, before serving: a bind failure then raises here
    ## and exits the process non-zero (the launcher's readiness wait sees it die),
    ## never a half-bound set where a probe reads 'blocked' for the wrong reason --
    ## a transient first-start miss the old 'start threads, sleep 1' could hide.
    served = []
    for family, addr in ((socket.AF_INET, addr4), (socket.AF_INET6, addr6)):
        for port in TCP_PORTS:
            served.append((serve_tcp, bind_socket(family, socket.SOCK_STREAM, addr, port)))
        for port in UDP_PORTS:
            served.append((serve_udp, bind_socket(family, socket.SOCK_DGRAM, addr, port)))
    for serve, sock in served:
        threading.Thread(target=serve, args=(sock,), daemon=True).start()
    ## Every socket is bound and serving: signal readiness so the launcher stops
    ## waiting and the first probe cannot race an unbound port.
    if ready_file is not None:
        open(ready_file, 'w').close()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
