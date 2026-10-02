#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Test-only fake privleapd comm socket for the use_leaprun.sh lib tests.

use_leaprun.sh's reachability check does a real connect() to the per-user
AF_UNIX socket, so the fixture cannot fake "privleapd is up" with a mere
`touch` (a regular file, or a dead socket inode, refuses connect()). This
helper creates the two socket states the tests need:

  listen <path> <ready_marker>
      bind + listen on the AF_UNIX stream socket at <path>, create
      <ready_marker> once it is accepting connections, then block until
      killed. A connect() succeeds -> privleapd reachable.

  stale <path>
      bind then close WITHOUT unlinking, leaving a dead socket inode at
      <path>, then exit. A connect() is refused -> stale leftover socket.
"""

import signal
import socket
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print(f"{sys.argv[0]}: ERROR: mode required (listen|stale)", file=sys.stderr)
        return 2
    mode = sys.argv[1]

    if mode == "stale":
        if len(sys.argv) != 3:
            print(f"{sys.argv[0]}: ERROR: usage: stale <path>", file=sys.stderr)
            return 2
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(sys.argv[2])
        sock.close()
        return 0

    if mode == "listen":
        if len(sys.argv) != 4:
            print(
                f"{sys.argv[0]}: ERROR: usage: listen <path> <ready_marker>",
                file=sys.stderr,
            )
            return 2
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(sys.argv[2])
        ## A backlog makes connect() complete at the kernel even without a
        ## userspace accept(), which is all the reachability probe needs.
        sock.listen(10)
        with open(sys.argv[3], "w", encoding="utf-8"):
            pass
        signal.pause()
        return 0

    print(f"{sys.argv[0]}: ERROR: unknown mode '{mode}'", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
