#!/usr/bin/env python3
"""
Adversarial probe: try to make onion-grater forward MORE to the real Tor than a
restrictive profile intends. A test profile allows only `GETINFO version` and
`SETCONF DisableNetwork=[01]`. We then send hand-crafted raw lines and classify
the response:

  510 Command filtered  -> blocked by onion-grater (good)
  anything else (250/5xx) -> the line REACHED real Tor (potential bypass)

For SETCONF injection we append a benign second keyword (ProtocolWarnings=1) and
keep DisableNetwork=1, so even a successful bypass cannot deanonymise (tor stays
offline) -- we only need the response code to tell whether it reached Tor.
"""

import os
import socket
import sys
import time

import e2e

TEST_PROFILE = """\
---
- exe-paths: ['*']
  users: ['*']
  hosts: ['*']
  commands:
    GETINFO:
      - 'version'
    SETCONF:
      - pattern: 'DisableNetwork=[01]'
"""

# (label, raw bytes to send, expected: "block" = should be 510-filtered,
#  "allow" = legitimately reaches Tor)
BATTERY = [
    ("baseline allow: GETINFO version",      b"GETINFO version\r\n",                       "allow"),
    ("baseline allow: SETCONF DN=1",         b"SETCONF DisableNetwork=1\r\n",              "allow"),
    ("forbidden key: GETINFO address",       b"GETINFO address\r\n",                       "block"),
    ("multi-key GETINFO",                    b"GETINFO version address\r\n",               "block"),
    ("trailing arg GETINFO",                 b"GETINFO version foo\r\n",                   "block"),
    ("SETCONF keyword injection (space)",    b"SETCONF DisableNetwork=1 ProtocolWarnings=1\r\n", "block"),
    ("SETCONF injection (tab sep)",          b"SETCONF DisableNetwork=1\tProtocolWarnings=1\r\n", "block"),
    ("SETCONF injection (2 spaces)",         b"SETCONF DisableNetwork=1  ProtocolWarnings=1\r\n", "block"),
    ("SETCONF injection (NUL)",              b"SETCONF DisableNetwork=1\x00ProtocolWarnings=1\r\n", "block"),
    ("SETCONF injection (CR mid)",           b"SETCONF DisableNetwork=1\rSETCONF ProtocolWarnings=1\r\n", "block"),
    ("SETCONF trailing space",               b"SETCONF DisableNetwork=1 \r\n",             "block"),
    ("SETCONF quoted-value smuggle",         b'SETCONF DisableNetwork="1 ProtocolWarnings=1"\r\n', "block"),
    ("tab between cmd and arg",              b"GETINFO\tversion\r\n",                      "?"),
    ("cmd case lower (getinfo)",             b"getinfo version\r\n",                       "allow-ok"),
    ("forbidden cmd: SETCONF DN=2",          b"SETCONF DisableNetwork=2\r\n",              "block"),
    ("forbidden cmd: GETCONF",               b"GETCONF DisableNetwork\r\n",                "block"),
    ("forbidden cmd: SIGNAL",                b"SIGNAL NEWNYM\r\n",                         "block"),
    ("plus-prefixed cmd",                    b"+GETINFO version\r\n",                      "block"),
    ("forbidden: MAPADDRESS",                b"MAPADDRESS 1.2.3.4=evil.com\r\n",           "block"),
]


def drain_reply(fp, sock, timeout=3.0):
    """Read a FULL control reply: lines until the final one (NNN<space>...).
    Returns (reached_tor: bool, summary). A command that gets no reply (a line
    onion-grater rejects as malformed) times out -> not reached."""
    sock.settimeout(timeout)
    lines = []
    try:
        while True:
            raw = fp.readline()
            if not raw:
                break
            t = raw.decode("ascii", "replace").rstrip("\r\n")
            lines.append(t)
            if len(t) >= 4 and t[3] == " " and t[:3].isdigit():
                break  # final line of this reply
    except (socket.timeout, OSError):
        pass
    if not lines:
        return (False, "no-response (rejected/ignored line)")
    final = lines[-1]
    blocked = final.startswith("510")
    return (not blocked, " | ".join(lines)[:70])


def main():
    tor = og = out = None
    try:
        e2e.setup_veth_ip()
        e2e.write_torrc()
        tor = e2e.start_tor()
        prof = os.path.join(e2e.WORKDIR, "40_probe.yml")
        with open(prof, "w") as f:
            f.write(TEST_PROFILE)
        e2e.set_profile(prof)
        og, out = e2e.start_onion_grater("probe")

        def probe_one(raw):
            # Fresh connection per test so a no-response (bad line) can't
            # desync later tests.
            sock = socket.create_connection((e2e.VETH_IP, e2e.OG_PORT), timeout=5)
            fp = sock.makefile("rwb")
            for cmd in (b"PROTOCOLINFO 1\r\n", b"AUTHENTICATE\r\n"):
                fp.write(cmd); fp.flush()
                drain_reply(fp, sock)
            fp.write(raw); fp.flush()
            result = drain_reply(fp, sock)
            try:
                sock.close()
            except OSError:
                pass
            return result

        print("{:<38} {:<9} {}".format("test", "expect", "reply (510=blocked)"))
        print("-" * 78)
        findings = []
        for label, raw, expected in BATTERY:
            reached, summary = probe_one(raw)
            flag = ""
            if expected == "block" and reached:
                flag = "  <<< BYPASS: reached Tor!"
                findings.append((label, raw, summary))
            print("{:<38} {:<9} {}{}".format(label[:38], expected, summary, flag))

        print()
        if findings:
            print("POTENTIAL BYPASSES FOUND:")
            for label, raw, code in findings:
                print("  {!r} -> {}".format(raw, code))
        else:
            print("No bypass: every 'block' case was 510-filtered (or got no "
                  "response). Filter held against this battery.")
        return 1 if findings else 0
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
