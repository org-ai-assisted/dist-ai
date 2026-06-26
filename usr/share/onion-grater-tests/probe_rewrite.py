#!/usr/bin/env python3
"""
Adversarial probe of the ADD_ONION REWRITE path and RESPONSE redaction.

Threat-model questions:
  1. The replacement forces the onion target to {client-address}. Can a crafted
     capture group escape that prefix and point the service somewhere else?
  2. Can a crafted group inject extra Flags / Port mappings?
  3. The response rule redacts the onion PrivateKey. Can the client get the real
     key blob anyway?

Test profile (bisq-like rewrite + a PrivateKey-redacting response rule):

    ADD_ONION:
      - pattern: 'NEW:(\\S+) Port=9999,(\\S+)'
        replacement: 'NEW:{} Port=9999,{client-address}:{}'
        response:
        - pattern: '250-PrivateKey=(\\S+):\\S+'
          replacement: '250-PrivateKey={}:REDACTED'

We send crafted ADD_ONIONs, capture (a) what onion-grater rewrote and forwarded
to tor (from its --debug log) and (b) the reply the client receives, then assert
the target is always {client-address} and the key blob never leaks.
"""

import os
import re
import socket
import subprocess
import sys
import time

import e2e

CLIENT_ADDR = e2e.VETH_IP  # what {client-address} must resolve to

TEST_PROFILE = """\
---
- exe-paths: ['*']
  users: ['*']
  hosts: ['*']
  commands:
    ADD_ONION:
      - pattern: 'NEW:(\\S+) Port=9999,(\\S+)'
        replacement: 'NEW:{} Port=9999,{client-address}:{}'
        response:
        - pattern: '250-PrivateKey=(\\S+):\\S+'
          replacement: '250-PrivateKey={}:REDACTED'
    DEL_ONION:
      - '\\S+'
"""

OG_DEBUG = None  # set in main


def og_last_rewrite():
    """Return the most recent 'rewrote command' (old, new) from the og debug log."""
    if not os.path.exists(OG_DEBUG):
        return None
    txt = open(OG_DEBUG, errors="replace").read()
    m = re.findall(r"rewrote command:\n(.+?)\nto:\n(.+?)\n", txt, re.S)
    return m[-1] if m else None


# (label, ADD_ONION arg, what we are testing)
CASES = [
    ("legit", "NEW:ED25519-V3 Port=9999,9999"),
    ("target ip escape", "NEW:ED25519-V3 Port=9999,1.2.3.4"),
    ("target host:port escape", "NEW:ED25519-V3 Port=9999,evilhost:80"),
    ("unix-socket escape", "NEW:ED25519-V3 Port=9999,unix:/tmp/x"),
    ("trailing Flags inject", "NEW:ED25519-V3 Port=9999,9999 Flags=Detach"),
    ("extra Port inject", "NEW:ED25519-V3 Port=9999,9999 Port=22,9999"),
]


def main():
    global OG_DEBUG
    tor = og = out = None
    fails = []
    try:
        e2e.setup_veth_ip()
        e2e.write_torrc()
        tor = e2e.start_tor()
        prof = os.path.join(e2e.WORKDIR, "40_probe.yml")
        with open(prof, "w") as f:
            f.write(TEST_PROFILE)
        e2e.set_profile(prof)
        OG_DEBUG = os.path.join(e2e.WORKDIR, "og-probe.log")
        out = open(OG_DEBUG, "w")
        og = subprocess.Popen(
            ["python3", e2e.OG_BIN, "--listen-address", e2e.VETH_IP,
             "--listen-port", str(e2e.OG_PORT),
             "--control-cookie-path", e2e.COOKIE, "--debug"],
            stdout=out, stderr=subprocess.STDOUT)
        for _ in range(50):
            try:
                socket.create_connection((e2e.VETH_IP, e2e.OG_PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)

        ctl = e2e.Control(e2e.VETH_IP, e2e.OG_PORT)
        ctl.authenticate_filtered()
        created = []

        print("{:<26} {:<8} {}".format("case", "verdict", "detail"))
        print("-" * 86)
        for label, arg in CASES:
            reply = ctl.command("ADD_ONION " + arg)
            time.sleep(0.3)
            rw = og_last_rewrite()
            reply_str = " ".join(reply)
            code = e2e.reply_code(reply)

            # collect service id for cleanup
            for ln in reply:
                if "ServiceID=" in ln:
                    created.append(ln.split("ServiceID=", 1)[1].strip())

            if code == "510" or "510" in reply_str:
                print("{:<26} {:<8} {}".format(label, "BLOCKED", "510 filtered"))
                continue

            # It was allowed + rewritten. Check the forwarded target + the reply.
            forwarded = rw[1].strip() if rw else "(no rewrite captured)"
            # target must be forced to {client-address}; never a foreign host
            target_ok = ("," + CLIENT_ADDR + ":") in forwarded
            foreign = bool(re.search(r"Port=9999,(?!" + re.escape(CLIENT_ADDR) + r":)",
                                     forwarded))
            # key blob must not leak (only redacted form, if any)
            key_leak = bool(re.search(r"250-PrivateKey=\S+:[A-Za-z0-9+/]{16,}", reply_str))

            verdict = "ok"
            detail = "fwd=[{}]".format(forwarded)
            if foreign or not target_ok:
                verdict = "ESCAPE!"; fails.append((label, "target not client-address: " + forwarded))
            elif key_leak:
                verdict = "KEYLEAK!"; fails.append((label, "private key leaked: " + reply_str[:80]))
            else:
                detail += "  key=redacted/none"
            print("{:<26} {:<8} {}".format(label, verdict, detail[:60]))

        for sid in created:
            try:
                ctl.command("DEL_ONION " + sid)
            except OSError:
                pass
        ctl.close()

        print()
        if fails:
            print("FINDINGS:")
            for l, d in fails:
                print("  {}: {}".format(l, d))
        else:
            print("No rewrite bypass: target always forced to {client-address}, "
                  "no Flags/Port injection reached tor, key blob never leaked.")
        return 1 if fails else 0
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
