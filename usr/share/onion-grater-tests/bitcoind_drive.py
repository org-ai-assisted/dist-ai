#!/usr/bin/env python3
"""
Drive the REAL bitcoind (30.2) through the real onion-grater filter, using the
shipped 40_bitcoind.yml profile.

Stands up the throwaway offline tor + onion-grater (bitcoind profile, debug
logging) from the e2e module, points bitcoind's -torcontrol at the filtered
control port over the veth IP, and lets bitcoind run long enough to publish its
P2P onion service (the ADD_ONION it issues at startup). We then show bitcoind's
real control commands as seen by onion-grater and confirm its ADD_ONION was
ALLOWED (rewritten + proxied), not filtered.

bitcoin-qt uses the identical torcontrol code path; testing bitcoind exercises
the same profile.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import time

import e2e

WORKDIR = e2e.WORKDIR
DATADIR = os.path.join(WORKDIR, "bitcoin-datadir")
OG_DEBUG_LOG = os.path.join(WORKDIR, "og-bitcoind-debug.log")
BTC_LOG = os.path.join(WORKDIR, "bitcoind.console.log")
TOR_SOCKS = 19050


def write_torrc_with_socks():
    os.makedirs(e2e.TORDIR, exist_ok=True)
    os.chmod(e2e.TORDIR, 0o700)
    with open(e2e.TORRC, "w") as handle:
        handle.write(
            "DataDirectory {0}\n"
            "ControlPort 127.0.0.1:9052\n"
            "CookieAuthentication 1\n"
            "CookieAuthFile {1}\n"
            "SocksPort 127.0.0.1:{2}\n"
            "DisableNetwork 1\n"
            "Log notice file {3}\n".format(
                e2e.TORDIR, e2e.COOKIE, TOR_SOCKS, e2e.TORLOG)
        )


def start_og_debug():
    out = open(OG_DEBUG_LOG, "w")
    proc = subprocess.Popen(
        ["python3", e2e.OG_BIN,
         "--listen-address", e2e.VETH_IP,
         "--listen-port", str(e2e.OG_PORT),
         "--control-cookie-path", e2e.COOKIE,
         "--debug"],
        stdout=out, stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(50):
            try:
                with socket.create_connection((e2e.VETH_IP, e2e.OG_PORT),
                                              timeout=1):
                    return proc, out
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("onion-grater did not come up")
    except BaseException:
        e2e.stop(proc)
        out.close()
        raise


def run_bitcoind():
    # Start from a clean datadir so the result checks never see a previous
    # run's debug.log (which would make a broken run look green).
    shutil.rmtree(DATADIR, ignore_errors=True)
    os.makedirs(DATADIR, exist_ok=True)
    args = [
        "bitcoind",
        "-datadir=" + DATADIR,
        "-chain=main",
        "-torcontrol={0}:{1}".format(e2e.VETH_IP, e2e.OG_PORT),
        "-onion=127.0.0.1:{0}".format(TOR_SOCKS),
        "-listen=1", "-listenonion=1",
        "-onlynet=onion", "-connect=0", "-dnsseed=0",
        "-blocksonly=1", "-dbcache=50", "-prune=550",
        "-debug=tor", "-printtoconsole=0", "-daemon=0",
    ]
    with open(BTC_LOG, "w") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        # Let bitcoind initialise and publish its onion service.
        deadline = time.time() + 45
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            dbg = os.path.join(DATADIR, "debug.log")
            if os.path.exists(dbg):
                txt = open(dbg, errors="replace").read()
                if "ADD_ONION successful" in txt or "Got tor service ID" in txt \
                   or "Command filtered" in txt:
                    break
            time.sleep(1)
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


def main():
    tor = og = out = None
    try:
        e2e.setup_veth_ip()
        write_torrc_with_socks()
        tor = e2e.start_tor()
        e2e.set_profile("40_bitcoind.yml")
        og, out = start_og_debug()
        print("running real bitcoind through the filter (offline tor)...\n")
        run_bitcoind()
    finally:
        e2e.stop(og)
        if out:
            out.close()
        e2e.stop(tor)
        e2e.cleanup_profile()
        e2e.teardown_veth_ip()

    debug = open(OG_DEBUG_LOG).read() if os.path.exists(OG_DEBUG_LOG) else ""
    btc_dbg_path = os.path.join(DATADIR, "debug.log")
    btc_dbg = open(btc_dbg_path, errors="replace").read() \
        if os.path.exists(btc_dbg_path) else ""

    sent = re.findall(r"-> (.+)", debug)
    filtered = re.findall(r"command filtered: (.+)", debug)
    rewrites = re.findall(r"rewrote command:\n(.+?)\nto:\n(.+?)\n", debug, re.S)

    print("bitcoind control commands seen by onion-grater:")
    for line in sent:
        print("  -> " + line.strip())
    print()
    if rewrites:
        print("onion-grater rewrote:")
        for old, new in rewrites:
            print("  {0}  =>  {1}".format(old.strip(), new.strip()))
        print()
    if filtered:
        print("onion-grater FILTERED (blocked):")
        for f in filtered:
            print("  x  " + f.strip())
        print()

    add_onion_sent = any(s.upper().startswith("ADD_ONION") for s in sent)
    add_onion_blocked = any(f.upper().startswith("ADD_ONION") for f in filtered)
    got_service = ("ADD_ONION successful" in btc_dbg) or \
                  bool(re.search(r"Got tor service ID (\w+)", btc_dbg))
    btc_tor_err = [l for l in btc_dbg.splitlines()
                   if "tor:" in l and ("error" in l.lower()
                                       or "fail" in l.lower()
                                       or "denied" in l.lower())]

    results = []

    def check(label, cond):
        results.append(bool(cond))
        print("  [{0}] {1}".format("ok  " if cond else "FAIL", label))

    print("results:")
    check("bitcoind issued ADD_ONION through the filter", add_onion_sent)
    check("ADD_ONION was ALLOWED (not filtered)",
          add_onion_sent and not add_onion_blocked)
    check("tor returned a service ID to bitcoind (onion published)",
          got_service)
    if btc_tor_err:
        print("\nbitcoind tor errors (excerpt):")
        for l in btc_tor_err[:6]:
            print("  ! " + l.strip()[-160:])
    print("\n(see " + OG_DEBUG_LOG + " and " + btc_dbg_path + ")")
    return 0 if results and all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
