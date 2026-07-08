#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Live-Tor integration tests: drive the application's OWN tor_bootstrap.TorBootstrap
against a throwaway tor daemon that actually connects to the Tor network, so the
"bootstraps to connected" scenarios from arraybolt3's manual plan run
automatically instead of needing a human.

Each test spins up its own tor (temp DataDirectory + ControlSocket + cookie auth,
no privilege / no system tor involved) and asserts real behaviour:
  * a direct bootstrap reaches 'Connected to the Tor network!' at 100%;
  * starting with DisableNetwork 1, TorBootstrap toggles it to 0 and still
    reaches connected (the Enable-network path);
  * a bootstrapped tor accepts a NEWNYM ('Request new Tor circuit').

These need the tor binary AND working Tor network reachability. setUpModule
probes once (one shared bootstrap); if tor cannot connect (e.g. a network-less
CI runner) every test SKIPS immediately rather than each waiting out a timeout.
The still-manual scenarios (obfs4/snowflake/meek actually connecting, a live
proxy, Onion Circuits) stay in test_manual_plan.py -- their configs are already
proven valid by test_torrc_applied.py; only the flaky live connection is manual.
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest

from PyQt5.QtCore import QObject, Qt

import tcp_testlib as T  # noqa: F401  (sets up sys.path / offscreen Qt + QApplication)
from tor_control_panel import tor_bootstrap

TOR = shutil.which("tor")

## Populated by setUpModule: whether a real bootstrap succeeded, and the shared
## instance kept alive for the connected-state tests.
LIVE = False
LIVE_REASON = "not probed"
_SHARED = None


class _TorInstance:
    """A throwaway tor with a ControlSocket, cookie auth, and its own dirs."""

    def __init__(self, extra_torrc=""):
        self.dir = tempfile.mkdtemp(prefix="tcp-livetor-")
        self.data = os.path.join(self.dir, "data")
        os.mkdir(self.data)
        os.chmod(self.data, 0o700)
        self.control_socket = os.path.join(self.dir, "control")
        self.cookie = os.path.join(self.data, "control_auth_cookie")
        torrc = os.path.join(self.dir, "torrc")
        with open(torrc, "w", encoding="utf-8") as handle:
            handle.write(
                "DataDirectory {0}\n".format(self.data)
                + "ControlSocket {0}\n".format(self.control_socket)
                + "CookieAuthentication 1\n"
                + "SocksPort auto\n"
                + extra_torrc)
        self.proc = subprocess.Popen(
            [TOR, "-f", torrc],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ## Wait for the control socket to appear (tor is starting up).
        for _ in range(75):
            if os.path.exists(self.control_socket):
                break
            time.sleep(0.2)

    def bootstrap(self, timeout_ms):
        """Run the app's TorBootstrap against this instance; return the list of
        (percent, phase) it emitted (empty if the thread never started)."""
        parent = QObject()
        thread = tor_bootstrap.TorBootstrap(parent)
        thread.control_socket_path = self.control_socket
        thread.control_cookie_path = self.cookie
        seen = []
        thread.signal.connect(
            lambda phase, pct: seen.append((pct, phase)), Qt.DirectConnection)
        thread.start()
        finished = thread.wait(timeout_ms)
        if not finished:
            thread.terminate()
            thread.wait()
        parent.deleteLater()
        return seen

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=15)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


def _reached_connected(seen):
    return any(pct == 100 for pct, _ in seen) and any(
        "Connected to the Tor network" in phase for _, phase in seen)


def setUpModule():
    global LIVE, LIVE_REASON, _SHARED
    if not TOR:
        LIVE_REASON = "tor binary not installed"
        return
    inst = _TorInstance()
    if not os.path.exists(inst.control_socket):
        inst.stop()
        LIVE_REASON = "tor did not start (no control socket)"
        return
    ## One real bootstrap, ~10-40s; reused by the connected-state tests.
    seen = inst.bootstrap(timeout_ms=90000)
    if _reached_connected(seen):
        LIVE = True
        _SHARED = inst
    else:
        inst.stop()
        LIVE_REASON = "tor could not reach the network (no direct Tor access)"


def tearDownModule():
    if _SHARED is not None:
        _SHARED.stop()


@unittest.skipUnless(TOR, "tor binary not installed")
class LiveBootstrapTest(unittest.TestCase):
    def setUp(self):
        if not LIVE:
            self.skipTest(LIVE_REASON)

    def test_direct_bootstrap_reaches_connected(self):
        ## The shared instance (setUpModule) bootstrapped directly; re-run the
        ## tracker against it to assert the app reports fully connected.
        seen = _SHARED.bootstrap(timeout_ms=90000)
        self.assertTrue(
            _reached_connected(seen),
            "expected 'Connected to the Tor network!' at 100%, got: "
            + repr(seen[-3:]))

    def test_newnym_requests_new_circuit(self):
        ## 'Request new Tor circuit' sends NEWNYM; a bootstrapped tor must accept
        ## it without error (same operation TorControlPanel.newnym performs).
        import stem
        import stem.control
        controller = stem.control.Controller.from_socket_file(
            _SHARED.control_socket)
        self.addCleanup(controller.close)
        controller.authenticate(_SHARED.cookie)
        controller.signal(stem.Signal.NEWNYM)  # must not raise


@unittest.skipUnless(TOR, "tor binary not installed")
class LiveDisableNetworkTest(unittest.TestCase):
    def setUp(self):
        if not LIVE:
            self.skipTest(LIVE_REASON)

    def test_disablenetwork_one_is_toggled_and_bootstraps(self):
        ## Enable-network path: a tor started with DisableNetwork 1 is idle;
        ## TorBootstrap flips it to 0 (tor_bootstrap.run) and bootstraps through
        ## to connected.
        inst = _TorInstance(extra_torrc="DisableNetwork 1\n")
        self.addCleanup(inst.stop)
        self.assertTrue(os.path.exists(inst.control_socket),
                        "tor did not start")
        seen = inst.bootstrap(timeout_ms=90000)
        self.assertTrue(
            _reached_connected(seen),
            "DisableNetwork 1 -> enable path did not reach connected: "
            + repr(seen[-3:]))


if __name__ == "__main__":
    unittest.main()
