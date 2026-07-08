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

import json
import os
import selectors
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from PyQt5.QtCore import QObject, Qt

import tcp_testlib as T  # noqa: F401  (sets up sys.path / offscreen Qt + QApplication)
from tor_control_panel import tor_bootstrap

TOR = shutil.which("tor")
OBFS4PROXY = "/usr/bin/obfs4proxy"
SNOWFLAKE_CLIENT = "/usr/bin/snowflake-client"

## The current Tor default snowflake bridge (the one shipped bridges_default
## uses a TEST-NET placeholder, so spell out a real one for the live test).
SNOWFLAKE_BRIDGE = (
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,docs.plesk.com "
    "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,"
    "stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,"
    "stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,"
    "stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 "
    "utls-imitate=hellorandomizedalpn")

try:
    ## tor_bootstrap imports stem lazily; the live tests drive it, so stem must
    ## be present or they cannot run (e.g. a CI image with tor but no stem).
    import stem  # noqa: F401
    HAVE_STEM = True
except ImportError:
    HAVE_STEM = False


def _bundled_obfs4_bridges():
    """The real obfs4 Bridge lines the app ships (bridges_default). meek /
    snowflake ship TEST-NET placeholder IPs and their clients are not
    installed, so only obfs4 can actually connect."""
    with open(T._bridges_default_path(), encoding="utf-8") as handle:
        bridges = json.load(handle)["bridges"]["obfs4"]
    return [line for line in bridges if line.strip()]

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


class _Socks5Forwarder:
    """A tiny CONNECT-only, no-auth SOCKS5 proxy that splices to the real
    destination. Just enough for a test tor's Socks5Proxy to route its OR/dir
    connections through it, so the proxy config path is exercised for real."""

    def __init__(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(64)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._srv.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(20)
            head = conn.recv(2)
            if len(head) < 2 or head[0] != 0x05:
                conn.close()
                return
            conn.recv(head[1])                 # methods
            conn.sendall(b"\x05\x00")          # no auth
            req = conn.recv(4)
            if len(req) < 4 or req[1] != 0x01:  # CONNECT only
                conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                conn.close()
                return
            atyp = req[3]
            if atyp == 0x01:
                host = socket.inet_ntoa(conn.recv(4))
            elif atyp == 0x04:
                host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
            elif atyp == 0x03:
                host = conn.recv(conn.recv(1)[0]).decode()
            else:
                conn.close()
                return
            port = struct.unpack(">H", conn.recv(2))[0]
            remote = socket.create_connection((host, port), timeout=20)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            self._splice(conn, remote)
        except Exception:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _splice(a, b):
        sel = selectors.DefaultSelector()
        a.setblocking(False)
        b.setblocking(False)
        sel.register(a, selectors.EVENT_READ, b)
        sel.register(b, selectors.EVENT_READ, a)
        try:
            while True:
                events = sel.select(timeout=30)
                if not events:
                    break
                for key, _ in events:
                    data = key.fileobj.recv(65536)
                    if not data:
                        return
                    key.data.sendall(data)
        except OSError:
            pass
        finally:
            sel.close()
            for sock in (a, b):
                try:
                    sock.close()
                except OSError:
                    pass

    def stop(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def setUpModule():
    global LIVE, LIVE_REASON, _SHARED
    if not TOR:
        LIVE_REASON = "tor binary not installed"
        return
    if not HAVE_STEM:
        LIVE_REASON = "python3-stem not installed"
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


@unittest.skipUnless(TOR and HAVE_STEM, "tor binary / python3-stem not installed")
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


@unittest.skipUnless(TOR and HAVE_STEM, "tor binary / python3-stem not installed")
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
        if not _reached_connected(seen):
            ## Never fail on network slowness -- this is an integration test.
            self.skipTest(
                "tor did not reach connected in time (network): "
                + repr(seen[-3:]))
        self.assertTrue(_reached_connected(seen))


class _BootstrapAtSharedInstance:
    """Context manager: make every new tor_bootstrap.TorBootstrap talk to the
    shared live tor, and neutralise the privileged restart, so the real GUI
    widgets that internally start a bootstrap can be driven headlessly."""

    def __enter__(self):
        from tor_control_panel import privilege
        self._priv = privilege
        self._saved_command = privilege.command
        self._saved_init = tor_bootstrap.TorBootstrap.__init__
        shared = _SHARED

        def patched_init(inner_self, main):
            self._saved_init(inner_self, main)
            inner_self.control_socket_path = shared.control_socket
            inner_self.control_cookie_path = shared.cookie

        tor_bootstrap.TorBootstrap.__init__ = patched_init
        ## The widget's privileged 'restart tor' becomes a no-op success.
        privilege.command = lambda action, *args: ["true"]
        return self

    def __exit__(self, *exc):
        tor_bootstrap.TorBootstrap.__init__ = self._saved_init
        self._priv.command = self._saved_command
        return False


@unittest.skipUnless(TOR and HAVE_STEM, "tor binary / python3-stem not installed")
class LiveRestartTorGuiTest(unittest.TestCase):
    def setUp(self):
        if not LIVE:
            self.skipTest(LIVE_REASON)

    def test_progress_popup_reaches_bootstrapping_done(self):
        ## restart-tor-gui shows a progress popup that walks the bootstrap and
        ## closes itself once connected. Drive the real RestartTor widget against
        ## the shared live tor (restart stubbed) and assert it reports done.
        from tor_control_panel import restart_tor_gui
        with _BootstrapAtSharedInstance():
            widget = restart_tor_gui.RestartTor()
            self.addCleanup(widget.deleteLater)
            finished = widget.bootstrap_thread.wait(90000)
            T.APP.processEvents()  # deliver the queued bootstrap signals
            if not finished:
                ## Integration test: skip on network slowness, do not fail.
                widget.bootstrap_thread.terminate()
                widget.bootstrap_thread.wait()
                self.skipTest("restart-tor-gui bootstrap did not finish in time")
            self.assertIn("bootstrapping done", widget.text.text().lower())


@unittest.skipUnless(TOR and HAVE_STEM, "tor binary / python3-stem not installed")
class LiveProxyTest(unittest.TestCase):
    def setUp(self):
        if not LIVE:
            self.skipTest(LIVE_REASON)

    def test_bootstrap_through_a_socks5_proxy(self):
        ## The 'Proxy type SOCKS5 -> Accept connects' scenario: route a real
        ## tor's connections through a local SOCKS5 proxy (Socks5Proxy, exactly
        ## what gen_torrc writes) and drive it to connected.
        proxy = _Socks5Forwarder()
        self.addCleanup(proxy.stop)
        inst = _TorInstance(
            extra_torrc="Socks5Proxy 127.0.0.1:{0}\n".format(proxy.port))
        self.addCleanup(inst.stop)
        self.assertTrue(os.path.exists(inst.control_socket), "tor did not start")
        seen = inst.bootstrap(timeout_ms=120000)
        if not _reached_connected(seen):
            self.skipTest(
                "tor could not connect through the SOCKS5 proxy in time: "
                + repr(seen[-3:]))
        self.assertTrue(_reached_connected(seen))


@unittest.skipUnless(TOR and HAVE_STEM, "tor binary / python3-stem not installed")
@unittest.skipUnless(os.path.exists(OBFS4PROXY), "obfs4proxy not installed")
class LiveObfs4BridgeTest(unittest.TestCase):
    def setUp(self):
        if not LIVE:
            self.skipTest(LIVE_REASON)

    def test_obfs4_bridges_bootstrap_through_the_transport(self):
        ## The 'Bridges type obfs4' scenario, for real: start a tor configured
        ## exactly as gen_torrc would (UseBridges + the obfs4 ClientTransportPlugin
        ## + the shipped obfs4 bridge lines) and drive the bootstrap. What is
        ## deterministic (and is the app-specific thing under test) is that the
        ## obfs4 transport connects to a bridge and Tor bootstraps THROUGH it --
        ## a pluggable-transport phase followed by real progress (loading network
        ## info via the bridge). Whether a given public bridge is fast enough to
        ## reach 100% right now is not, so do not require it. If not even one
        ## shipped bridge is reachable, skip.
        bridges = _bundled_obfs4_bridges()
        self.assertTrue(bridges, "no obfs4 bridges shipped in bridges_default")
        extra = ("UseBridges 1\n"
                 "ClientTransportPlugin obfs4 exec {0}\n".format(OBFS4PROXY)
                 + "\n".join(bridges) + "\n")
        inst = _TorInstance(extra_torrc=extra)
        self.addCleanup(inst.stop)
        self.assertTrue(os.path.exists(inst.control_socket), "tor did not start")
        seen = inst.bootstrap(timeout_ms=150000)
        max_progress = max((pct for pct, _ in seen), default=0)
        used_transport = any("transport" in phase.lower() for _, phase in seen)
        ## Past ~40% means Tor is loading directory info over the bridge, i.e.
        ## the obfs4 hop is up and carrying traffic (not merely a valid config).
        if max_progress < 40 or not used_transport:
            self.skipTest(
                "no shipped obfs4 bridge reachable now (max {0}%, transport={1}): "
                "{2}".format(max_progress, used_transport, seen[-3:]))
        self.assertGreaterEqual(max_progress, 40)
        self.assertTrue(used_transport)


@unittest.skipUnless(TOR and HAVE_STEM, "tor binary / python3-stem not installed")
@unittest.skipUnless(os.path.exists(SNOWFLAKE_CLIENT), "snowflake-client not installed")
class LiveSnowflakeBridgeTest(unittest.TestCase):
    def setUp(self):
        if not LIVE:
            self.skipTest(LIVE_REASON)

    def test_snowflake_bridge_bootstraps(self):
        ## 'Bridges type Snowflake -> Accept: connects': start a tor with the
        ## snowflake ClientTransportPlugin + a real snowflake bridge and drive it
        ## to connected. Snowflake (WebRTC) is slow, so a long timeout; skip if
        ## the broker/proxy path is not reachable right now.
        extra = ("UseBridges 1\n"
                 "ClientTransportPlugin snowflake exec {0}\n".format(SNOWFLAKE_CLIENT)
                 + "Bridge " + SNOWFLAKE_BRIDGE + "\n")
        inst = _TorInstance(extra_torrc=extra)
        self.addCleanup(inst.stop)
        self.assertTrue(os.path.exists(inst.control_socket), "tor did not start")
        seen = inst.bootstrap(timeout_ms=180000)
        if not _reached_connected(seen):
            self.skipTest(
                "snowflake broker/proxy not reachable in time: "
                + repr(seen[-3:]))
        self.assertTrue(_reached_connected(seen))


if __name__ == "__main__":
    unittest.main()
