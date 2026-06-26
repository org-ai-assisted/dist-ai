#!/usr/bin/env python3
"""
Full-stack end-to-end reproduction for the onion-grater profile fixes.

Unlike the in-process harness, this runs the REAL moving parts:
  * a real throwaway `tor` (offline: DisableNetwork 1, no network egress) with
    a cookie-authenticated control port on 127.0.0.1:9052,
  * the real `onion-grater` binary filtering that control port, and
  * a real Tor control-protocol client connecting over the veth network
    (10.200.1.0/24) so the hosts:'*' profiles match, exactly as a
    Whonix-Workstation would.

It proves, through the actual socket/stem/tor path:
  A. OLD Bisq profile (SETCONF DisableNetwork.*): an injected second keyword
     reaches Tor and CHANGES its config (deanonymization vector reproduced).
  B. NEW Bisq profile (SETCONF DisableNetwork=[01]): the same injection is
     blocked with 510 and never reaches Tor; the legitimate form still works.
  C. onionshare ADD_ONION: the legitimate request is rewritten + proxied (Tor
     returns a ServiceID); a Flags-injection variant is blocked.
  D. onion_authentication ONION_CLIENT_AUTH_ADD: the profile's own documented
     command is allowed by the filter AND accepted by real Tor (250, the
     credential is registered); malformed / injection variants (wrong key-arg
     order, wrong key algorithm, missing key, a trailing extra keyword) are
     blocked with 510 and never reach Tor.

Requires sudo (for /etc/onion-grater.d and the veth IP) and tor. Cleans up
after itself. Run: sudo-capable user, `python3 e2e.py`.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _resolve_onion_grater():
    """ONION_GRATER_REPO override, else the installed package, else a checkout."""
    repo = os.environ.get("ONION_GRATER_REPO")
    if repo:
        return (os.path.join(repo, "usr/lib/onion-grater"),
                os.path.join(repo, "usr/share/doc/onion-grater-merger/examples"))
    if os.path.exists("/usr/lib/onion-grater"):
        return ("/usr/lib/onion-grater",
                "/usr/share/doc/onion-grater-merger/examples")
    repo = "/home/user/derivative-maker/packages/whonix/onion-grater"
    return (os.path.join(repo, "usr/lib/onion-grater"),
            os.path.join(repo, "usr/share/doc/onion-grater-merger/examples"))


OG_BIN, PROFILES = _resolve_onion_grater()

# All runtime artifacts (tor datadir, logs) go here -- a throwaway temp dir,
# never the script's own directory (which is under version control). Override
# with OG_TEST_WORKDIR to inspect them after a run.
WORKDIR = os.environ.get("OG_TEST_WORKDIR") or tempfile.mkdtemp(prefix="og-e2e-")
TORDIR = os.path.join(WORKDIR, "tordata")
COOKIE = os.path.join(TORDIR, "control.cookie")
TORRC = os.path.join(WORKDIR, "torrc")
TORLOG = os.path.join(WORKDIR, "tor.log")
OG_DROPIN = "/etc/onion-grater.d"
TEST_PROFILE = "40_test.yml"
VETH_IP = "10.200.1.1"
OG_PORT = 19052
TOR_CONTROL = ("127.0.0.1", 9052)

# Track whether THIS run created the drop-in dir / added the veth IP, so
# cleanup only undoes what it created and never touches pre-existing state.
_dropin_preexisted = None
_veth_added = False

results = {"pass": 0, "fail": 0}


def check(label, cond):
    mark = "ok  " if cond else "FAIL"
    if cond:
        results["pass"] += 1
    else:
        results["fail"] += 1
    print("  [{0}] {1}".format(mark, label))


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


# --------------------------------------------------------------------------
# Tor control-protocol client (raw, no stem -- we are the application).
# --------------------------------------------------------------------------

class Control:
    def __init__(self, host, port, cookie_hex=None):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.fp = self.sock.makefile("rwb")
        self.cookie_hex = cookie_hex

    def _send(self, line):
        self.fp.write((line + "\r\n").encode("ascii"))
        self.fp.flush()

    def _read_reply(self):
        lines = []
        while True:
            raw = self.fp.readline()
            if not raw:
                break
            text = raw.decode("ascii", "replace").rstrip("\r\n")
            lines.append(text)
            # Final line: three digits followed by a space.
            if len(text) >= 4 and text[3] == " " and text[:3].isdigit():
                break
        return lines

    def command(self, line):
        self._send(line)
        return self._read_reply()

    def authenticate_filtered(self):
        # onion-grater answers PROTOCOLINFO/AUTHENTICATE itself (NULL auth).
        self.command("PROTOCOLINFO 1")
        return self.command("AUTHENTICATE")

    def authenticate_cookie(self):
        return self.command("AUTHENTICATE " + self.cookie_hex)

    def close(self):
        try:
            self.command("QUIT")
        except OSError:
            pass
        self.fp.close()
        self.sock.close()


def reply_code(lines):
    if not lines:
        return None
    return lines[-1][:3]


# --------------------------------------------------------------------------
# Environment setup / teardown.
# --------------------------------------------------------------------------

def write_torrc():
    os.makedirs(TORDIR, exist_ok=True)
    os.chmod(TORDIR, 0o700)
    with open(TORRC, "w") as handle:
        handle.write(
            "DataDirectory {0}\n"
            "ControlPort 127.0.0.1:9052\n"
            "CookieAuthentication 1\n"
            "CookieAuthFile {1}\n"
            "SocksPort 0\n"
            "DisableNetwork 1\n"
            "Log notice file {2}\n".format(TORDIR, COOKIE, TORLOG)
        )


def start_tor():
    proc = subprocess.Popen(
        ["tor", "-f", TORRC],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError("tor exited early; see " + TORLOG)
            try:
                with socket.create_connection(TOR_CONTROL, timeout=1):
                    if os.path.exists(COOKIE):
                        return proc
            except OSError:
                pass
            time.sleep(0.2)
        raise RuntimeError("tor control port did not come up")
    except BaseException:
        stop(proc)
        raise


def cookie_hex():
    with open(COOKIE, "rb") as handle:
        return handle.read().hex()


def setup_veth_ip():
    global _veth_added
    rc = subprocess.run(
        ["ip", "addr", "show", "dev", "lo"], capture_output=True, text=True)
    if VETH_IP not in rc.stdout:
        sh(["sudo", "ip", "addr", "add", VETH_IP + "/32", "dev", "lo"])
        _veth_added = True


def teardown_veth_ip():
    # Only remove the address if this run added it.
    if _veth_added:
        subprocess.run(
            ["sudo", "ip", "addr", "del", VETH_IP + "/32", "dev", "lo"],
            check=False)


def set_profile(name_or_path):
    global _dropin_preexisted
    if _dropin_preexisted is None:
        _dropin_preexisted = os.path.isdir(OG_DROPIN)
    # Refuse to run against a real onion-grater install rather than deleting
    # its profiles: bail if the drop-in dir already holds any profile other
    # than our own test file.
    if os.path.isdir(OG_DROPIN):
        try:
            stray = [f for f in os.listdir(OG_DROPIN)
                     if f.endswith(".yml") and f != TEST_PROFILE]
        except PermissionError:
            stray = ["<unreadable>"]
        if stray:
            raise RuntimeError(
                "refusing to run: {0} already contains {1} -- this looks "
                "like a real onion-grater install; not touching it".format(
                    OG_DROPIN, stray))
    sh(["sudo", "mkdir", "-p", OG_DROPIN])
    sh(["sudo", "chmod", "0755", OG_DROPIN])
    src = name_or_path if os.path.isabs(name_or_path) \
        else os.path.join(PROFILES, name_or_path)
    dest = os.path.join(OG_DROPIN, TEST_PROFILE)
    sh(["sudo", "cp", src, dest])
    sh(["sudo", "chmod", "0644", dest])


def cleanup_profile():
    # Remove only our test file; remove the dir only if we created it.
    subprocess.run(["sudo", "rm", "-f", os.path.join(OG_DROPIN, TEST_PROFILE)],
                   check=False)
    if _dropin_preexisted is False:
        subprocess.run(["sudo", "rmdir", OG_DROPIN], check=False)


def start_onion_grater(tag):
    out = open(os.path.join(WORKDIR, "og-{0}.log".format(tag)), "w")
    proc = subprocess.Popen(
        ["python3", OG_BIN,
         "--listen-address", VETH_IP,
         "--listen-port", str(OG_PORT),
         "--control-cookie-path", COOKIE],
        stdout=out, stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(50):
            if proc.poll() is not None:
                raise RuntimeError(
                    "onion-grater exited early; see og-{0}.log".format(tag))
            try:
                with socket.create_connection((VETH_IP, OG_PORT), timeout=1):
                    return proc, out
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("onion-grater listen port did not come up")
    except BaseException:
        stop(proc)
        out.close()
        raise


def stop(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------------
# Direct (unfiltered) Tor access, to observe whether an injection landed.
# --------------------------------------------------------------------------

def tor_getconf(key):
    ctl = Control(*TOR_CONTROL, cookie_hex=cookie_hex())
    try:
        ctl.authenticate_cookie()
        return ctl.command("GETCONF " + key)
    finally:
        ctl.close()


def tor_resetconf(key):
    ctl = Control(*TOR_CONTROL, cookie_hex=cookie_hex())
    try:
        ctl.authenticate_cookie()
        ctl.command("RESETCONF " + key)
    finally:
        ctl.close()


def tor_direct(line):
    # Unfiltered command straight to Tor (cookie auth), to observe Tor's own
    # state -- e.g. whether a client-auth credential actually got registered.
    ctl = Control(*TOR_CONTROL, cookie_hex=cookie_hex())
    try:
        ctl.authenticate_cookie()
        return ctl.command(line)
    finally:
        ctl.close()


def client_command(line):
    ctl = Control(VETH_IP, OG_PORT)
    try:
        ctl.authenticate_filtered()
        return ctl.command(line)
    finally:
        ctl.close()


# --------------------------------------------------------------------------
# Scenarios.
# --------------------------------------------------------------------------

INJECTION = "DisableNetwork=1 ProtocolWarnings=1"   # benign 2nd keyword = proof
LEGIT_SETCONF = "DisableNetwork=1"


def scenario_old_bisq():
    print("A. OLD Bisq profile (SETCONF 'DisableNetwork.*') -- vuln reproduced")
    # Reconstruct the pre-fix profile: same as shipped but the vulnerable
    # SETCONF pattern.
    old = os.path.join(WORKDIR, "40_bisq_OLD.yml")
    with open(os.path.join(PROFILES, "40_bisq.yml")) as handle:
        text = handle.read()
    text = text.replace("'DisableNetwork=[01]'", "'DisableNetwork.*'")
    with open(old, "w") as handle:
        handle.write(text)
    set_profile(old)
    proc, out = start_onion_grater("old")
    try:
        tor_resetconf("ProtocolWarnings")
        legit = client_command("SETCONF " + LEGIT_SETCONF)
        check("legit SETCONF proxied to Tor (250)", reply_code(legit) == "250")
        attack = client_command("SETCONF " + INJECTION)
        check("injection NOT blocked by old filter (not 510)",
              reply_code(attack) != "510")
        landed = tor_getconf("ProtocolWarnings")
        check("injected keyword REACHED Tor and changed config "
              "(ProtocolWarnings=1)",
              any("ProtocolWarnings=1" in ln for ln in landed))
        tor_resetconf("ProtocolWarnings")
    finally:
        stop(proc)
        out.close()


def scenario_new_bisq():
    print("B. NEW Bisq profile (SETCONF 'DisableNetwork=[01]') -- fixed")
    set_profile("40_bisq.yml")
    proc, out = start_onion_grater("new")
    try:
        tor_resetconf("ProtocolWarnings")
        legit = client_command("SETCONF " + LEGIT_SETCONF)
        check("legit SETCONF still proxied to Tor (250)",
              reply_code(legit) == "250")
        attack = client_command("SETCONF " + INJECTION)
        check("injection BLOCKED by new filter (510 Command filtered)",
              reply_code(attack) == "510")
        landed = tor_getconf("ProtocolWarnings")
        check("injected keyword did NOT reach Tor (ProtocolWarnings=0)",
              any("ProtocolWarnings=0" in ln for ln in landed))
    finally:
        stop(proc)
        out.close()


def scenario_onionshare():
    print("C. onionshare profile -- real ADD_ONION rewrite + Flags injection")
    set_profile("40_onionshare.yml")
    proc, out = start_onion_grater("onionshare")
    try:
        legit = client_command("ADD_ONION NEW:ED25519-V3 Port=80,17600")
        code = reply_code(legit)
        service_id = None
        for ln in legit:
            if "ServiceID=" in ln:
                service_id = ln.split("ServiceID=", 1)[1].strip()
        check("legit ADD_ONION proxied to Tor (250 + ServiceID), got {0}"
              .format(code), code == "250" and service_id is not None)
        attack = client_command(
            "ADD_ONION NEW:ED25519-V3 Port=80,17600 Flags=Detach")
        check("ADD_ONION Flags-injection BLOCKED (510)",
              reply_code(attack) == "510")
        if service_id:
            client_command("DEL_ONION " + service_id)
    finally:
        stop(proc)
        out.close()


# A real, checksum-valid v3 onion address and two distinct, Tor-accepted x25519
# client-auth keys. AUTH_ADDR / AUTH_KEY_GOOD are the profile's own documented
# example (so this proves the shipped example is a genuinely working command);
# AUTH_KEY_OTHER is used only in the BLOCKED attempts, so that if any of them
# leaked past the filter the final VIEW would show the wrong key. The service
# need not exist: ONION_CLIENT_AUTH_ADD only registers a credential, it does not
# contact the service, so this stays offline (DisableNetwork 1) and hermetic.
AUTH_ADDR = "m5bmcnsk64naezc26scz2xb3l3n2nd5xobsljljrpvf77tclmykn7wid"
AUTH_KEY_GOOD = "uBKh6DGrkcFxB1adYuyKQltUDDUT9IZrOsne3nfHbHI="
AUTH_KEY_OTHER = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


def scenario_onion_auth():
    print("D. onion_authentication profile -- real ONION_CLIENT_AUTH_ADD "
          "allowed, injections blocked")
    set_profile("40_onion_authentication.yml")
    proc, out = start_onion_grater("onionauth")
    try:
        # Start from a clean slate in case a prior run left it registered.
        tor_direct("ONION_CLIENT_AUTH_REMOVE " + AUTH_ADDR)

        # The profile's own example command: allowed by the filter and accepted
        # by real Tor -- i.e. the shipped profile permits a WORKING auth.
        legit = client_command(
            "ONION_CLIENT_AUTH_ADD {0} x25519:{1}".format(
                AUTH_ADDR, AUTH_KEY_GOOD))
        check("legit ONION_CLIENT_AUTH_ADD proxied to Tor (250)",
              reply_code(legit) == "250")
        view = tor_direct("ONION_CLIENT_AUTH_VIEW " + AUTH_ADDR)
        check("credential registered in real Tor with the good key",
              any(("x25519:" + AUTH_KEY_GOOD) in ln for ln in view))

        # Malformed / injection variants: each must be blocked by the filter
        # (510) and never reach Tor. Each carries AUTH_KEY_OTHER so a leak is
        # detectable below.
        blocked = [
            ("Flags before ClientName (wrong arg order)",
             "{0} x25519:{1} Flags=Permanent ClientName=alice".format(
                 AUTH_ADDR, AUTH_KEY_OTHER)),
            ("wrong key algorithm (ed25519, not x25519)",
             "{0} ed25519:{1}".format(AUTH_ADDR, AUTH_KEY_OTHER)),
            ("missing key blob",
             "{0}".format(AUTH_ADDR)),
            ("trailing extra keyword (argument injection)",
             "{0} x25519:{1} ClientName=alice Evil=1".format(
                 AUTH_ADDR, AUTH_KEY_OTHER)),
        ]
        for label, arg in blocked:
            reply = client_command("ONION_CLIENT_AUTH_ADD " + arg)
            check("blocked by filter (510): " + label,
                  reply_code(reply) == "510")

        # None of the blocked variants reached Tor: the registered key is still
        # the good one, and the attack key is absent.
        view2 = tor_direct("ONION_CLIENT_AUTH_VIEW " + AUTH_ADDR)
        check("no blocked variant leaked to Tor "
              "(good key still registered, attack key absent)",
              any(("x25519:" + AUTH_KEY_GOOD) in ln for ln in view2)
              and not any(AUTH_KEY_OTHER in ln for ln in view2))

        tor_direct("ONION_CLIENT_AUTH_REMOVE " + AUTH_ADDR)
    finally:
        stop(proc)
        out.close()


def main():
    if os.path.isfile("/run/tor/control.authcookie") or \
       subprocess.run(["pgrep", "-x", "tor"],
                      capture_output=True).returncode == 0:
        print("NOTE: a system tor is running; this test starts its own on 9052.")
    tor = None
    try:
        setup_veth_ip()
        write_torrc()
        tor = start_tor()
        print("tor up (offline); control 9052, cookie auth\n")
        scenario_old_bisq()
        scenario_new_bisq()
        scenario_onionshare()
        scenario_onion_auth()
    finally:
        stop(tor)
        cleanup_profile()
        teardown_veth_ip()
    print()
    total = results["pass"] + results["fail"]
    print("{0}/{1} end-to-end checks passed".format(results["pass"], total))
    if results["fail"]:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
