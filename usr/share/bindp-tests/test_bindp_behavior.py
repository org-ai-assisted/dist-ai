#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
End-to-end behaviour tests for bindp (usr/src/bindp/bindp.c).

bindp is an LD_PRELOAD shim that rewrites bind()/connect() to a configured source
address and optionally sets SO_REUSEADDR / SO_REUSEPORT / IP_TRANSPARENT. These
tests build the REAL bindp.c with its shipped Makefile (resolved via BINDP_REPO),
LD_PRELOAD the resulting libindp.so, and drive bindp_probe.c (a test fixture, not
a subject copy) to observe what bindp actually did to each socket:

  * BIND_ADDR / BIND_PORT rewrite the bound source address and port (bind + connect);
  * SO_REUSEADDR / SO_REUSEPORT are applied when requested, gated to IP sockets;
  * a valid AF_UNSPEC IPv4 wildcard bind still gets the reuse options (regression:
    the gate must key on the socket family, not the caller's sa_family);
  * AF_UNIX binds are left untouched and never get the IP options;
  * invalid BIND_ADDR / BIND_PORT / REUSE_* env values are rejected, not applied.

gcc and make are REQUIRED build tools; their absence is an environment bug
(FATAL), not a skip. Only a missing subject (no bindp.c under BINDP_REPO) skips.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
PROBE_SRC = os.path.join(HERE, "bindp_probe.c")


def _bindp_src_dir():
    repo = os.environ.get("BINDP_REPO", "").strip()
    base = repo if repo else "/"
    src_dir = os.path.join(base, "usr/src/bindp")
    return src_dir if os.path.isfile(os.path.join(src_dir, "bindp.c")) else ""


def _free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class BindpBehaviorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="bindp-tests.")
        src_dir = _bindp_src_dir()
        if not src_dir:
            raise unittest.SkipTest(
                "bindp.c not found (set BINDP_REPO to the bindp checkout)")
        ## gcc / make are required build tools, not optional: a missing one is an
        ## environment bug that must fail loud, so do not guard them with a skip.
        cls._lib = os.path.join(cls._tmp, "libindp.so")
        ## Build the REAL source with the shipped Makefile and its hardening
        ## flags; direct the output into the tmp dir so the checkout is untouched.
        subprocess.run(
            ["make", "-C", src_dir, f"TARGET={cls._lib}"],
            check=True, capture_output=True, text=True)
        cls._probe = os.path.join(cls._tmp, "bindp_probe")
        subprocess.run(
            ["gcc", "-O2", "-Wall", PROBE_SRC, "-o", cls._probe],
            check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _probe_run(self, mode, *args, **env_overrides):
        env = dict(os.environ)
        env["LD_PRELOAD"] = self._lib
        ## Clear every bindp knob so a leaked ambient value cannot steer a case;
        ## each test sets only the ones it exercises.
        for key in ("BIND_ADDR", "BIND_PORT", "REUSE_ADDR", "REUSE_PORT",
                    "IP_TRANSPARENT"):
            env.pop(key, None)
        env.update({k: str(v) for k, v in env_overrides.items()})
        proc = subprocess.run(
            [self._probe, mode, *args], env=env, capture_output=True, text=True)
        self.assertNotEqual(
            proc.returncode, 2, msg=f"probe setup failed: {proc.stderr}")
        out = {}
        for line in proc.stdout.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                out[key] = value
        out["_stderr"] = proc.stderr
        return out

    ## --- the reuse-option family gate (the reviewer regression) ---------------

    def test_af_unspec_wildcard_bind_gets_reuse_options(self):
        ## Two AF_INET UDP sockets bound AF_UNSPEC to one wildcard port: both must
        ## get SO_REUSEPORT or the second bind fails EADDRINUSE. bindp must gate on
        ## the socket's real family (AF_INET), not the caller's sa_family.
        out = self._probe_run("dual-unspec", REUSE_ADDR=1, REUSE_PORT=1)
        self.assertEqual(
            out.get("second_bind_rc"), "0",
            msg=("second AF_UNSPEC wildcard bind rejected -- reuse options gated "
                 f"on sa_family, not socket family. stderr: {out['_stderr']}"))

    def test_reuseaddr_applied_for_inet(self):
        self.assertEqual(self._probe_run("bind-inet", REUSE_ADDR=1)["reuseaddr"], "1")

    def test_reuseport_applied_for_inet(self):
        self.assertEqual(self._probe_run("bind-inet", REUSE_PORT=1)["reuseport"], "1")

    def test_no_reuse_options_by_default(self):
        out = self._probe_run("bind-inet")
        self.assertEqual(out["reuseaddr"], "0")
        self.assertEqual(out["reuseport"], "0")

    def test_reuse_options_skipped_for_af_unix(self):
        ## AF_UNIX is not an IP socket: bindp must not set SO_REUSEADDR on it even
        ## when asked. SO_REUSEADDR is readable on a unix socket, so 0 proves skip.
        path = os.path.join(self._tmp, "u1.sock")
        out = self._probe_run("bind-unix", path, REUSE_ADDR=1)
        self.assertEqual(out["bind_rc"], "0")
        self.assertEqual(out["reuseaddr"], "0")

    ## --- address / port rewrite -----------------------------------------------

    def test_bind_addr_rewrites_source(self):
        out = self._probe_run("bind-inet", BIND_ADDR="127.0.0.1")
        self.assertEqual(out["addr"], "127.0.0.1")

    def test_bind_port_rewrites_port(self):
        port = _free_tcp_port()
        out = self._probe_run("bind-inet", BIND_PORT=port)
        self.assertEqual(out.get("bind_rc"), "0", msg=out.get("_stderr"))
        self.assertEqual(out["port"], str(port))

    def test_bind_addr_and_port_together(self):
        port = _free_tcp_port()
        out = self._probe_run("bind-inet", BIND_ADDR="127.0.0.1", BIND_PORT=port)
        self.assertEqual(out.get("bind_rc"), "0", msg=out.get("_stderr"))
        self.assertEqual(out["addr"], "127.0.0.1")
        self.assertEqual(out["port"], str(port))

    def test_connect_binds_source_address(self):
        ## connect() must bind the source to BIND_ADDR before connecting.
        out = self._probe_run("connect-src", BIND_ADDR="127.0.0.2")
        self.assertEqual(out.get("connect_rc"), "0", msg=out.get("_stderr"))
        self.assertEqual(out["src_addr"], "127.0.0.2")

    def test_af_unix_bind_unchanged(self):
        path = os.path.join(self._tmp, "u2.sock")
        out = self._probe_run("bind-unix", path)
        self.assertEqual(out["bind_rc"], "0")

    ## --- invalid env values are rejected, not applied -------------------------

    def test_invalid_bind_addr_not_applied(self):
        ## A bad BIND_ADDR must be rejected (address left wildcard), with a warning.
        out = self._probe_run("bind-inet", BIND_ADDR="not.an.ip")
        self.assertEqual(out["addr"], "0.0.0.0")
        self.assertIn("BIND_ADDR", out["_stderr"])

    def test_invalid_bind_port_not_applied(self):
        ## An out-of-range BIND_PORT must be rejected (not rewritten), with a warning.
        out = self._probe_run("bind-inet", BIND_PORT="99999")
        self.assertEqual(out.get("bind_rc"), "0", msg=out.get("_stderr"))
        self.assertNotEqual(out["port"], "99999")
        self.assertIn("BIND_PORT", out["_stderr"])

    def test_invalid_reuse_flag_treated_as_off(self):
        out = self._probe_run("bind-inet", REUSE_ADDR="2")
        self.assertEqual(out["reuseaddr"], "0")
        self.assertIn("REUSE_ADDR", out["_stderr"])


if __name__ == "__main__":
    sys.exit(unittest.main())
