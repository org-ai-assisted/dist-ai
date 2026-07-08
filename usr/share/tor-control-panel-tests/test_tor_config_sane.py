#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Functional tests for the privileged tor-config-sane helper -- the script that
makes Tor actually READ tor-control-panel's drop-in on plain Debian (adds the
%include the stock /etc/tor/torrc lacks, Debian bug #866187) and provisions a
control socket. This is Debian *functionality*, not just the GUI: it runs the
real bash helper against a throwaway root (paths overridden via the environment)
and, where a tor binary exists, proves with `tor --verify-config` that the
resulting torrc chain reads the drop-in.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

import tcp_testlib as T  # noqa: F401  (sets up sys.path)

TOR = shutil.which("tor")


def _script_path():
    repo = os.environ.get("TCP_REPO", "").strip()
    rel = "usr/libexec/tor-control-panel/tor-config-sane"
    if repo and os.path.exists(os.path.join(repo, rel)):
        return os.path.join(repo, rel)
    return "/" + rel


SCRIPT = _script_path()


@unittest.skipUnless(os.path.exists(SCRIPT), "tor-config-sane not found")
class TorConfigSaneTest(unittest.TestCase):
    def _run(self, root, whonix=False):
        os.makedirs(root, exist_ok=True)
        env = dict(os.environ)
        env["torrc_dir"] = os.path.join(root, "usr/local/etc/torrc.d")
        env["main_torrc"] = os.path.join(root, "etc/tor/torrc")
        marker = os.path.join(root, "gateway-marker")
        env["whonix_marker"] = marker
        if whonix:
            open(marker, "w", encoding="utf-8").close()
        return subprocess.run(["bash", SCRIPT], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding="utf-8")

    def test_debian_adds_include_and_control_socket(self):
        with tempfile.TemporaryDirectory() as root:
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            dropin_dir = os.path.join(root, "usr/local/etc/torrc.d")
            self.assertTrue(os.path.isdir(dropin_dir))
            torrc = open(os.path.join(root, "etc/tor/torrc"),
                         encoding="utf-8").read()
            self.assertIn("%include", torrc)
            self.assertIn("/usr/local/etc/torrc.d", torrc)
            socket_conf = open(
                os.path.join(dropin_dir, "30_tor_control_panel_socket.conf"),
                encoding="utf-8").read()
            self.assertIn("ControlSocket /run/tor/control", socket_conf)
            self.assertIn("CookieAuthentication 1", socket_conf)

    def test_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            self._run(root)
            self._run(root)
            torrc = open(os.path.join(root, "etc/tor/torrc"),
                         encoding="utf-8").read()
            self.assertEqual(torrc.count("%include"), 1,
                             "re-running duplicated the %include line")

    def test_whonix_only_ensures_dropin_dir(self):
        with tempfile.TemporaryDirectory() as root:
            result = self._run(root, whonix=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            ## The drop-in dir is ensured, but on Whonix we do NOT touch the
            ## main torrc (the anon-gw config owns the include chain).
            self.assertTrue(
                os.path.isdir(os.path.join(root, "usr/local/etc/torrc.d")))
            self.assertFalse(os.path.exists(os.path.join(root, "etc/tor/torrc")))

    @unittest.skipUnless(TOR, "tor binary not installed")
    def test_resulting_chain_makes_tor_read_the_dropin(self):
        ## The whole point: after tor-config-sane, a real Tor started with the
        ## main torrc must READ the drop-in. Put an invalid directive in the
        ## drop-in -- tor --verify-config must then FAIL, proving it is read.
        with tempfile.TemporaryDirectory() as root:
            self._run(root)
            torrc = os.path.join(root, "etc/tor/torrc")
            os.makedirs(os.path.join(root, "data"))
            with open(torrc, "a", encoding="utf-8") as handle:
                handle.write("DataDirectory {0}/data\nSocksPort 0\n".format(root))
            ## Point the ControlSocket somewhere harmless for the verify.
            socket_conf = os.path.join(
                root, "usr/local/etc/torrc.d/30_tor_control_panel_socket.conf")
            text = open(socket_conf, encoding="utf-8").read().replace(
                "/run/tor/control", os.path.join(root, "ctrl"))
            open(socket_conf, "w", encoding="utf-8").write(text)
            open(os.path.join(root,
                              "usr/local/etc/torrc.d/40_tor_control_panel.conf"),
                 "w", encoding="utf-8").write("ThisIsNotARealTorOption 1\n")
            result = subprocess.run([TOR, "-f", torrc, "--verify-config"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, encoding="utf-8")
            self.assertNotEqual(
                result.returncode, 0,
                "tor accepted an invalid drop-in -> it is NOT reading the "
                "drop-in via the include:\n" + result.stdout)


if __name__ == "__main__":
    unittest.main()
