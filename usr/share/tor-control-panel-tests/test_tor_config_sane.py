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

import tcp_testlib

tcp_testlib.require_app()  # side-effect harness: sys.path + offscreen QApplication

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

    def test_debian_adds_include_but_not_control_socket(self):
        ## On plain Debian tor-config-sane adds the %include so Tor reads the
        ## drop-in, but must NOT write a ControlSocket: Tor's own
        ## tor-service-defaults-torrc already provides /run/tor/control (with
        ## RelaxDirModeCheck + cookie auth), and a bare 'ControlSocket' here
        ## fails Tor's /run/tor permission check and stops it from starting.
        with tempfile.TemporaryDirectory() as root:
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            dropin_dir = os.path.join(root, "usr/local/etc/torrc.d")
            self.assertTrue(os.path.isdir(dropin_dir))
            with open(os.path.join(root, "etc/tor/torrc"),
                      encoding="utf-8") as handle:
                torrc = handle.read()
            self.assertIn("%include", torrc)
            self.assertIn(dropin_dir, torrc)
            self.assertFalse(
                os.path.exists(os.path.join(
                    dropin_dir, "30_tor_control_panel_socket.conf")),
                "tor-config-sane must not write a ControlSocket on Debian")

    def test_debian_removes_stale_control_socket_dropin(self):
        ## An older tor-control-panel wrote a bare-ControlSocket drop-in that
        ## breaks Tor on Debian; tor-config-sane must remove it on upgrade.
        with tempfile.TemporaryDirectory() as root:
            dropin_dir = os.path.join(root, "usr/local/etc/torrc.d")
            os.makedirs(dropin_dir)
            stale = os.path.join(dropin_dir, "30_tor_control_panel_socket.conf")
            with open(stale, "w", encoding="utf-8") as handle:
                handle.write("ControlSocket /run/tor/control\n")
            result = self._run(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(os.path.exists(stale),
                             "stale ControlSocket drop-in must be removed")

    def test_debian_migrates_stale_usr_local_include(self):
        ## Upgrade path (Codex review): an older tor-control-panel wrote
        ## '%include /usr/local/etc/torrc.d/*.conf', which Tor's AppArmor profile
        ## forbids on Debian and keeps Tor from starting. tor-config-sane must
        ## delete that stale include and add the new /etc/tor drop-in include.
        with tempfile.TemporaryDirectory() as root:
            main_torrc = os.path.join(root, "etc/tor/torrc")
            os.makedirs(os.path.dirname(main_torrc))
            with open(main_torrc, "w", encoding="utf-8") as handle:
                handle.write("SocksPort 9050\n"
                             "%include /usr/local/etc/torrc.d/*.conf\n")
            env = dict(os.environ)
            env["torrc_dir"] = os.path.join(root, "etc/tor/torrc.d")
            env["main_torrc"] = main_torrc
            env["whonix_marker"] = os.path.join(root, "no-marker")
            result = subprocess.run(["bash", SCRIPT], env=env,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(main_torrc, encoding="utf-8") as handle:
                torrc = handle.read()
            self.assertNotIn(
                "/usr/local/etc/torrc.d", torrc,
                "stale AppArmor-forbidden include must be removed on upgrade")
            self.assertIn(os.path.join(root, "etc/tor/torrc.d"), torrc)

    def test_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            self._run(root)
            self._run(root)
            with open(os.path.join(root, "etc/tor/torrc"),
                      encoding="utf-8") as handle:
                torrc = handle.read()
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
            ## tor-config-sane writes no ControlSocket (Debian provides it), so
            ## nothing to neutralise -- just drop an invalid directive in.
            with open(os.path.join(
                    root,
                    "usr/local/etc/torrc.d/40_tor_control_panel.conf"),
                    "w", encoding="utf-8") as handle:
                handle.write("ThisIsNotARealTorOption 1\n")
            result = subprocess.run([TOR, "-f", torrc, "--verify-config"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, encoding="utf-8")
            self.assertNotEqual(
                result.returncode, 0,
                "tor accepted an invalid drop-in -> it is NOT reading the "
                "drop-in via the include:\n" + result.stdout)


if __name__ == "__main__":
    unittest.main()
