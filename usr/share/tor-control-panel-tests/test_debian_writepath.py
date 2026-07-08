#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
End-to-end Debian *functionality* (not just the GUI): the whole write-path a
plain-Debian user relies on, exercised against a throwaway root with the real
privileged bash helpers.

  1. tor-config-sane makes /etc/tor/torrc %include the drop-in dir + adds a
     control socket.
  2. the GUI stages the generated torrc into the comm file; acw-write-torrc
     (the privileged helper) copies it into the drop-in with mode 0644.
  3. a real `tor --verify-config` proves Tor reads the config the GUI produced.

This closes the gap where the suite only tested the GUI/logic and stubbed the
privileged writes -- so the Debian path could look tested while being broken.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

import tcp_testlib as T
from tor_control_panel import torrc_gen

TOR = shutil.which("tor")


def _helper(rel):
    repo = os.environ.get("TCP_REPO", "").strip()
    if repo and os.path.exists(os.path.join(repo, rel)):
        return os.path.join(repo, rel)
    return "/" + rel


TOR_CONFIG_SANE = _helper("usr/libexec/tor-control-panel/tor-config-sane")
ACW_WRITE_TORRC = _helper("usr/libexec/anon-connection-wizard/acw-write-torrc")


@unittest.skipUnless(os.path.exists(ACW_WRITE_TORRC), "acw-write-torrc not found")
class AcwWriteTorrcTest(unittest.TestCase):
    def _write(self, root, contents):
        comm = os.path.join(root, "comm")
        dropin = os.path.join(root, "torrc.d", "40_tor_control_panel.conf")
        with open(comm, "w", encoding="utf-8") as handle:
            handle.write(contents)
        env = dict(os.environ)
        env["acw_comm_file_path"] = comm
        env["torrc_file_path"] = dropin
        result = subprocess.run(["bash", ACW_WRITE_TORRC], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                encoding="utf-8")
        return result, dropin

    def test_lands_content_with_mode_644(self):
        with tempfile.TemporaryDirectory() as root:
            result, dropin = self._write(
                root, "DisableNetwork 0\nUseBridges 1\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(dropin, encoding="utf-8") as handle:
                self.assertEqual(handle.read(),
                                 "DisableNetwork 0\nUseBridges 1\n")
            self.assertEqual(oct(os.stat(dropin).st_mode & 0o777), "0o644")

    def test_empty_comm_file_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            result, _ = self._write(root, "")
            self.assertNotEqual(result.returncode, 0,
                                "empty comm file must be rejected")


@unittest.skipUnless(TOR and os.path.exists(TOR_CONFIG_SANE)
                     and os.path.exists(ACW_WRITE_TORRC),
                     "tor / helpers not available")
class DebianEndToEndTest(unittest.TestCase):
    def test_full_write_path_produces_a_torrc_tor_reads(self):
        with tempfile.TemporaryDirectory() as root:
            dropin_dir = os.path.join(root, "usr/local/etc/torrc.d")
            main_torrc = os.path.join(root, "etc/tor/torrc")

            ## 1. tor-config-sane: %include + control socket (Debian branch).
            env = dict(os.environ)
            env["torrc_dir"] = dropin_dir
            env["main_torrc"] = main_torrc
            env["whonix_marker"] = os.path.join(root, "no-marker")
            self.assertEqual(
                subprocess.run(["bash", TOR_CONFIG_SANE], env=env).returncode, 0)

            ## 2. generate a real config (in the sandbox) and stage it into the
            ## comm file, then run acw-write-torrc into the drop-in dir.
            with T.sandbox() as staged:
                torrc_gen.gen_torrc(["obfs4", "None", "None"])
                generated = staged.read_text(encoding="utf-8")
            comm = os.path.join(root, "comm")
            with open(comm, "w", encoding="utf-8") as handle:
                handle.write(generated)
            wenv = dict(os.environ)
            wenv["acw_comm_file_path"] = comm
            wenv["torrc_file_path"] = os.path.join(
                dropin_dir, "40_tor_control_panel.conf")
            self.assertEqual(
                subprocess.run(["bash", ACW_WRITE_TORRC], env=wenv).returncode, 0)

            ## 3. neutralise the real ControlSocket path, then verify Tor reads
            ## the whole chain (main torrc -> include -> the GUI's drop-in).
            socket_conf = os.path.join(
                dropin_dir, "30_tor_control_panel_socket.conf")
            with open(socket_conf, encoding="utf-8") as handle:
                text = handle.read().replace(
                    "/run/tor/control", os.path.join(root, "ctrl"))
            with open(socket_conf, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.makedirs(os.path.join(root, "data"))
            with open(main_torrc, "a", encoding="utf-8") as handle:
                handle.write("DataDirectory {0}/data\nSocksPort 0\n".format(root))
            result = subprocess.run([TOR, "-f", main_torrc, "--verify-config"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, encoding="utf-8")
            self.assertEqual(
                result.returncode, 0,
                "Tor rejected the config the GUI write-path produced:\n"
                + result.stdout)
            ## And the GUI's obfs4 config really is in the effective torrc.
            with open(wenv["torrc_file_path"], encoding="utf-8") as handle:
                self.assertIn("UseBridges", handle.read())


if __name__ == "__main__":
    unittest.main()
