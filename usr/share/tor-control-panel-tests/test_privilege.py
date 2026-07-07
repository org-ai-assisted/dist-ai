#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the portable privilege runner (tor_control_panel.privilege): use
leaprun (privleap) when available, else fall back to pkexec -- the non-Whonix
design adrelanos/ArrayBolt3 described. These capture the learning that the tool
must work on plain Debian (no privleap), verified against a chroot in this
session.
"""

import unittest

import tcp_testlib as T  # noqa: F401  (sets up sys.path / offscreen Qt)
from tor_control_panel import privilege


class PrivilegePrefixTest(unittest.TestCase):
    def setUp(self):
        self._saved_which = privilege.shutil.which
        self.addCleanup(lambda: setattr(privilege.shutil, "which", self._saved_which))

    def test_prefix_prefers_leaprun_when_available(self):
        privilege.shutil.which = lambda name: "/usr/bin/leaprun" if name == "leaprun" else None
        self.assertTrue(privilege.leaprun_available())
        self.assertEqual(privilege._prefix(), ["leaprun"])

    def test_prefix_falls_back_to_pkexec_without_leaprun(self):
        privilege.shutil.which = lambda name: None
        self.assertFalse(privilege.leaprun_available())
        self.assertEqual(privilege._prefix(), ["pkexec"])

    def test_run_uses_prefix(self):
        calls = {}
        privilege.shutil.which = lambda name: "/usr/bin/leaprun"
        saved_call = privilege.subprocess.call
        self.addCleanup(lambda: setattr(privilege.subprocess, "call", saved_call))

        def fake_call(argv):
            calls["argv"] = argv
            return 0

        privilege.subprocess.call = fake_call
        rc = privilege.run("acw-tor-control-restart")
        self.assertEqual(rc, 0)
        self.assertEqual(calls["argv"], ["leaprun", "acw-tor-control-restart"])


if __name__ == "__main__":
    unittest.main()
