#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the portable privilege runner (tor_control_panel.privilege): the
escalation chain leaprun (privleap) -> pkexec -> passwordless sudo -> error.
leaprun resolves an action BY NAME; pkexec / sudo need the action mapped to its
real command. Captures the plain-Debian design (adrelanos / ArrayBolt3).
"""

import unittest

import tcp_testlib as T  # noqa: F401  (sets up sys.path / offscreen Qt)
from tor_control_panel import privilege


class PrivilegeChainTest(unittest.TestCase):
    def setUp(self):
        self._which = privilege.shutil.which
        self._sudo = privilege._passwordless_sudo_available
        self.addCleanup(lambda: setattr(privilege.shutil, "which", self._which))
        self.addCleanup(
            lambda: setattr(privilege, "_passwordless_sudo_available", self._sudo))

    def _have(self, *names):
        present = set(names)
        privilege.shutil.which = lambda name: (
            "/usr/bin/" + name if name in present else None)

    def test_leaprun_used_by_name_when_available(self):
        self._have("leaprun", "pkexec")
        self.assertTrue(privilege.leaprun_available())
        ## leaprun takes the action NAME (resolved via the privleap config).
        self.assertEqual(
            privilege.command("acw-tor-control-restart"),
            ["leaprun", "acw-tor-control-restart"])

    def test_pkexec_maps_action_to_command(self):
        self._have("pkexec")  # no leaprun
        self.assertEqual(
            privilege.command("acw-tor-control-restart"),
            ["pkexec", "/usr/libexec/anon-connection-wizard/acw-tor-control",
             "restart"])
        self.assertEqual(
            privilege.command("tor-config-sane"),
            ["pkexec", "/usr/libexec/tor-control-panel/tor-config-sane"])

    def test_sudo_fallback_when_no_leaprun_or_pkexec(self):
        self._have()  # neither leaprun nor pkexec
        privilege._passwordless_sudo_available = lambda mapped: True
        self.assertEqual(
            privilege.command("acw-tor-control-stop"),
            ["sudo", "--non-interactive",
             "/usr/libexec/anon-connection-wizard/acw-tor-control", "stop"])

    def test_sudo_probe_receives_the_mapped_command(self):
        ## The probe must see the REAL helper argv (not a generic `true`), so a
        ## NOPASSWD rule scoped to the helper path is detected correctly.
        self._have()  # neither leaprun nor pkexec
        seen = []
        privilege._passwordless_sudo_available = lambda mapped: (
            seen.append(mapped) or True)
        privilege.command("tor-config-sane")
        self.assertEqual(
            seen, [["/usr/libexec/tor-control-panel/tor-config-sane"]])

    def test_error_when_no_method_available(self):
        self._have()  # nothing
        privilege._passwordless_sudo_available = lambda mapped: False
        with self.assertRaises(privilege.NoPrivilegeMethod):
            privilege.command("acw-tor-control-restart")

    def test_unknown_action_on_pkexec_path_raises(self):
        self._have("pkexec")
        with self.assertRaises(KeyError):
            privilege.command("no-such-action")

    def test_extra_args_are_appended(self):
        self._have("pkexec")
        self.assertEqual(
            privilege.command("acw-write-torrc", "--extra"),
            ["pkexec", "/usr/libexec/anon-connection-wizard/acw-write-torrc",
             "--extra"])

    def test_action_map_matches_leaprun_actions(self):
        ## Every action the GUI dispatches must be in the pkexec/sudo map too,
        ## or the plain-Debian path would KeyError. (Guards against adding a
        ## leaprun action without its command mapping.)
        for action in ("acw-tor-control-restart", "acw-tor-control-reload",
                       "acw-tor-control-stop", "acw-tor-control-status",
                       "acw-write-torrc", "tor-config-sane",
                       "tor-control-panel-read-tor-default-log",
                       "anon-dns-add", "anon-dns-remove"):
            self.assertIn(action, privilege._ACTION_COMMANDS)

    def test_anon_dns_maps_to_installed_helper(self):
        ## Must match the Command= in etc/privleap/conf.d/tor-control-panel.conf
        ## (/usr/bin/anon-dns), or the pkexec/sudo fallback would resolve a
        ## different (non-installed) path than leaprun and silently fail.
        self.assertEqual(privilege._ACTION_COMMANDS["anon-dns-add"],
                         ["/usr/bin/anon-dns", "add"])
        self.assertEqual(privilege._ACTION_COMMANDS["anon-dns-remove"],
                         ["/usr/bin/anon-dns", "remove"])


if __name__ == "__main__":
    unittest.main()
