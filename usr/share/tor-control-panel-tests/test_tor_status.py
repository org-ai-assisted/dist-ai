#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for tor_status.set_enabled / set_disabled (the shared, comment-aware
_write_disable_network helper). Runs through tcp_testlib.sandbox() so the torrc
write is captured and the privileged leaprun calls are stubbed.
"""

import unittest

import tcp_testlib as T
from tor_control_panel import tor_status


def _active(text):
    return [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


class DisableNetworkRewriteTest(unittest.TestCase):
    def _run(self, action, initial):
        with T.sandbox(initial_torrc=initial) as torrc:
            action()
            return torrc.read_text(encoding="utf-8")

    def test_enable_sets_directive_to_zero(self):
        text = self._run(tor_status.set_enabled, "DisableNetwork 1\n")
        self.assertIn("DisableNetwork 0", _active(text))
        self.assertNotIn("DisableNetwork 1", _active(text))

    def test_disable_sets_directive_to_one(self):
        text = self._run(tor_status.set_disabled, "DisableNetwork 0\n")
        self.assertIn("DisableNetwork 1", _active(text))

    def test_directive_appended_when_absent(self):
        text = self._run(tor_status.set_disabled, "# just a comment\n")
        self.assertIn("DisableNetwork 1", _active(text))

    def test_comment_mentioning_directive_is_not_touched(self):
        text = self._run(tor_status.set_disabled,
                         "# DisableNetwork 1 is bad\nDisableNetwork 0\n")
        self.assertIn("# DisableNetwork 1 is bad", text)
        self.assertIn("DisableNetwork 1", _active(text))

    def test_missing_torrc_reports_enabled(self):
        """A missing torrc (plain Debian/Kicksecure) must report tor_enabled
        (Tor's own default), not crash."""
        with T.sandbox() as torrc:
            torrc.unlink()
            self.assertEqual(tor_status.tor_status(), "tor_enabled")

    def test_missing_torrc_created_on_enable(self):
        """set_enabled() must repair a missing torrc (plain Debian, no drop-in
        yet), not crash -- its docstring guarantees the file ends up existing
        with DisableNetwork 0."""
        with T.sandbox() as torrc:
            torrc.unlink()
            tor_status.set_enabled()
            self.assertTrue(torrc.exists())
            self.assertIn("DisableNetwork 0",
                          _active(torrc.read_text(encoding="utf-8")))

    def test_missing_torrc_created_on_disable(self):
        """set_disabled() must likewise create a missing torrc with
        DisableNetwork 1 rather than raising FileNotFoundError."""
        with T.sandbox() as torrc:
            torrc.unlink()
            tor_status.set_disabled()
            self.assertTrue(torrc.exists())
            self.assertIn("DisableNetwork 1",
                          _active(torrc.read_text(encoding="utf-8")))

    def test_all_active_directives_normalized(self):
        """A duplicated torrc must not be left with a conflicting directive."""
        text = self._run(tor_status.set_enabled,
                         "DisableNetwork 0\nDisableNetwork 1\n")
        self.assertEqual([d for d in _active(text) if d.startswith("DisableNetwork")],
                         ["DisableNetwork 0", "DisableNetwork 0"])


if __name__ == "__main__":
    unittest.main()
