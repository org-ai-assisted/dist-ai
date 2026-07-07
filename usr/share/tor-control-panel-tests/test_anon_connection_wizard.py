#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for the merged Anon Connection Wizard (ACW).

These construct the real AnonConnectionWizard under the Qt offscreen platform,
with tcp_testlib.sandbox() redirecting torrc writes and tcp_testlib.no_modal()
neutralising the blocking self.exec_() modal loop that ACW.__init__ would
otherwise enter. No root, no privleap, no Tor daemon, no display.

Regression guarded:
  * A2 -- closing the wizard with Cancel must not crash. ACW.__init__ never
    initialised self.bootstrap_thread, so cancel_button_clicked() raised
    AttributeError -> IOT/core dump (arraybolt3 test-plan bug 4).
"""

import unittest

import tcp_testlib as T
from tor_control_panel import anon_connection_wizard as acw


class AcwCancelCrashTest(unittest.TestCase):
    def _make_wizard(self):
        wizard = acw.AnonConnectionWizard()
        self.addCleanup(wizard.deleteLater)
        return wizard

    def test_a2_bootstrap_thread_is_initialized(self):
        """bootstrap_thread must exist right after construction.

        Fails on unfixed source: the attribute is only created inside the
        connect path, so a fresh wizard has no bootstrap_thread.
        """
        with T.sandbox(), T.no_modal():
            wizard = self._make_wizard()
            self.assertTrue(
                hasattr(wizard, "bootstrap_thread"),
                "bootstrap_thread not initialized in __init__ (bug A2)",
            )
            self.assertFalse(
                wizard.bootstrap_thread,
                "bootstrap_thread should be falsy (no thread running yet)",
            )

    def test_a2_cancel_before_connect_does_not_crash(self):
        """Pressing Cancel before connecting must not raise AttributeError."""
        with T.sandbox(), T.no_modal():
            wizard = self._make_wizard()
            try:
                wizard.cancel_button_clicked()
            except AttributeError as exc:  # pragma: no cover - the bug under test
                self.fail(f"cancel_button_clicked() crashed on a fresh wizard: {exc}")


if __name__ == "__main__":
    unittest.main()
