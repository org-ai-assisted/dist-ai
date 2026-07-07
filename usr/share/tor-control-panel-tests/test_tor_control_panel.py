#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for the TorControlPanel main window.

Constructed under the Qt offscreen platform with tcp_testlib.sandbox() (torrc
redirected) and tcp_testlib.no_modal() (any dialog neutralised). TorControlPanel
is a QMainWindow whose __init__ only builds the UI -- refresh()/show() happen in
main() -- so it is safe to build and then drive refresh() directly.

The live tor state that refresh() reacts to is controlled deterministically:
  * tor_is_enabled  <- tor_status.tor_status(), which reads the (sandboxed)
    torrc: 'DisableNetwork 0' => enabled, 'DisableNetwork 1' => disabled.
  * tor_is_running  <- os.path.exists(self.tor_running_path); the test points
    tor_running_path at a path it controls.

Regression guarded:
  * A3 -- the Bridges-type selector must never show two "Disable network"
    (or "Enable network") entries. refresh() toggled the trailing entry with a
    hard-coded removeItem(8); the entry actually sits at index 7, so removeItem
    was a no-op and addItem appended a duplicate (arraybolt3 test-plan bug 1).
"""

import os
import tempfile
import unittest

from PyQt5.QtWidgets import QRadioButton

import tcp_testlib as T
from tor_control_panel import tor_control_panel as tcp


def _toggle_counts(combo):
    items = [combo.itemText(i) for i in range(combo.count())]
    return items.count("Disable network"), items.count("Enable network")


class BridgesComboToggleTest(unittest.TestCase):
    def test_a3_no_duplicate_disable_network_when_stopped(self):
        """Refreshing while Tor is stopped must not duplicate 'Disable network'."""
        with T.sandbox(), T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            ## Force tor_is_running == False -> the stopped refresh branch.
            panel.tor_running_path = os.path.join(
                tempfile.gettempdir(), "tcp-test-no-such-tor-pid"
            )
            combo = panel.bridges_combo

            self.assertEqual(_toggle_counts(combo), (1, 0), "unexpected initial combo state")

            panel.refresh(False)
            disable, enable = _toggle_counts(combo)
            self.assertEqual(
                disable, 1, "duplicate 'Disable network' entry after refresh (bug A3)"
            )
            self.assertEqual(enable, 0)

            ## Repeated refreshes must remain stable, never accumulate.
            for _ in range(3):
                panel.refresh(False)
            self.assertEqual(_toggle_counts(combo), (1, 0))

    def test_a3_toggle_replaced_not_duplicated_when_disabled(self):
        """When Tor is disabled-but-running the entry becomes 'Enable network' only."""
        pid = tempfile.NamedTemporaryFile(prefix="tcp-test-pid-", delete=False)
        pid.close()
        self.addCleanup(os.unlink, pid.name)

        ## 'DisableNetwork 1' => tor_status() reports disabled.
        with T.sandbox(initial_torrc="DisableNetwork 1\n"), T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            panel.tor_running_path = pid.name  # exists -> tor_is_running == True
            combo = panel.bridges_combo

            panel.refresh(False)
            disable, enable = _toggle_counts(combo)
            self.assertEqual(
                enable, 1, "expected exactly one 'Enable network' entry (bug A3)"
            )
            self.assertEqual(
                disable, 0, "'Disable network' should have been replaced, not kept (bug A3)"
            )


class ConfigUiTest(unittest.TestCase):
    """Guards for the config UI: the update_proxy_settings behaviour (which was
    renamed from proxy_settings_show because it also *hides* fields) and the
    tab identifiers, which were swapped to match each tab's content."""

    def _panel(self):
        panel = tcp.TorControlPanel()
        self.addCleanup(panel.deleteLater)
        return panel

    def test_proxy_none_hides_all_proxy_fields(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.update_proxy_settings("None")
            for widget in (panel.proxy_ip_edit, panel.proxy_port_edit,
                           panel.proxy_user_edit, panel.proxy_pwd_edit):
                self.assertTrue(widget.isHidden())

    def test_proxy_socks5_shows_all_proxy_fields(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.update_proxy_settings("SOCKS5")
            for widget in (panel.proxy_ip_edit, panel.proxy_port_edit,
                           panel.proxy_user_edit, panel.proxy_pwd_edit):
                self.assertFalse(widget.isHidden())

    def test_proxy_socks4_disables_auth_fields(self):
        ## SOCKS4 has no authentication, so the user/password fields are shown
        ## but disabled.
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.update_proxy_settings("SOCKS4")
            self.assertFalse(panel.proxy_user_edit.isEnabled())
            self.assertFalse(panel.proxy_pwd_edit.isEnabled())

    def test_tabs_are_labelled_by_their_content(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            labels = [panel.tabs.tabText(i) for i in range(panel.tabs.count())]
            self.assertEqual(labels, ["Control", "Utilities", "Logs"])
            ## The log-source radio buttons must live in the tab labelled 'Logs'
            ## (i.e. logs_tab), not the utilities tab.
            radios = panel.logs_tab.findChildren(QRadioButton)
            self.assertIn(panel.torrc_button, radios)
            self.assertIn(panel.log_button, radios)
            self.assertIn(panel.journal_button, radios)


if __name__ == "__main__":
    unittest.main()
