#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Coverage for GUI branch/handler paths that previously lived only in the skipped
manual plan: the custom-bridge accept/cancel handlers and their validity gate,
the proxy-settings validity gate, the Anon Connection Wizard first-page routing,
and the Stop/Exit handlers. All headless via tcp_testlib.sandbox()/no_modal().
"""

import unittest

import tcp_testlib as T
from tor_control_panel import anon_connection_wizard as acw
from tor_control_panel import privilege
from tor_control_panel import tor_control_panel as tcp


class CustomBridgeHandlersTest(unittest.TestCase):
    """G1/G2: the custom-bridge accept/cancel handlers and their validity gate."""

    def _panel(self):
        panel = tcp.TorControlPanel()
        self.addCleanup(panel.deleteLater)
        return panel

    def test_invalid_custom_bridges_rejected(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.custom_bridges.setPlainText("this is not a bridge")
            self.assertFalse(panel.check_valid_custom_bridges())

    def test_valid_custom_bridges_accepted(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.custom_bridges.setPlainText(
                "obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01")
            self.assertTrue(panel.check_valid_custom_bridges())

    def test_accept_invalid_custom_bridges_does_not_write_torrc(self):
        ## accept_custom_bridges() on junk must pop the warning (neutralised by
        ## no_modal) and NOT close the screen / write the torrc.
        with T.sandbox() as torrc, T.no_modal():
            panel = self._panel()
            panel.custom_bridges_frame.show()
            panel.custom_bridges.setPlainText("junk")
            before = torrc.read_text(encoding="utf-8")
            panel.accept_custom_bridges()
            self.assertFalse(panel.custom_bridges_frame.isHidden(),
                             "screen should stay open on invalid input")
            self.assertEqual(torrc.read_text(encoding="utf-8"), before,
                             "torrc must not change on invalid input")

    def test_accept_valid_custom_bridges_closes_screen(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.custom_bridges_frame.show()
            panel.custom_bridges.setPlainText(
                "obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01")
            panel.accept_custom_bridges()
            self.assertTrue(panel.custom_bridges_frame.isHidden(),
                            "valid input should close the custom-bridge screen")


class ProxyValidityGateTest(unittest.TestCase):
    """G3: the proxy-settings validity gate."""

    def _panel(self):
        panel = tcp.TorControlPanel()
        self.addCleanup(panel.deleteLater)
        return panel

    def test_invalid_proxy_settings_rejected(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.proxy_ip_edit.setText("not-an-ip !!")
            panel.proxy_port_edit.setText("999999")
            self.assertFalse(panel.check_valid_proxy_settings())

    def test_valid_proxy_settings_accepted(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.proxy_ip_edit.setText("127.0.0.1")
            panel.proxy_port_edit.setText("9050")
            self.assertTrue(panel.check_valid_proxy_settings())


class StopAndQuitTest(unittest.TestCase):
    """G7: the Stop Tor and Exit handlers run without touching the system."""

    def setUp(self):
        ## stop_tor shells out via privilege.command; make it a no-op success
        ## (sandbox only stubs privilege.run/check_run, not .command).
        self._saved = privilege.command
        privilege.command = lambda action, *a: ["true"]
        self.addCleanup(lambda: setattr(privilege, "command", self._saved))

    def test_stop_tor_reenables_restart(self):
        with T.sandbox(), T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            panel.stop_tor()  # must not raise
            self.assertTrue(panel.restart_button.isEnabled())

    def test_quit_does_not_raise(self):
        with T.sandbox(), T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            panel.quit()  # calls accept(); must not raise


class WizardFirstPageRoutingTest(unittest.TestCase):
    """G6: ConnectionMainPage.nextId routes Connect/Configure/Disable correctly."""

    def _page(self):
        with T.sandbox():
            page = acw.ConnectionMainPage()
        self.addCleanup(page.deleteLater)
        return page

    def test_connect_routes_to_torrc_page(self):
        page = self._page()
        page.connect_option.setChecked(True)
        self.assertEqual(page.nextId(),
                         acw.Common.wizard_steps.index("torrc_page"))
        self.assertFalse(acw.Common.disable_tor)

    def test_configure_routes_to_bridge_page(self):
        page = self._page()
        page.configure_option.setChecked(True)
        self.assertEqual(page.nextId(),
                         acw.Common.wizard_steps.index("bridge_wizard_page"))
        self.assertFalse(acw.Common.disable_tor)

    def test_disable_routes_to_status_page(self):
        page = self._page()
        page.disable_option.setChecked(True)
        self.assertEqual(page.nextId(),
                         acw.Common.wizard_steps.index("tor_status_page"))
        self.assertTrue(acw.Common.disable_tor)


if __name__ == "__main__":
    unittest.main()
