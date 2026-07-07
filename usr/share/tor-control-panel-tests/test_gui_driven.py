#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Headless GUI-driven feature tests.

Where test_torrc_gen.py calls gen_torrc()/parse_torrc() directly, this module
drives the REAL PyQt5 widgets under the Qt offscreen platform: it populates the
actual combo boxes / line edits / text edits a user would interact with, then
invokes the real handler slots (TorControlPanel.set_torrc,
AnonConnectionWizard.write_torrc) and asserts the torrc the widget state
produces. This exercises the widget -> torrc_gen wiring that the pure-logic
tests skip.

Everything runs through tcp_testlib.sandbox() (torrc redirected, privileged
helpers stubbed) and tcp_testlib.no_modal() (blocking modal loops neutralised).
TorControlPanel.restart_tor is stubbed per-instance because it would otherwise
Popen('leaprun ...') and start a TorBootstrap QThread; the torrc is already
written by gen_torrc before restart_tor is reached, so stubbing it does not
affect what we assert. No root, no privleap, no Tor daemon, no display.
"""

import unittest

import tcp_testlib as T
from tor_control_panel import tor_control_panel as tcp
from tor_control_panel import anon_connection_wizard as acw
from tor_control_panel.anon_connection_wizard import Common


def _config_lines(text):
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


CUSTOM_BRIDGES = (
    "obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01\n"
    "obfs4 5.6.7.8:5678 0123456789ABCDEF0123456789ABCDEF01234567"
)


class TorControlPanelWidgetTest(unittest.TestCase):
    """Drive TorControlPanel widgets and assert the generated torrc."""

    def _panel(self):
        panel = tcp.TorControlPanel()
        self.addCleanup(panel.deleteLater)
        ## restart_tor() would Popen a leaprun helper and start a QThread.
        panel.restart_tor = lambda: None
        return panel

    def _default_bridge(self, transport):
        with T.sandbox() as torrc, T.no_modal():
            panel = self._panel()
            panel.bridges_combo.setCurrentText(transport)
            self.assertEqual(panel.bridges_combo.currentText(), transport)
            panel.use_default_bridges = True
            panel.use_custom_bridges = False
            panel.use_proxy = False
            panel.set_torrc()
            return torrc.read_text(encoding="utf-8")

    def test_obfs4_via_combo(self):
        text = self._default_bridge("obfs4")
        self.assertIn("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy", text)
        self.assertTrue(any(ln.startswith("Bridge obfs4 ") for ln in _config_lines(text)))

    def test_snowflake_via_combo(self):
        text = self._default_bridge("snowflake")
        self.assertIn("ClientTransportPlugin snowflake exec /usr/bin/snowflake-client", text)

    def test_meek_via_combo(self):
        text = self._default_bridge("meek")
        self.assertIn("ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy", text)

    def test_none_via_combo(self):
        with T.sandbox() as torrc, T.no_modal():
            panel = self._panel()
            panel.bridges_combo.setCurrentText("None")
            panel.use_default_bridges = False
            panel.use_custom_bridges = False
            panel.use_proxy = False
            panel.set_torrc()
            self.assertEqual(_config_lines(torrc.read_text()), ["DisableNetwork 0"])

    def test_custom_bridges_via_textedit_survive(self):
        """Custom bridges typed into the QTextEdit reach the torrc intact.

        End-to-end widget-level check of A1: they must not be replaced by
        default obfs4 bridges.
        """
        with T.sandbox() as torrc, T.no_modal():
            panel = self._panel()
            panel.custom_bridges.setPlainText(CUSTOM_BRIDGES)
            panel.use_custom_bridges = True
            panel.use_default_bridges = False
            panel.use_proxy = False
            panel.set_torrc()
            text = torrc.read_text(encoding="utf-8")
            self.assertIn("# Custom bridges are used", text)
            self.assertIn("Bridge obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01", text)
            self.assertIn("Bridge obfs4 5.6.7.8:5678 0123456789ABCDEF0123456789ABCDEF01234567", text)
            ## Custom bridges must be re-detected on parse (would be lost otherwise).
            from tor_control_panel import torrc_gen
            self.assertEqual(torrc_gen.parse_torrc()[0], "Custom bridges")

    def _proxy(self, proxy_type):
        with T.sandbox() as torrc, T.no_modal():
            panel = self._panel()
            panel.proxy_combo.setCurrentText(proxy_type)
            panel.proxy_ip_edit.setText("127.0.0.1")
            panel.proxy_port_edit.setText("9050")
            panel.proxy_user_edit.setText("")
            panel.proxy_pwd_edit.setText("")
            panel.use_default_bridges = False
            panel.use_custom_bridges = False
            panel.use_proxy = True
            panel.set_torrc()
            return torrc.read_text(encoding="utf-8")

    def test_socks5_proxy_via_widgets(self):
        self.assertIn("Socks5Proxy 127.0.0.1:9050", self._proxy("SOCKS5"))

    def test_socks4_proxy_via_widgets(self):
        self.assertIn("Socks4Proxy 127.0.0.1:9050", self._proxy("SOCKS4"))

    def test_tabs_and_control_buttons_present(self):
        """Three tabs (Control default) and the control buttons are present."""
        from PyQt5.QtWidgets import QTabWidget
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            tabs = panel.findChildren(QTabWidget)[0]
            self.assertEqual([tabs.tabText(i) for i in range(tabs.count())],
                             ["Control", "Utilities", "Logs"])
            self.assertEqual(tabs.currentIndex(), 0)
            self.assertIn("Restart Tor", panel.restart_button.text())
            self.assertIn("Stop Tor", panel.stop_button.text())
            self.assertIn("Exit", panel.quit_button.text())

    def test_configure_button_click_toggles_mode(self):
        """Clicking Configure enters edit mode (button morphs to Accept)."""
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            self.assertIn("Configure", panel.configure_button.text())
            panel.configure_button.click()
            self.assertIn("Accept", panel.configure_button.text())

    def test_refresh_user_configuration_resets_bridge_flags(self):
        """A stale custom/default bridge flag must not survive a refresh.

        With a torrc that has no custom bridges, refresh_user_configuration()
        must clear a previously-set use_custom_bridges (else set_torrc() could
        emit conflicting bridge config).
        """
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.use_custom_bridges = True  # stale state from an earlier screen
            panel.refresh_user_configuration()
            self.assertFalse(panel.use_custom_bridges)

    def test_valid_ip_accepts_ipv6(self):
        """Proxy/bridge address validation (shared validators) accepts IPv6."""
        from tor_control_panel import validators
        self.assertTrue(validators.valid_ip("::1"))
        self.assertTrue(validators.valid_ip("127.0.0.1"))
        self.assertFalse(validators.valid_ip("definitely not an address"))
        self.assertTrue(validators.valid_port("9050"))
        self.assertFalse(validators.valid_port("70000"))
        self.assertFalse(validators.valid_port("notaport"))

    def test_tor_log_view_sanitizes_untrusted_content(self):
        """A hostile Tor log line cannot inject markup / escapes into the view."""
        import os
        import tempfile
        from PyQt5.QtWidgets import QRadioButton

        with T.sandbox(), T.no_modal():
            panel = self._panel()
            tmp = tempfile.mkdtemp(prefix="tcp-log-")
            self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
            log_path = os.path.join(tmp, "log")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "Jul 07 12:00:00.000 [notice] "
                    "<script>alert(1)</script>\x1b[31mEVIL\x07 [warn] bad\n"
                )
            panel.tor_log = log_path
            panel.tor_log_html = os.path.join(tmp, "log.html")
            for button in panel.files_box.findChildren(QRadioButton):
                if button.text() == panel.button_name[1]:
                    button.setChecked(True)
            panel.refresh_logs()

            rendered = open(panel.tor_log_html, encoding="utf-8").read()
            self.assertNotIn("<script>", rendered)
            self.assertNotIn("\x1b", rendered)
            self.assertNotIn("\x07", rendered)
            ## The application's own [warn] highlight styling is still applied.
            self.assertIn("span", rendered)
            ## The benign text content survives (markup stripped, not the words).
            self.assertIn("alert(1)", panel.file_browser.toPlainText())


class AnonConnectionWizardWidgetTest(unittest.TestCase):
    """Drive AnonConnectionWizard state/widgets and assert write_torrc output."""

    def setUp(self):
        ## Common is shared class state; reset the fields write_torrc reads so
        ## tests do not leak into each other.
        Common.use_default_bridges = False
        Common.use_custom_bridges = False
        Common.use_proxy = False
        Common.bridge_type = "None"
        Common.custom_bridges = "None"
        Common.proxy_type = "None"
        Common.proxy_username = ""
        Common.proxy_password = ""

    def _wizard(self):
        wizard = acw.AnonConnectionWizard()
        self.addCleanup(wizard.deleteLater)
        return wizard

    def _default_bridge(self, transport):
        with T.sandbox() as torrc, T.no_modal():
            wizard = self._wizard()
            Common.use_default_bridges = True
            Common.bridge_type = transport
            wizard.write_torrc()
            return torrc.read_text(encoding="utf-8")

    def test_first_page_offers_connect_configure_disable(self):
        """The wizard's first page offers Connect / Configure / Disable Tor."""
        with T.sandbox(), T.no_modal():
            wizard = self._wizard()
            page = wizard.connection_main_page
            self.assertTrue(hasattr(page, "connect_option"))
            self.assertTrue(hasattr(page, "configure_option"))
            self.assertTrue(hasattr(page, "disable_option"))

    def test_bridge_type_combo_offers_all_types(self):
        """The bridge-type combo offers obfs4, snowflake, meek and custom."""
        with T.sandbox(), T.no_modal():
            wizard = self._wizard()
            combo = wizard.bridge_wizard_page.bridges_combo
            items = [combo.itemText(i) for i in range(combo.count())]
            self.assertEqual(items, ["obfs4", "snowflake", "meek", "Custom bridges"])

    def test_default_bridge_obfs4(self):
        self.assertIn("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy",
                      self._default_bridge("obfs4"))

    def test_default_bridge_meek(self):
        self.assertIn("ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy",
                      self._default_bridge("meek"))

    def test_default_bridge_snowflake(self):
        self.assertIn("ClientTransportPlugin snowflake exec /usr/bin/snowflake-client",
                      self._default_bridge("snowflake"))

    def test_socks4_proxy(self):
        with T.sandbox() as torrc, T.no_modal():
            wizard = self._wizard()
            Common.use_proxy = True
            Common.proxy_type = "SOCKS4"
            Common.proxy_username = ""
            Common.proxy_password = ""
            wizard.proxy_wizard_page.ip_edit.setText("127.0.0.1")
            wizard.proxy_wizard_page.port_edit.setText("9050")
            wizard.write_torrc()
            self.assertIn("Socks4Proxy 127.0.0.1:9050", torrc.read_text())

    def test_init_tor_status_captured_at_launch(self):
        """init_tor_status must reflect the launch state (not stay '') so the
        cancel/back restore logic is live."""
        for torrc, expect in (("DisableNetwork 0\n", "tor_enabled"),
                              ("DisableNetwork 1\n", "tor_disabled")):
            with self.subTest(torrc=torrc):
                with T.sandbox(initial_torrc=torrc), T.no_modal():
                    self._wizard()
                    self.assertEqual(Common.init_tor_status, expect)

    class _FakeThread:
        def terminate(self):
            pass

    def _spy_set_enabled(self):
        from tor_control_panel import tor_status
        calls = []
        saved = tor_status.set_enabled
        tor_status.set_enabled = lambda: (calls.append("enabled"), ("tor_enabled", 0))[1]
        self.addCleanup(lambda: setattr(tor_status, "set_enabled", saved))
        return calls

    def test_cancel_restores_initially_enabled_tor_after_bootstrap(self):
        """Cancelling after a bootstrap ran, from an initially-enabled state,
        must re-enable Tor (previously the enabled branch did nothing)."""
        with T.sandbox(initial_torrc="DisableNetwork 0\n"), T.no_modal():
            wizard = self._wizard()
            self.assertEqual(Common.init_tor_status, "tor_enabled")
            wizard.bootstrap_thread = self._FakeThread()  # a bootstrap ran
            calls = self._spy_set_enabled()
            wizard.cancel_button_clicked()
            self.assertEqual(calls, ["enabled"])

    def test_untouched_cancel_does_not_restart_tor(self):
        """Opening and cancelling without starting a bootstrap must NOT restart
        Tor (would disrupt an existing connection)."""
        with T.sandbox(initial_torrc="DisableNetwork 0\n"), T.no_modal():
            wizard = self._wizard()
            self.assertFalse(wizard.bootstrap_thread)  # no bootstrap started
            calls = self._spy_set_enabled()
            wizard.cancel_button_clicked()
            self.assertEqual(calls, [])

    def test_custom_bridges(self):
        with T.sandbox() as torrc, T.no_modal():
            wizard = self._wizard()
            Common.use_custom_bridges = True
            Common.custom_bridges = CUSTOM_BRIDGES
            wizard.write_torrc()
            text = torrc.read_text(encoding="utf-8")
            self.assertIn("# Custom bridges are used", text)
            self.assertIn("Bridge obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01", text)

    def test_socks5_proxy(self):
        with T.sandbox() as torrc, T.no_modal():
            wizard = self._wizard()
            Common.use_proxy = True
            Common.proxy_type = "SOCKS5"
            Common.proxy_username = ""
            Common.proxy_password = ""
            wizard.proxy_wizard_page.ip_edit.setText("127.0.0.1")
            wizard.proxy_wizard_page.port_edit.setText("9050")
            wizard.write_torrc()
            self.assertIn("Socks5Proxy 127.0.0.1:9050", torrc.read_text())


if __name__ == "__main__":
    unittest.main()
