#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Headless, automated coverage of the parts of arraybolt3's manual test plan
(Whonix forum post #161) that do NOT need a live bootstrapped Tor: window
layout, tab structure, the configure/accept toggle, the log-source selector,
and each Anon Connection Wizard page's controls. Driven under offscreen Qt via
tcp_testlib.sandbox()/no_modal().

The remainder of the plan -- scenarios that require Tor to actually connect to
the network (obfs4/snowflake/meek bootstrap, the restart cycle, a live proxy,
Onion Circuits) -- stays in test_manual_plan.py as a human release checklist.
"""

import unittest

from PyQt5.QtWidgets import QDialog, QMessageBox, QRadioButton

import tcp_testlib as T
from tor_control_panel import anon_connection_wizard as acw
from tor_control_panel import tor_control_panel as tcp


def _clean(text):
    ## Drop Qt accelerator ampersands ('Tor &log' -> 'Tor log').
    return text.replace("&", "")


class TorControlPanelWalkthroughTest(unittest.TestCase):
    """Automatable Tor Control Panel steps from the manual plan."""

    def _panel(self):
        panel = tcp.TorControlPanel()
        self.addCleanup(panel.deleteLater)
        return panel

    def test_layout_and_defaults(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            labels = [panel.tabs.tabText(i) for i in range(panel.tabs.count())]
            self.assertEqual(labels, ["Control", "Utilities", "Logs"])
            self.assertEqual(panel.tabs.currentIndex(), 0)
            self.assertIn("Restart Tor", panel.restart_button.text())
            self.assertIn("Stop Tor", panel.stop_button.text())
            self.assertIn("Configure", panel.configure_button.text())
            self.assertIn("Exit", panel.quit_button.text())

    def test_configure_toggles_editability(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            self.assertIn("Configure", panel.configure_button.text())
            panel.configure()
            ## 'Configure' morphs into 'Accept' and the selectors become
            ## editable (shown).
            self.assertIn("Accept", panel.configure_button.text())
            self.assertFalse(panel.bridges_combo.isHidden())
            self.assertFalse(panel.proxy_combo.isHidden())

    def test_configure_then_exit_reverts(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.configure()
            self.assertIn("Accept", panel.configure_button.text())
            panel.exit_configuration()
            self.assertIn("Configure", panel.configure_button.text())

    def test_utilities_tab_controls(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            self.assertIn("Onion Circuits", _clean(panel.onioncircuits_button.text()))
            self.assertIn("new Tor circuit", _clean(panel.newnym_button.text()))

    def test_logs_tab_sources(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            sources = sorted(_clean(b.text())
                             for b in panel.files_box.findChildren(QRadioButton))
            self.assertEqual(sources, sorted(["torrc", "Tor log", "systemd journal"]))
            self.assertIn("Refresh", panel.refresh_button.text())

    def test_logs_torrc_source_renders(self):
        ## Selecting the torrc source refreshes the view from the (sandboxed)
        ## torrc without error.
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.torrc_button.setChecked(True)
            panel.refresh_logs()
            self.assertIsInstance(panel.file_browser.toPlainText(), str)

    def test_logs_tab_refresh_picks_up_new_lines(self):
        ## The manual plan's "after generating new Tor log lines, Refresh
        ## updates the Tor log view" -- automated with a file standing in for
        ## the Tor log.
        import os
        import shutil
        import tempfile
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            tmp = tempfile.mkdtemp(prefix="tcp-loglive-")
            self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
            log_path = os.path.join(tmp, "log")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write("Jul 08 00:00:00.000 [notice] first log line\n")
            panel.tor_log = log_path
            panel.log_button.setChecked(True)
            panel.refresh_logs()
            self.assertIn("first log line", panel.file_browser.toPlainText())
            ## New lines appended -> a Refresh must show them.
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write("Jul 08 00:00:01.000 [notice] second log line\n")
            panel.refresh_logs()
            self.assertIn("second log line", panel.file_browser.toPlainText())


class AnonConnectionWizardWalkthroughTest(unittest.TestCase):
    """Automatable Anon Connection Wizard steps from the manual plan."""

    def _page(self, cls):
        with T.sandbox():
            page = cls()
        self.addCleanup(page.deleteLater)
        return page

    def test_first_page_options(self):
        page = self._page(acw.ConnectionMainPage)
        self.assertEqual(page.connect_option.text(), "Connect")
        self.assertEqual(page.configure_option.text(), "Configure")
        self.assertEqual(page.disable_option.text(), "Disable Tor")

    def test_bridge_page_offers_all_types(self):
        page = self._page(acw.BridgeWizardPage)
        items = [page.bridges_combo.itemText(i)
                 for i in range(page.bridges_combo.count())]
        for bridge_type in ("obfs4", "snowflake", "meek", "Custom bridges"):
            self.assertIn(bridge_type, items)
        self.assertIsNotNone(page.bridges_checkbox)
        self.assertIsNotNone(page.show_help_censorship)

    def test_bridge_checkbox_reveals_panel(self):
        page = self._page(acw.BridgeWizardPage)
        page.bridges_checkbox.setChecked(True)
        page.show_bridges_panel()
        self.assertFalse(page.bridges_frame.isHidden())

    def test_custom_bridges_reveals_input(self):
        page = self._page(acw.BridgeWizardPage)
        page.bridges_checkbox.setChecked(True)
        page.show_bridges_panel()
        index = page.bridges_combo.findText("Custom bridges")
        page.bridges_combo.setCurrentIndex(index)
        page.set_bridges_panel()
        self.assertFalse(page.custom_frame.isHidden())

    def test_proxy_page_controls(self):
        page = self._page(acw.ProxyWizardPage)
        self.assertIsNotNone(page.proxy_checkbox)
        self.assertIsNotNone(page.proxy_help)
        self.assertIsNotNone(page.proxy_combo)

    def test_summary_page_controls(self):
        page = self._page(acw.TorrcPage)
        self.assertIn("torrc", page.show_torrc_button.text().lower())
        for label in (page.status_label, page.bridge_type_label,
                      page.proxy_type_label):
            self.assertIsNotNone(label)

    def test_wizard_has_five_pages(self):
        acw.AnonConnectionWizard.exec_ = lambda self, *a, **k: 0
        QMessageBox.exec_ = lambda self, *a, **k: 0
        QDialog.exec_ = lambda self, *a, **k: 0
        with T.sandbox():
            wizard = acw.AnonConnectionWizard()
            self.addCleanup(wizard.deleteLater)
            self.assertEqual(len(wizard.pageIds()), 5)


if __name__ == "__main__":
    unittest.main()
