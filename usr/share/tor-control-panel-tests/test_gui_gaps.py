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
from tor_control_panel import tor_control_panel as tcp

try:
    import stem
    HAVE_STEM = stem is not None    # newnym imports it lazily; require it present
except ImportError:
    HAVE_STEM = False


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
    """G7: the Stop Tor and Exit handlers run without touching the system.
    (sandbox() stubs privilege.command, so stop_tor's Popen is harmless.)"""

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


class BootstrapErrorBranchTest(unittest.TestCase):
    """G8: update_bootstrap reacts to the error phases (hide progress, set the
    matching info message) rather than only the happy path."""

    def _panel(self):
        panel = tcp.TorControlPanel()
        self.addCleanup(panel.deleteLater)
        return panel

    def test_no_controller_phase(self):
        from tor_control_panel import info
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.update_bootstrap("no_controller", 0)
            self.assertEqual(panel.tor_status, "no_controller")
            self.assertEqual(panel.message, info.no_controller())
            self.assertTrue(panel.bootstrap_progress.isHidden())

    def test_socket_error_phase(self):
        from tor_control_panel import info
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.update_bootstrap("socket_error", 50)
            self.assertEqual(panel.message, info.socket_error())
            self.assertTrue(panel.bootstrap_progress.isHidden())

    def test_cookie_error_phase(self):
        from tor_control_panel import info
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.update_bootstrap("cookie_authentication_failed", 0)
            self.assertEqual(panel.message, info.cookie_error())
            self.assertTrue(panel.bootstrap_progress.isHidden())

    def test_done_phase_marks_bootstrap_done(self):
        with T.sandbox(), T.no_modal():
            panel = self._panel()
            panel.update_bootstrap("Connected to the Tor network!", 100)
            self.assertTrue(panel.bootstrap_done)
            self.assertTrue(panel.restart_button.isEnabled())


class HelpButtonsTest(unittest.TestCase):
    """G4: the info/help buttons exist and their handlers run without raising."""

    def test_info_buttons_present_and_help_callable(self):
        from tor_control_panel import info_gui
        with T.sandbox(), T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            self.assertIsNotNone(panel.bridge_info_button)
            self.assertIsNotNone(panel.proxy_info_button)
            ## The help dialogs (now in info_gui) are neutralised by no_modal;
            ## just ensure the handlers build and show without raising.
            info_gui.show_help_censorship()
            info_gui.show_proxy_help()


class CustomBridgesProxyInteractionTest(unittest.TestCase):
    """arraybolt3 residual: adding a proxy to an existing custom-bridges config
    must NOT replace the custom bridges with default obfs4."""

    def test_custom_bridges_survive_adding_a_proxy(self):
        custom = ("# Custom bridges are used\nUseBridges 1\n"
                  "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n"
                  "Bridge obfs4 1.2.3.4:1234 "
                  "ABCDEF0123456789ABCDEF0123456789ABCDEF01\nDisableNetwork 0\n")
        with T.sandbox(initial_torrc=custom) as torrc, T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            panel.tor_running_path = "/run/tor/tor.pid"
            panel.refresh(False)
            ## Custom bridges were correctly detected (not misread as obfs4).
            self.assertEqual(panel.bridge_type.text(), "Custom bridges")
            panel.configure()  # -> Accept mode
            panel.proxy_combo.setCurrentIndex(panel.proxy_combo.findText("SOCKS5"))
            panel.proxy_ip_edit.setText("127.0.0.1")
            panel.proxy_port_edit.setText("9050")
            panel.bridges_combo.setCurrentIndex(
                panel.bridges_combo.findText("Custom bridges"))
            panel.configure()  # Accept -> custom-bridge screen (repopulates)
            panel.accept_custom_bridges()  # writes torrc
            final = torrc.read_text(encoding="utf-8")
        self.assertIn("Bridge obfs4 1.2.3.4:1234", final)
        self.assertIn("Socks5Proxy 127.0.0.1:9050", final)
        ## Exactly the user's one custom bridge -- no default bridges injected.
        self.assertEqual(final.count("Bridge obfs4 "), 1)


class NewnymAndOnionCircuitsTest(unittest.TestCase):
    """The Utilities-tab actions: NEWNYM must not restart Tor, and Onion
    Circuits launches the external viewer."""

    @unittest.skipUnless(HAVE_STEM, "python3-stem not installed")
    def test_newnym_does_not_restart_tor(self):
        ## 'Request new Tor circuit' sends NEWNYM only; a restart would tear
        ## down the circuits it just requested (arraybolt3 review).
        with T.sandbox(), T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            restarted = []
            panel.restart_tor = lambda *a, **k: restarted.append(True)
            panel.newnym()  # no control socket -> caught; must not restart
            self.assertEqual(restarted, [], "NEWNYM must not restart Tor")

    @unittest.skipUnless(HAVE_STEM, "python3-stem not installed")
    def test_newnym_connect_failure_does_not_leak_fds(self):
        ## Regression: stem's from_socket_file leaked the control-socket fd when
        ## the connect failed (Tor down). newnym pre-flights with its own socket
        ## and closes it, so repeated NEWNYM clicks while Tor is down must not
        ## grow the process's open file descriptors.
        import os
        with T.sandbox(), T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            panel.restart_tor = lambda *a, **k: None

            def open_fd_count():
                return len(os.listdir("/proc/self/fd"))

            panel.newnym()  # warm up lazy imports before measuring
            before = open_fd_count()
            for _ in range(20):
                panel.newnym()  # no control socket -> connect fails each time
            after = open_fd_count()
            self.assertLessEqual(
                after, before,
                "NEWNYM connect-failure path leaked file descriptors "
                "({0} -> {1})".format(before, after))

    def test_onioncircuits_launches_viewer(self):
        from tor_control_panel import tor_control_panel as tcp_mod
        with T.sandbox(), T.no_modal():
            panel = tcp_mod.TorControlPanel()
            self.addCleanup(panel.deleteLater)
            calls = []
            saved = tcp_mod.Popen
            tcp_mod.Popen = lambda argv, *a, **k: calls.append(argv)
            self.addCleanup(lambda: setattr(tcp_mod, "Popen", saved))
            panel.onioncircuits()
            self.assertEqual(calls, [["onioncircuits"]])


class DebianTorGroupPromptTest(unittest.TestCase):
    """Plain-Debian: offer to add the account to debian-tor for control access;
    skip on Whonix or when already a member; run only when the user accepts."""

    def _run(self, whonix, is_member, answer):
        from PyQt5.QtWidgets import QMessageBox
        saved = {
            "whonix": tcp.tor_status.whonix,
            "member": tcp.tor_status.user_in_debian_tor_group,
            "question": QMessageBox.question,
            "information": QMessageBox.information,
            "warning": QMessageBox.warning,
            "run": tcp.privilege.run,
            "command": tcp.privilege.command,
        }
        runs = []
        tcp.tor_status.whonix = whonix
        tcp.tor_status.user_in_debian_tor_group = lambda: is_member
        tcp.privilege.command = lambda action, *a: ["leaprun", action]
        tcp.privilege.run = lambda action, *a: runs.append(action) or 0
        QMessageBox.question = staticmethod(lambda *a, **k: answer)
        QMessageBox.information = staticmethod(lambda *a, **k: QMessageBox.Ok)
        QMessageBox.warning = staticmethod(lambda *a, **k: QMessageBox.Ok)
        try:
            tcp.ensure_debian_tor_group_access(None)
        finally:
            tcp.tor_status.whonix = saved["whonix"]
            tcp.tor_status.user_in_debian_tor_group = saved["member"]
            QMessageBox.question = saved["question"]
            QMessageBox.information = saved["information"]
            QMessageBox.warning = saved["warning"]
            tcp.privilege.run = saved["run"]
            tcp.privilege.command = saved["command"]
        return runs

    def test_whonix_never_prompts(self):
        from PyQt5.QtWidgets import QMessageBox
        self.assertEqual(
            self._run(whonix=True, is_member=False, answer=QMessageBox.Yes), [])

    def test_existing_member_never_prompts(self):
        from PyQt5.QtWidgets import QMessageBox
        self.assertEqual(
            self._run(whonix=False, is_member=True, answer=QMessageBox.Yes), [])

    def test_declined_does_not_run(self):
        from PyQt5.QtWidgets import QMessageBox
        self.assertEqual(
            self._run(whonix=False, is_member=False, answer=QMessageBox.No), [])

    def test_accepted_runs_add_tor_group(self):
        from PyQt5.QtWidgets import QMessageBox
        self.assertEqual(
            self._run(whonix=False, is_member=False, answer=QMessageBox.Yes),
            ["add-tor-group"])


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
