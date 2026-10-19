#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Headless smoke tests for the PyQt6 GUI dialog (tor_control_panel). Construct the
main dialog offscreen with the torrc / privileged layer sandboxed, and assert
its startup wiring: the config is parsed, and the bridge / proxy selectors are
populated from the shared tcpl_* lists.
"""

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl
from tor_control_panel import tor_control_panel as tcp_gui
from tor_control_panel import tor_status_watcher

tcp_testlib.require_app()


@contextmanager
def _fake_tor_run_dir():
    ## The status watcher refuses to start unless Tor's runtime dir
    ## (tcpl_tor_run_path, i.e. /run/tor) already exists, waiting ~10s then
    ## raising FileNotFoundError -- it is absent on a CI runner with no Tor.
    ## Point the watcher at an empty temp dir so the headless dialog constructs
    ## without a live Tor (no pid file in it -> Tor reads as simply not running).
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch.object(tor_status_watcher, 'tcpl_tor_run_path', Path(tmp)), \
             mock.patch.object(tor_status_watcher, 'tcpl_tor_run_path_str', tmp):
            yield


class TestGuiSmoke(unittest.TestCase):
    def _build(self):
        ## no_modal keeps any startup dialog from entering a blocking loop.
        return tcp_gui.TorControlPanelDialog()

    def test_dialog_constructs_and_parses_config(self):
        with tcp_testlib.sandbox(), tcp_testlib.no_modal(), _fake_tor_run_dir():
            dialog = self._build()
            self.assertIsInstance(dialog.tor_conf_info, tcpl.TcplTorConfInfo)

    def test_bridge_type_selector_populated(self):
        ## The combo interleaves QComboBox separators (empty-text items) between
        ## the groups; compare only the real, selectable entries.
        with tcp_testlib.sandbox(), tcp_testlib.no_modal(), _fake_tor_run_dir():
            dialog = self._build()
            items = [
                dialog.bridges_type_combo_box.itemText(i)
                for i in range(dialog.bridges_type_combo_box.count())
            ]
        self.assertEqual(
            [i for i in items if i != ''], tcpl.tcpl_bridge_type_list
        )

    def test_proxy_type_selector_populated(self):
        with tcp_testlib.sandbox(), tcp_testlib.no_modal(), _fake_tor_run_dir():
            dialog = self._build()
            items = [
                dialog.proxy_type_combo_box.itemText(i)
                for i in range(dialog.proxy_type_combo_box.count())
            ]
        self.assertEqual(
            [i for i in items if i != ''], tcpl.tcpl_proxy_type_list
        )


if __name__ == '__main__':
    unittest.main()
