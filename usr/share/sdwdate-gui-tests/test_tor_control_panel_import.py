#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for the anon-connection-wizard -> tor-control-panel merge.

anon-connection-wizard was merged into tor-control-panel, so the client's Tor
status now comes from the tor_control_panel package (module tor_status), gated
on the presence of /usr/bin/tor-control-panel rather than the removed
/usr/bin/anon-connection-wizard.

The rest of the suite never exercised the "Tor tooling is installed" branch:
the gate is False on a build/test host, so the conditional import at the top of
sdwdate_gui_client is skipped and a stale reference to the removed
anon_connection_wizard module would ship uncaught. These tests mock the tooling
as present, force the conditional import to run, and assert the client resolves
tor_status from tor_control_panel and reports Tor status through it.

They import sdwdate_gui_client directly (no Qt / X server required).
"""

# pylint: disable=protected-access,import-outside-toplevel

import asyncio
import importlib
import os
import sys
import types
import unittest
import unittest.mock as mock

_TCP_BINARY: str = "/usr/bin/tor-control-panel"


def _fake_tor_control_panel(tor_status_fn):
    """
    Build a fake 'tor_control_panel' package exposing a 'tor_status' submodule
    whose tor_status() is tor_status_fn. Returned as a name -> module dict ready
    to splice into sys.modules.
    """

    pkg = types.ModuleType("tor_control_panel")
    pkg.__path__ = []  # mark as a package so submodule imports resolve
    tor_status_mod = types.ModuleType("tor_control_panel.tor_status")
    tor_status_mod.tor_status = tor_status_fn
    pkg.tor_status = tor_status_mod
    return {
        "tor_control_panel": pkg,
        "tor_control_panel.tor_status": tor_status_mod,
    }


def _reload_client(present_paths, fake_modules):
    """
    (Re)import sdwdate_gui.sdwdate_gui_client with os.path.exists() reporting
    present_paths as present and fake_modules spliced into sys.modules, so the
    module-level Tor-tooling gate and conditional import actually run. Returns
    the freshly imported client module.
    """

    real_exists = os.path.exists

    def fake_exists(path):
        if path in present_paths:
            return True
        return real_exists(path)

    ## Evict the client and any real/fake acw + tcp modules so the top-level
    ## import logic re-runs against our mocks.
    evicted = {}
    for name in list(sys.modules):
        if (
            name == "sdwdate_gui.sdwdate_gui_client"
            or name == "anon_connection_wizard"
            or name.startswith("anon_connection_wizard.")
            or name == "tor_control_panel"
            or name.startswith("tor_control_panel.")
        ):
            evicted[name] = sys.modules.pop(name)

    sys.modules.update(fake_modules)
    try:
        with mock.patch("os.path.exists", side_effect=fake_exists):
            return importlib.import_module("sdwdate_gui.sdwdate_gui_client")
    finally:
        for name in fake_modules:
            sys.modules.pop(name, None)
        sys.modules.pop("sdwdate_gui.sdwdate_gui_client", None)
        sys.modules.update(evicted)


try:
    _reload_client(set(), {})
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
        "or set PYTHONPATH to its dist-packages directory"
    ) from exc


class TorControlPanelImportTests(unittest.TestCase):
    """The client sources Tor status from tor_control_panel, not from acw."""

    def test_tor_status_imported_from_tor_control_panel(self) -> None:
        """With the tooling present, tor_status comes from tor_control_panel."""
        fake = _fake_tor_control_panel(lambda: "tor_enabled")
        client = _reload_client({_TCP_BINARY}, fake)
        self.assertTrue(client.GlobalData.tor_control_panel_installed)
        self.assertIs(client.tor_status, fake["tor_control_panel.tor_status"])

    def test_no_reference_to_removed_anon_connection_wizard(self) -> None:
        """
        The tooling is present but only tor_control_panel is provided (the
        removed anon_connection_wizard module is not). A lingering
        'from anon_connection_wizard import tor_status' would raise
        ModuleNotFoundError here; a clean import must not touch acw at all.
        """
        fake = _fake_tor_control_panel(lambda: "tor_enabled")
        _reload_client({_TCP_BINARY}, fake)
        self.assertNotIn("anon_connection_wizard", sys.modules)

    def test_gate_false_when_tooling_absent(self) -> None:
        """No tor-control-panel binary: the import is skipped, status 'absent'."""
        client = _reload_client(set(), {})
        self.assertFalse(client.GlobalData.tor_control_panel_installed)

    def test_tor_status_changed_reports_running(self) -> None:
        """
        The runtime path works end to end: tor_status() from tor_control_panel
        reporting 'tor_enabled' with a running Tor yields a 'running' update.
        """
        fake = _fake_tor_control_panel(lambda: "tor_enabled")
        client = _reload_client({_TCP_BINARY}, fake)

        sent: list[str] = []

        async def fake_set_tor_status(status: str) -> None:
            sent.append(status)

        real_exists = os.path.exists

        def fake_exists(path):
            if path == client.GlobalData.tor_running_path:
                return True
            return real_exists(path)

        real_set = client.set_tor_status
        client.set_tor_status = fake_set_tor_status
        try:
            with mock.patch("os.path.exists", side_effect=fake_exists):
                asyncio.run(client.tor_status_changed())
        finally:
            client.set_tor_status = real_set

        self.assertEqual(sent, ["running"])


if __name__ == "__main__":
    unittest.main()
