#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Manual (interactive) test plan for tor-control-panel / anon-connection-wizard /
restart-tor-gui.

Source: arraybolt3's (Aaron Rainbolt) test plan, Whonix forum thread
"Tor controller GUI (tor-control-panel)" post #161, 2026-07-06.

Only the scenarios that need Tor to actually CONNECT to the network (obfs4 /
snowflake / meek bootstrap, the restart cycle, a live proxy, Onion Circuits
showing real circuits) remain here -- they cannot be automated headlessly and a
human ticks them off during release testing.

Everything automatable has been moved OUT of this skipped plan into real,
running tests:
  * window layout, tabs, the Configure/Accept toggle, the log-source selector,
    and every Anon Connection Wizard page's controls -> test_ui_walkthrough.py;
  * a real direct bootstrap to 'Connected to the Tor network!', the
    Enable-network (DisableNetwork toggle) path, and NEWNYM ('Request new Tor
    circuit') against a throwaway live tor -> test_live_tor.py;
  * torrc generation / parsing, the A1/A3 regressions, proxy field behaviour,
    the include-chain (incl. every bridge/proxy torrc validated by a real
    'tor --verify-config') -> test_torrc_gen.py, test_tor_control_panel.py,
    test_anon_connection_wizard.py, test_torrc_applied.py.

What is left here needs Tor to connect over the network THROUGH a specific
transport/proxy whose reachability is non-deterministic (obfs4/snowflake/meek
bridges, a live SOCKS/HTTP proxy) or a running desktop (Onion Circuits, the
restart-tor-gui popup) -- a human ticks these off at release time.
"""

import unittest

MANUAL = "manual GUI test -- requires a display and a live Tor daemon"


@unittest.skip(MANUAL)
class TorControlPanelManualPlan(unittest.TestCase):
    """Tor Control Panel -- interactive walkthrough."""

    def test_restart_stop_restart_cycle(self):
        """'Restart Tor' walks the bootstrap states to 'Connected to the Tor
        network!'; 'Stop Tor' -> 'Tor is not running'; 'Restart Tor' repeats the
        bootstrap states. (Layout/defaults + the Configure/Accept toggle and its
        revert are auto-tested in test_ui_walkthrough.py.)"""

    def test_bridges_obfs4_full_connect(self):
        """Bridges type obfs4 -> Accept: bootstraps all the way to connected.
        (That the shipped obfs4 bridges + ClientTransportPlugin actually connect
        THROUGH the transport and bootstrap past loading directory info is
        auto-tested against a live tor in test_live_tor.py; only whether a given
        public bridge is fast enough to reach 100% right now is left to a human.)"""

    def test_bridges_snowflake(self):
        """Bridges type Snowflake -> Accept: connects (slowly); Tor log mentions
        'snowflake-client'."""

    def test_bridges_meek(self):
        """Bridges type meek -> Accept: connects (slowly); Tor log mentions
        'meek_lite'."""

    def test_disable_then_enable_network(self):
        """Bridges type 'Disable network' -> Accept: stops Tor, 'The network is
        disabled.', prevents restart. (Regression A3 -- the selector must not
        show duplicate or both toggle entries -- is auto-tested in
        test_tor_control_panel.py; the Enable-network path -- DisableNetwork
        toggled back to 0 then bootstrapping to connected -- is auto-tested
        against a live tor in test_live_tor.py; 'None' -> Accept bootstrapping
        quickly to connected is the same test_live_tor.py direct bootstrap.)"""

    def test_proxy_socks5_then_socks4_then_none(self):
        """Proxy type SOCKS5 with a working proxy -> Accept connects; repeat with
        SOCKS4; then Proxy type None -> Accept connects. (HTTP proxies are
        unreliable; skip.) (Routing a live tor through a real SOCKS5 proxy --
        the Socks5Proxy directive gen_torrc writes -- and bootstrapping to
        connected is auto-tested in test_live_tor.py.)"""

    def test_custom_bridges_cancel_and_apply(self):
        """Bridges type 'Custom bridges' -> Accept shows the custom-bridge screen;
        'Cancel' returns to Control. Re-enter, paste BridgeDB bridges, Accept:
        bootstraps to connected mentioning a pluggable transport. (Regression A1
        -- custom bridges must survive a later reconfigure -- is auto-tested in
        test_torrc_gen.py; A4 -- bridge lines not mangled on redisplay -- is
        fixed in source.)"""

    def test_utilities_tab_onion_circuits(self):
        """'Onion Circuits' shows the current circuits (needs the desktop app
        + a bootstrapped Tor). (That the Utilities tab shows both buttons with
        helpful text is auto-tested in test_ui_walkthrough.py; that a
        bootstrapped Tor accepts the 'Request new Tor circuit' NEWNYM is
        auto-tested in test_live_tor.py.)"""

    def test_logs_tab_live_refresh(self):
        """After generating new Tor log lines, 'Refresh' updates the Tor log
        view. (The source selector, its three options, and torrc rendering are
        auto-tested in test_ui_walkthrough.py.)"""


@unittest.skip(MANUAL)
class AnonConnectionWizardManualPlan(unittest.TestCase):
    """Anon Connection Wizard -- interactive walkthrough."""

    def test_connect_summary_and_torrc(self):
        """'Connect' -> Next shows a summary ('Tor will be enabled', 'Bridges:
        None Selected', 'Proxy: None Selected', 'Show torrc'). Back returns to
        page 1. 'Details' morphs to 'Hide' and shows a torrc with a single
        'DisableNetwork 0'; 'Hide' reverts. Next bootstraps to 'Tor bootstrapping
        done'; Finish closes."""

    def test_disable_tor(self):
        """'Disable Tor' -> Next shows 'Tor is disabled'; the sdwdate-gui icon
        morphs to an 'X'; Finish closes. Re-open, Disable Tor -> Next -> Back
        returns to the first page."""

    def test_bridge_types(self):
        """With 'I need bridges...' checked, the bridge-type combo offers obfs4,
        snowflake, meek and custom bridges; obfs4/meek/snowflake each bootstrap
        to connected (meek/snowflake slowly)."""

    def test_custom_bridges_bootstrap(self):
        """Pasted custom bridges bootstrap to connected mentioning a pluggable
        transport. (That 'Custom bridges' reveals the input + 'How to get
        Bridges?' help is auto-tested in test_ui_walkthrough.py.)"""

    def test_proxy_socks5_and_socks4(self):
        """Local Proxy Configuration with 'Use proxy...' checked shows the proxy
        UI + Help; SOCKS5 and SOCKS4 proxies each bootstrap to connected. (Known
        minor: 'Unknown Bootstrap TAG' shown when connecting via a proxy.)"""

    def test_cancel_and_full_connect(self):
        """Unchecking proxy summarises 'no bridges'; Cancel closes the wizard.
        Re-open, Connect -> Next until connected; Finish closes."""


## restart-tor-gui's progress popup (connect to Tor, then close itself) is now
## auto-tested end-to-end against a live tor in test_live_tor.py
## (LiveRestartTorGuiTest), so it is no longer a manual-only scenario.


if __name__ == "__main__":
    unittest.main()
