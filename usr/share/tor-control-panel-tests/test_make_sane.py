#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for tor_control_panel_lib.tcpl_make_tor_conf_info_sane().

Its documented contract: validate / normalise a TcplTorConfInfo and, if it has
issues that cannot be fixed, RETURN A STRING describing what is wrong. The
function must therefore never raise on caller input -- an uncaught exception is
a contract violation.
"""

import copy
import unittest

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl

tcp_testlib.require_app()


def _info(**overrides):
    info = copy.deepcopy(tcpl.tcpl_blank_tor_conf_info)
    for key, value in overrides.items():
        setattr(info, key, value)
    return info


class TestMakeSaneValid(unittest.TestCase):
    def test_blank_is_sane(self):
        result = tcpl.tcpl_make_tor_conf_info_sane(_info())
        self.assertIsInstance(result, tcpl.TcplTorConfInfo)

    def test_disabled_bridges_cleared(self):
        info = _info(
            bridges_enabled=False,
            bridge_type_set={'obfs4'},
            bridge_line_list=['Bridge obfs4 10.0.0.1:1 AA cert=x'],
        )
        result = tcpl.tcpl_make_tor_conf_info_sane(info)
        self.assertIsInstance(result, tcpl.TcplTorConfInfo)
        self.assertEqual(result.bridge_type_set, set())
        self.assertEqual(result.bridge_line_list, [])

    def test_valid_socks5_with_credentials(self):
        info = _info(
            proxy_type='SOCKS5',
            proxy_host='10.0.0.9',
            proxy_port=1080,
            proxy_username='u',
            proxy_password='p',
        )
        result = tcpl.tcpl_make_tor_conf_info_sane(info, proxy_auth_type='SOCKS5')
        self.assertIsInstance(result, tcpl.TcplTorConfInfo)


class TestMakeSaneReturnsErrorString(unittest.TestCase):
    """Bad input must come back as a str, not an exception."""

    def test_unrecognized_proxy_type(self):
        result = tcpl.tcpl_make_tor_conf_info_sane(_info(proxy_type='TELEPATHY'))
        self.assertIsInstance(result, str)

    def test_unrecognized_bridge_type(self):
        info = _info(bridges_enabled=True, bridge_type_set={'telepathy'})
        result = tcpl.tcpl_make_tor_conf_info_sane(info)
        self.assertIsInstance(result, str)

    def test_socks5_username_without_password(self):
        info = _info(
            proxy_type='SOCKS5',
            proxy_host='h',
            proxy_port=1080,
            proxy_username='u',
            proxy_password=None,
        )
        result = tcpl.tcpl_make_tor_conf_info_sane(info, proxy_auth_type='SOCKS5')
        self.assertIsInstance(result, str)

    def test_mismatched_proxy_auth_type(self):
        info = _info(proxy_type='SOCKS5', proxy_host='h', proxy_port=1080)
        result = tcpl.tcpl_make_tor_conf_info_sane(info, proxy_auth_type='SOCKS4')
        self.assertIsInstance(result, str)

    @unittest.expectedFailure
    def test_empty_bridge_line_returns_str_not_assertionerror(self):
        ## KNOWN BUG (see BUGS.md): a caller-supplied empty/whitespace bridge line
        ## with bridges enabled. Contract says return a str; the implementation's
        ## bare 'assert len(bridge_bit_list) > 1' raises AssertionError instead.
        ## xfail until tor-control-panel hardens the bridge path -- an XPASS here
        ## (suite goes red) is the signal to drop this marker once it is fixed.
        info = _info(
            bridges_enabled=True,
            bridge_type_set=set(),
            bridge_line_list=[''],
        )
        try:
            result = tcpl.tcpl_make_tor_conf_info_sane(info)
        except Exception as exc:  # noqa: BLE001
            self.fail(
                "tcpl_make_tor_conf_info_sane raised "
                f"{type(exc).__name__} instead of returning an error string"
            )
        self.assertIsInstance(result, str)


if __name__ == '__main__':
    unittest.main()
