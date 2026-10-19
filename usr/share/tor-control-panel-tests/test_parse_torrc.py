#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Feature + regression tests for tor_control_panel_lib.tcpl_parse_torrc().

Drives the real logic layer: a torrc is written to the sandbox's fake drop-in
and parsed. A valid torrc yields a TcplTorConfInfo; an invalid one yields a str
describing the problem (the function's documented contract).
"""

import unittest

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl

tcp_testlib.require_app()


def _parse(torrc_text):
    with tcp_testlib.sandbox(initial_torrc=torrc_text):
        return tcpl.tcpl_parse_torrc()


class TestParseTorrcValid(unittest.TestCase):
    def test_network_enabled_no_bridges_no_proxy(self):
        info = _parse('DisableNetwork 0\n')
        self.assertIsInstance(info, tcpl.TcplTorConfInfo)
        self.assertTrue(info.network_enabled)
        self.assertEqual(info.bridge_line_list, [])
        self.assertIsNone(info.proxy_type)

    def test_network_disabled(self):
        info = _parse('DisableNetwork 1\n')
        self.assertIsInstance(info, tcpl.TcplTorConfInfo)
        self.assertFalse(info.network_enabled)

    def test_commented_disablenetwork_is_ignored(self):
        ## A commented directive must NOT flip the parsed state.
        info = _parse('DisableNetwork 0\n# DisableNetwork 1\n')
        self.assertIsInstance(info, tcpl.TcplTorConfInfo)
        self.assertTrue(info.network_enabled)

    def test_obfs4_bridges(self):
        torrc = (
            'DisableNetwork 0\n'
            'UseBridges 1\n'
            'ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n'
            'Bridge obfs4 10.0.0.1:443 ABCDEF cert=x iat-mode=0\n'
        )
        info = _parse(torrc)
        self.assertIsInstance(info, tcpl.TcplTorConfInfo)
        self.assertIn('obfs4', info.bridge_type_set)
        self.assertEqual(len(info.bridge_line_list), 1)

    def test_https_proxy_with_auth(self):
        torrc = (
            'DisableNetwork 0\n'
            'HTTPSProxy 10.0.0.9:8080\n'
            'HTTPSProxyAuthenticator user:secretpass\n'
        )
        info = _parse(torrc)
        self.assertIsInstance(info, tcpl.TcplTorConfInfo)
        self.assertEqual(info.proxy_type, 'HTTP / HTTPS')
        self.assertEqual(info.proxy_host, '10.0.0.9')
        self.assertEqual(info.proxy_port, 8080)
        self.assertEqual(info.proxy_username, 'user')
        self.assertEqual(info.proxy_password, 'secretpass')

    def test_socks5_proxy_with_credentials(self):
        torrc = (
            'DisableNetwork 0\n'
            'Socks5Proxy 10.0.0.9:1080\n'
            'Socks5ProxyUsername alice\n'
            'Socks5ProxyPassword wonderland\n'
        )
        info = _parse(torrc)
        self.assertIsInstance(info, tcpl.TcplTorConfInfo)
        self.assertEqual(info.proxy_type, 'SOCKS5')
        self.assertEqual(info.proxy_username, 'alice')
        self.assertEqual(info.proxy_password, 'wonderland')

    def test_socks4_proxy_no_auth(self):
        info = _parse('DisableNetwork 0\nSocks4Proxy 10.0.0.9:1080\n')
        self.assertIsInstance(info, tcpl.TcplTorConfInfo)
        self.assertEqual(info.proxy_type, 'SOCKS4')


class TestParseTorrcInvalid(unittest.TestCase):
    """An invalid torrc must return a str, never raise."""

    def test_missing_file_returns_str(self):
        with tcp_testlib.sandbox() as torrc_file:
            torrc_file.unlink()
            result = tcpl.tcpl_parse_torrc()
        self.assertIsInstance(result, str)

    def test_bad_disablenetwork_value_returns_str(self):
        self.assertIsInstance(_parse('DisableNetwork 7\n'), str)

    def test_double_disablenetwork_returns_str(self):
        self.assertIsInstance(
            _parse('DisableNetwork 0\nDisableNetwork 1\n'), str
        )

    def test_multiple_proxies_returns_str(self):
        torrc = (
            'DisableNetwork 0\n'
            'Socks5Proxy 10.0.0.9:1080\n'
            'HTTPSProxy 10.0.0.8:8080\n'
        )
        self.assertIsInstance(_parse(torrc), str)

    def test_bare_bridge_line_returns_str(self):
        self.assertIsInstance(_parse('DisableNetwork 0\nBridge\n'), str)


if __name__ == '__main__':
    unittest.main()
