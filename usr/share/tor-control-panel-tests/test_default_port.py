#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Tests for tor_control_panel_lib.tcpl_default_port_for_protocol()."""

import unittest

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl

tcp_testlib.require_app()


class TestDefaultPort(unittest.TestCase):
    def test_http_https(self):
        self.assertEqual(tcpl.tcpl_default_port_for_protocol('HTTP / HTTPS'), 443)

    def test_socks4(self):
        self.assertEqual(tcpl.tcpl_default_port_for_protocol('SOCKS4'), 1080)

    def test_socks5(self):
        self.assertEqual(tcpl.tcpl_default_port_for_protocol('SOCKS5'), 1080)

    def test_unknown_raises_valueerror(self):
        with self.assertRaises(ValueError):
            tcpl.tcpl_default_port_for_protocol('GOPHER')

    def test_every_non_none_proxy_type_has_a_default_port(self):
        ## Each selectable proxy type (all but the leading "None") must map to a
        ## port, else the GUI's default-port lookup raises on selection.
        for proxy_type in tcpl.tcpl_proxy_type_list[1:]:
            self.assertIsInstance(
                tcpl.tcpl_default_port_for_protocol(proxy_type), int
            )


if __name__ == '__main__':
    unittest.main()
