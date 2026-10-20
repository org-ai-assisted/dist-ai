#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for tor_control_panel_lib.tcpl_write_torrc() and the parse<->write
round-trip. The privileged helper is stubbed by tcp_testlib.sandbox(): the
config the client pushes through the comm FIFO lands in the fake torrc file,
reproducing the real tcp-write-torrc helper's effect without root.
"""

import copy
import unittest

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl

tcp_testlib.require_app()


def _blank():
    return copy.deepcopy(tcpl.tcpl_blank_tor_conf_info)


class TestWriteTorrc(unittest.TestCase):
    def test_write_lands_in_torrc_file(self):
        info = _blank()
        info.network_enabled = True
        with tcp_testlib.sandbox() as torrc_file:
            tcpl.tcpl_write_torrc(info)
            written = torrc_file.read_text(encoding='utf-8')
        self.assertIn('DisableNetwork 0', written)
        self.assertIn('UseBridges 0', written)
        self.assertIn('tor-control-panel', written)

    def test_disabled_network_written(self):
        info = _blank()
        info.network_enabled = False
        with tcp_testlib.sandbox() as torrc_file:
            tcpl.tcpl_write_torrc(info)
            written = torrc_file.read_text(encoding='utf-8')
        self.assertIn('DisableNetwork 1', written)

    def test_socks5_proxy_round_trip(self):
        info = _blank()
        info.network_enabled = True
        info.proxy_type = 'SOCKS5'
        info.proxy_host = '10.0.0.9'
        info.proxy_port = 1080
        info.proxy_username = 'alice'
        info.proxy_password = 'wonderland'
        with tcp_testlib.sandbox():
            tcpl.tcpl_write_torrc(info)
            reparsed = tcpl.tcpl_parse_torrc()
        self.assertIsInstance(reparsed, tcpl.TcplTorConfInfo)
        self.assertEqual(reparsed.proxy_type, 'SOCKS5')
        self.assertEqual(reparsed.proxy_host, '10.0.0.9')
        self.assertEqual(reparsed.proxy_username, 'alice')
        self.assertEqual(reparsed.proxy_password, 'wonderland')

    def test_obfs4_bridge_round_trip(self):
        info = _blank()
        info.network_enabled = True
        info.bridge_type_set = {'obfs4'}
        info.bridge_line_list = [
            'Bridge obfs4 10.0.0.1:443 ABCDEF cert=x iat-mode=0'
        ]
        with tcp_testlib.sandbox():
            tcpl.tcpl_write_torrc(info)
            written = tcpl.tcpl_torrc_file.read_text(encoding='utf-8')
            reparsed = tcpl.tcpl_parse_torrc()
        self.assertIn('ClientTransportPlugin obfs4', written)
        self.assertIn('Bridge obfs4 10.0.0.1:443', written)
        self.assertIsInstance(reparsed, tcpl.TcplTorConfInfo)
        self.assertIn('obfs4', reparsed.bridge_type_set)

    def test_http_proxy_auth_round_trip(self):
        info = _blank()
        info.network_enabled = True
        info.proxy_type = 'HTTP / HTTPS'
        info.proxy_host = '10.0.0.8'
        info.proxy_port = 8080
        info.proxy_username = 'bob'
        info.proxy_password = 'hunter2'
        with tcp_testlib.sandbox():
            tcpl.tcpl_write_torrc(info)
            reparsed = tcpl.tcpl_parse_torrc()
        self.assertIsInstance(reparsed, tcpl.TcplTorConfInfo)
        self.assertEqual(reparsed.proxy_type, 'HTTP / HTTPS')
        self.assertEqual(reparsed.proxy_username, 'bob')
        self.assertEqual(reparsed.proxy_password, 'hunter2')

    @unittest.expectedFailure
    def test_socks5_proxy_credentials_with_space_round_trip(self):
        ## KNOWN BUG (org-ai-assisted/tor-control-panel#6): a Socks5 proxy
        ## username/password containing a space is written unquoted, and
        ## tcpl_parse_torrc still guards `len(torrc_bit_list) == 2` before the
        ## `" ".join(...)`, so the >2-token line is rejected ("Invalid number of
        ## arguments") and the config comes back blank. xfail until the parser
        ## accepts the space; an XPASS here (suite red) is the signal to drop it.
        info = _blank()
        info.network_enabled = True
        info.proxy_type = 'SOCKS5'
        info.proxy_host = '10.0.0.9'
        info.proxy_port = 1080
        info.proxy_username = 'alice smith'
        info.proxy_password = 'open sesame'
        with tcp_testlib.sandbox():
            tcpl.tcpl_write_torrc(info)
            reparsed = tcpl.tcpl_parse_torrc()
        self.assertIsInstance(reparsed, tcpl.TcplTorConfInfo)
        self.assertEqual(reparsed.proxy_username, 'alice smith')
        self.assertEqual(reparsed.proxy_password, 'open sesame')


if __name__ == '__main__':
    unittest.main()
