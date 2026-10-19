#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for tor_control_panel_lib.tcpl_bridge_lines_add_prefix() /
tcpl_bridge_lines_remove_prefix(): the conversion between Tor's torrc 'Bridge '
prefixed form and the bare BridgesDB form.
"""

import unittest

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl

tcp_testlib.require_app()


class TestBridgePrefix(unittest.TestCase):
    def test_add_prefix(self):
        out = tcpl.tcpl_bridge_lines_add_prefix(['obfs4 10.0.0.1:1 AA cert=x'])
        self.assertEqual(out, ['Bridge obfs4 10.0.0.1:1 AA cert=x'])

    def test_remove_prefix(self):
        out = tcpl.tcpl_bridge_lines_remove_prefix(
            ['Bridge obfs4 10.0.0.1:1 AA cert=x']
        )
        self.assertEqual(out, ['obfs4 10.0.0.1:1 AA cert=x'])

    def test_round_trip(self):
        bare = ['obfs4 10.0.0.1:1 AA', 'meek_lite 10.0.0.2:2 BB']
        self.assertEqual(
            tcpl.tcpl_bridge_lines_remove_prefix(
                tcpl.tcpl_bridge_lines_add_prefix(bare)
            ),
            bare,
        )

    def test_add_prefix_skips_empty_lines(self):
        out = tcpl.tcpl_bridge_lines_add_prefix(['', 'obfs4 1.2.3.4:1 AA', ''])
        self.assertEqual(out, ['Bridge obfs4 1.2.3.4:1 AA'])

    def test_add_prefix_rejects_already_prefixed(self):
        with self.assertRaises(ValueError):
            tcpl.tcpl_bridge_lines_add_prefix(['Bridge obfs4 1.2.3.4:1 AA'])

    def test_remove_prefix_rejects_unprefixed(self):
        with self.assertRaises(ValueError):
            tcpl.tcpl_bridge_lines_remove_prefix(['obfs4 1.2.3.4:1 AA'])


if __name__ == '__main__':
    unittest.main()
