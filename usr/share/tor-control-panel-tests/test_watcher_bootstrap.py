#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for tor_status_watcher.TcplTorMonitor.emit_bootstrap_event_maybe().

This parses untrusted 'status/bootstrap-phase' data from the Tor control port,
so it must reject malformed / out-of-range / oversized fields and only emit a
torBootstrapChanged signal for well-formed input. Driven directly (no control
socket, no live Tor) by feeding argument dicts and recording the signal.
"""

import unittest

import tcp_testlib
from tor_control_panel.tor_status_watcher import TcplTorMonitor

tcp_testlib.require_app()


class TestEmitBootstrapEventMaybe(unittest.TestCase):
    def setUp(self):
        self.monitor = TcplTorMonitor()
        self.events: list[tuple[int, str, str]] = []
        self.monitor.torBootstrapChanged.connect(
            lambda pct, tag, summary: self.events.append((pct, tag, summary))
        )

    def _feed(self, args):
        self.monitor.emit_bootstrap_event_maybe(args)

    def test_valid_event_is_emitted(self):
        self._feed({'PROGRESS': '50', 'TAG': 'conn', 'SUMMARY': 'Connecting'})
        self.assertEqual(self.events, [(50, 'conn', 'Connecting')])

    def test_missing_progress_suppressed(self):
        self._feed({'TAG': 'conn', 'SUMMARY': 'x'})
        self.assertEqual(self.events, [])

    def test_missing_tag_suppressed(self):
        self._feed({'PROGRESS': '50', 'SUMMARY': 'x'})
        self.assertEqual(self.events, [])

    def test_non_numeric_progress_suppressed(self):
        self._feed({'PROGRESS': 'abc', 'TAG': 't', 'SUMMARY': 's'})
        self.assertEqual(self.events, [])

    def test_out_of_range_progress_suppressed(self):
        self._feed({'PROGRESS': '150', 'TAG': 't', 'SUMMARY': 's'})
        self.assertEqual(self.events, [])

    def test_overlong_progress_field_suppressed(self):
        ## len(PROGRESS) > 3 is rejected before the int() parse.
        self._feed({'PROGRESS': '0050', 'TAG': 't', 'SUMMARY': 's'})
        self.assertEqual(self.events, [])

    def test_overlong_tag_suppressed(self):
        self._feed({'PROGRESS': '50', 'TAG': 'x' * 101, 'SUMMARY': 's'})
        self.assertEqual(self.events, [])

    def test_overlong_summary_suppressed(self):
        self._feed({'PROGRESS': '50', 'TAG': 't', 'SUMMARY': 'x' * 2049})
        self.assertEqual(self.events, [])

    def test_boundary_progress_zero_and_hundred(self):
        self._feed({'PROGRESS': '0', 'TAG': 'a', 'SUMMARY': 's'})
        self._feed({'PROGRESS': '100', 'TAG': 'b', 'SUMMARY': 's'})
        self.assertEqual([e[0] for e in self.events], [0, 100])


if __name__ == '__main__':
    unittest.main()
