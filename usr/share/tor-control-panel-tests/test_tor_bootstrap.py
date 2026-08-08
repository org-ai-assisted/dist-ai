#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the TorBootstrap thread's tag mapping and lifetime management.

Constructed with a QObject parent under the offscreen Qt platform; run() (which
needs a live Tor control port via stem) is not exercised here.
"""

import unittest

import tcp_testlib

tcp_testlib.require_app()  # side-effect harness: sys.path + offscreen QApplication
from PyQt5.QtCore import QObject
from tor_control_panel import tor_bootstrap


## Every bootstrap tag Tor can emit, transcribed from its own boot_to_str_tab:
## https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/feature/control/control_bootstrap.c
## The panel must map all of them, else the user sees an "Unknown Bootstrap TAG"
## placeholder instead of progress. "undef" is excluded: it is Tor's internal
## pre-bootstrap sentinel, never reported as a phase.
TOR_BOOTSTRAP_TAGS = (
    'starting',
    'conn_pt', 'conn_done_pt', 'conn_proxy', 'conn_done_proxy',
    'conn', 'conn_done', 'handshake', 'handshake_done',
    'onehop_create', 'requesting_status', 'loading_status', 'loading_keys',
    'requesting_descriptors', 'loading_descriptors', 'enough_dirinfo',
    'ap_conn_pt', 'ap_conn_done_pt', 'ap_conn_proxy', 'ap_conn_done_proxy',
    'ap_conn', 'ap_conn_done', 'ap_handshake', 'ap_handshake_done',
    'circuit_create', 'done',
)

## Tags Tor emitted before 0.4.0.x. Still mapped so an old Tor keeps working.
TOR_LEGACY_BOOTSTRAP_TAGS = (
    'conn_dir', 'handshake_dir', 'conn_or', 'handshake_or',
)


class TagPhaseTest(unittest.TestCase):
    def setUp(self):
        self._parent = QObject()
        self.thread = tor_bootstrap.TorBootstrap(self._parent)

    def test_every_tor_bootstrap_tag_is_mapped(self):
        """The full Tor bootstrap tag table must be covered, so no real phase
        falls through to the 'Unknown Bootstrap TAG' message."""
        for tag in TOR_BOOTSTRAP_TAGS + TOR_LEGACY_BOOTSTRAP_TAGS:
            with self.subTest(tag=tag):
                self.assertIn(tag, self.thread.tag_phase)
                self.assertTrue(
                    self.thread.tag_phase[tag].strip(),
                    f"{tag} maps to an empty phase description",
                )

    def test_no_unknown_tags_are_mapped(self):
        """Guard against the reverse drift: a mapped tag Tor never emits is a
        typo that would silently never fire."""
        known = set(TOR_BOOTSTRAP_TAGS) | set(TOR_LEGACY_BOOTSTRAP_TAGS)
        self.assertEqual(set(self.thread.tag_phase) - known, set())


class ThreadLifetimeTest(unittest.TestCase):
    def test_thread_registered_in_active_set(self):
        """A TorBootstrap thread is held in the module-level set so it cannot be
        garbage-collected while running."""
        parent = QObject()
        thread = tor_bootstrap.TorBootstrap(parent)
        self.assertIn(thread, tor_bootstrap._active_bootstrap_threads)


class ParseBootstrapPhaseTest(unittest.TestCase):
    """The extracted, GUI-free parser for untrusted 'status/bootstrap-phase'
    control output (also fuzzed by fuzz_torrc / fuzz/fuzz_bootstrap.py)."""

    TAG_PHASE = {'conn_done': 'Connected to a relay', 'done': 'Done!'}

    def _parse(self, line):
        from tor_control_panel.tor_bootstrap_parse import parse_bootstrap_phase
        return parse_bootstrap_phase(line, self.TAG_PHASE)

    def test_known_tag_maps_to_phase(self):
        line = ('NOTICE BOOTSTRAP PROGRESS=10 TAG=conn_done '
                'SUMMARY="Connected to a relay"')
        self.assertEqual(self._parse(line), ('Connected to a relay', 10))

    def test_unknown_tag_uses_sanitized_summary(self):
        line = 'x PROGRESS=25 TAG=brand_new SUMMARY="Doing \x1b[31ma thing"'
        phase, percent = self._parse(line)
        self.assertEqual(percent, 25)
        self.assertNotIn('\x1b', phase)  # escape stripped by sanitize_string
        self.assertIn('Doing', phase)

    def test_malformed_lines_return_none(self):
        for line in ('', 'garbage', 'PROGRESS=10', 'TAG=x SUMMARY="y"',
                     'no progress here TAG=x', 'PROGRESS=abc TAG=x SUMMARY=z'):
            with self.subTest(line=line):
                self.assertIsNone(self._parse(line))

    def test_huge_progress_does_not_crash(self):
        line = 'x PROGRESS=999999999999999999 TAG=conn_done SUMMARY="s"'
        _phase, percent = self._parse(line)
        self.assertIsInstance(percent, int)

    def test_percent_is_clamped_to_100(self):
        """An out-of-range PROGRESS must not exceed 100.

        tor_bootstrap drives 'while bootstrap_percent < 100', and completion is
        detected with '== 100'. An unclamped 999 skips past both: the loop ends
        without the completion branch ever running, so the thread exits and the
        wizard sits at 'Bootstrapping...' with no finish.
        """
        for raw in ('101', '999', '999999999999999999'):
            with self.subTest(raw=raw):
                _phase, percent = self._parse(
                    f'x PROGRESS={raw} TAG=conn_done SUMMARY="s"')
                self.assertEqual(percent, 100)

    def test_summary_text_cannot_supply_progress(self):
        """SUMMARY is attacker-influenced text Tor echoes back, so a greedy
        '.*' that takes the LAST PROGRESS= in the line let it drive the value.
        """
        line = ('NOTICE BOOTSTRAP PROGRESS=10 TAG=conn_done '
                'SUMMARY="relay said PROGRESS=100"')
        phase, percent = self._parse(line)
        self.assertEqual(percent, 10)
        self.assertEqual(phase, 'Connected to a relay')

    def test_summary_text_cannot_extend_the_tag(self):
        """A greedy 'TAG=(.*) +SUMMARY' matched the LAST ' SUMMARY', so a
        SUMMARY value containing the word made TAG absorb the text between."""
        line = ('x PROGRESS=10 TAG=conn_done '
                'SUMMARY="mentions SUMMARY= again"')
        phase, percent = self._parse(line)
        self.assertEqual(percent, 10)
        self.assertEqual(phase, 'Connected to a relay')


if __name__ == '__main__':
    unittest.main()
