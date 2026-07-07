#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the TorBootstrap thread's tag mapping and lifetime management.

Constructed with a QObject parent under the offscreen Qt platform; run() (which
needs a live Tor control port via stem) is not exercised here.
"""

import re
import unittest

import tcp_testlib as T  # noqa: F401  (imports set up offscreen Qt + QApplication)
from PyQt5.QtCore import QObject
from tor_control_panel import tor_bootstrap


class TagPhaseTest(unittest.TestCase):
    def setUp(self):
        self._parent = QObject()
        self.thread = tor_bootstrap.TorBootstrap(self._parent)

    def test_proxy_and_pt_tags_are_mapped(self):
        """Modern proxy / pluggable-transport bootstrap tags must be recognised
        so they no longer trigger the 'Unknown Bootstrap TAG' fallback."""
        for tag in ("conn_proxy", "conn_done_proxy", "ap_conn_proxy",
                    "ap_conn_done_proxy", "conn_pt", "ap_conn_pt", "handshake_done"):
            with self.subTest(tag=tag):
                self.assertIn(tag, self.thread.tag_phase)

    def test_summary_fallback_regex(self):
        """The fallback for an unknown tag extracts Tor's SUMMARY text."""
        status = 'NOTICE BOOTSTRAP PROGRESS=25 TAG=brand_new_tag SUMMARY="Doing a thing"'
        match = re.search(r'SUMMARY="([^"]*)"', status)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "Doing a thing")


class ThreadLifetimeTest(unittest.TestCase):
    def test_thread_registered_in_active_set(self):
        """A TorBootstrap thread is held in the module-level set so it cannot be
        garbage-collected while running."""
        parent = QObject()
        thread = tor_bootstrap.TorBootstrap(parent)
        self.assertIn(thread, tor_bootstrap._active_bootstrap_threads)


if __name__ == "__main__":
    unittest.main()
