#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the TorBootstrap thread's tag mapping and the controller-close
behaviour on authentication failure.

Constructed with a QObject parent under the offscreen Qt platform; run() (which
needs a live Tor control port via stem) is not exercised here.
"""

import tempfile
import unittest
import unittest.mock as mock

import tcp_testlib

tcp_testlib.require_app()  # side-effect harness: sys.path + offscreen QApplication
from PyQt5.QtCore import QObject
from tor_control_panel import tor_bootstrap

try:
    import stem.control  # noqa: F401
    ## connect_to_control_port()'s 'except stem.connection.*' clauses need the
    ## submodule imported to resolve. In production stem's own authenticate()
    ## imports it; the test mocks authenticate(), so import it here to mirror
    ## that state rather than AttributeError inside the except.
    import stem.connection  # noqa: F401
    _HAS_STEM = True
except Exception:
    _HAS_STEM = False


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

    def test_no_unknown_tags_are_mapped(self):
        """Guard against the reverse drift: a mapped tag Tor never emits is a
        typo that would silently never fire."""
        known = set(TOR_BOOTSTRAP_TAGS) | set(TOR_LEGACY_BOOTSTRAP_TAGS)
        self.assertEqual(set(self.thread.tag_phase) - known, set())


@unittest.skipUnless(_HAS_STEM, 'python3-stem not installed')
class ControllerLeakTest(unittest.TestCase):
    """connect_to_control_port() must close the stem Controller when
    authentication fails: from_socket_file() has already opened the control
    socket and started stem's reader thread, so a bare 'return None' leaks an
    fd and a thread on every Enable/Restart retry."""

    def test_controller_closed_on_auth_failure(self):
        ## Keep the parent referenced: if it is GC'd, Qt deletes the C++
        ## TorBootstrap and self.signal.emit() raises before authenticate().
        parent = QObject()
        thread = tor_bootstrap.TorBootstrap(parent)
        closed = {'count': 0}

        class _FakeController:
            def authenticate(self, *args, **kwargs):
                raise RuntimeError('authentication failed')

            def close(self):
                closed['count'] += 1

        with tempfile.NamedTemporaryFile() as socket_file:
            ## A real, readable path so the existence/readability pre-checks
            ## pass and execution reaches authenticate().
            thread.control_socket_path = socket_file.name
            thread.control_cookie_path = socket_file.name
            with mock.patch.object(stem.control.Controller, 'from_socket_file',
                                   return_value=_FakeController()):
                result = thread.connect_to_control_port()

        self.assertIsNone(result)
        self.assertEqual(
            closed['count'], 1,
            'controller left unclosed on auth failure (fd/thread leak)')

    def test_controller_closed_before_cookie_failure_signal(self):
        ## The UnreadableCookieFile branch emits 'cookie_authentication_failed',
        ## which the GUI handles by terminate()-ing this thread during the sleep
        ## that follows -- so close() must run BEFORE that emit, or the fd and
        ## stem reader thread leak when the thread is aborted mid-sleep.
        parent = QObject()
        thread = tor_bootstrap.TorBootstrap(parent)
        events = []
        thread.signal.connect(lambda phase, _pct: events.append(('emit', phase)))

        class _FakeController:
            def authenticate(self, *args, **kwargs):
                raise stem.connection.UnreadableCookieFile(
                    'unreadable cookie', 'cookie-path', False)

            def close(self):
                events.append('close')

        with tempfile.NamedTemporaryFile() as socket_file:
            thread.control_socket_path = socket_file.name
            thread.control_cookie_path = socket_file.name
            with mock.patch.object(stem.control.Controller, 'from_socket_file',
                                   return_value=_FakeController()), \
                    mock.patch.object(tor_bootstrap.time, 'sleep'):
                result = thread.connect_to_control_port()

        self.assertIsNone(result)
        self.assertIn('close', events)
        self.assertLess(
            events.index('close'),
            events.index(('emit', 'cookie_authentication_failed')),
            'controller must close before the cookie-failure signal (the GUI '
            'terminates the thread during the following sleep)')


if __name__ == '__main__':
    unittest.main()
