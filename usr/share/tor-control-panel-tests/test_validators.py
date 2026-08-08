#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tests for the shared proxy/bridge input validators.

The central guarantee here is that valid_ip() is SYNTACTIC. It used to call
socket.getaddrinfo(), which had two consequences: both front-ends call it from
the GUI thread, so a non-resolving host froze the window until the resolver
timed out; and the lookup went to the system resolver before Tor was
configured, disclosing a user-entered proxy hostname outside Tor.
"""

import socket
import unittest

import tcp_testlib  # noqa: F401  -- sys.path setup for tor_control_panel
from tor_control_panel import validators


class NoResolutionTest(unittest.TestCase):
    def test_valid_ip_never_resolves(self):
        """No name resolution may happen, for any input.

        Guards the privacy property directly rather than trusting that the
        import was removed: any getaddrinfo call fails the test.
        """
        calls = []
        saved = socket.getaddrinfo

        def _boom(*args, **kwargs):
            calls.append(args)
            raise AssertionError(
                'valid_ip() resolved a name; it must stay syntactic so a '
                'proxy hostname is not disclosed to the system resolver')

        socket.getaddrinfo = _boom
        try:
            for value in ('example.com', 'no-such-host.invalid', '192.0.2.1',
                          '::1', '[::1]', 'a' * 300, ''):
                validators.valid_ip(value)
        finally:
            socket.getaddrinfo = saved
        self.assertEqual(calls, [])


class ValidIpTest(unittest.TestCase):
    def test_accepts_ip_literals(self):
        for value in ('192.0.2.1', '127.0.0.1', '::1',
                      '2001:db8::1', '[::1]'):
            with self.subTest(value=value):
                self.assertTrue(validators.valid_ip(value))

    def test_accepts_hostnames(self):
        ## A hostname need not resolve to be a syntactically valid proxy host;
        ## whether it resolves is Tor's business, over Tor.
        for value in ('example.com', 'proxy', 'a-b.example.com',
                      'example.com.'):
            with self.subTest(value=value):
                self.assertTrue(validators.valid_ip(value))

    def test_rejects_blank_and_malformed(self):
        for value in ('', '   ', None, '-bad.example.com', 'bad-.example.com',
                      'has space.example.com', 'under_score.example.com',
                      'a' * 64 + '.example.com', 'a' * 254):
            with self.subTest(value=value):
                self.assertFalse(validators.valid_ip(value))

    def test_always_returns_bool(self):
        ## The fuzz harness asserts this; keep a deterministic guard too.
        for value in ('192.0.2.1', 'example.com', '', '\x00', '::'):
            with self.subTest(value=value):
                self.assertIsInstance(validators.valid_ip(value), bool)


class ValidPortTest(unittest.TestCase):
    def test_range(self):
        for value in (1, '1', 9050, '65535'):
            with self.subTest(value=value):
                self.assertTrue(validators.valid_port(value))
        for value in (0, -1, 65536, 'abc', '', None):
            with self.subTest(value=value):
                self.assertFalse(validators.valid_port(value))


if __name__ == '__main__':
    unittest.main()
