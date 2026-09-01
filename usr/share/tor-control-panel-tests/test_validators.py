#!/usr/bin/python3 -Bsu

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
        for bad_value in (0, -1, 65536, 'abc', '', None):
            with self.subTest(value=bad_value):
                self.assertFalse(validators.valid_port(bad_value))

    def test_rejects_non_decimal(self):
        ## int() accepts these, but they are not plain decimals and gen_torrc
        ## would carry the junk into the torrc, where Tor rejects it. Fails on
        ## the int()-only validator (which accepts '1_0', '+80', ...).
        for value in ('1_0', '+80', '-80', '\uff18\uff10', '0x50', '0b1',
                      '1e3', '8 0', '80\n90'):
            with self.subTest(value=value):
                self.assertFalse(validators.valid_port(value))

    def test_accepts_surrounding_whitespace(self):
        ## A whitespace-padded decimal normalizes to a valid port; gen_torrc
        ## strips the port before writing, so validate and write agree.
        for value in (' 80', '80 ', '\t443', '80\n', 9050):
            with self.subTest(value=value):
                self.assertTrue(validators.valid_port(value))


class ValidProxyCredentialTest(unittest.TestCase):
    def test_accepts_ordinary_and_empty(self):
        ## Empty means "no credential"; spaces, ':' , '#' and Unicode are all
        ## legal in a SOCKS/HTTP credential (Tor reads the rest of the line).
        for value in ('', 'bob', 'secret', 'my pass word', 'p@ss:w0rd#!',
                      'unicode-\u00e9\u00fc', 'a' * 255):
            with self.subTest(value=value):
                self.assertTrue(validators.valid_proxy_credential(value))

    def test_rejects_control_characters(self):
        ## A line break is the torrc-injection vector; other control bytes have
        ## no place in a credential either.
        for value in ('x\nDisableNetwork 1', 'a\rb', 'a\x00b', 'a\x01b',
                      'a\x7fb', 'a\x9fb'):
            with self.subTest(value=value):
                self.assertFalse(validators.valid_proxy_credential(value))

    def test_rejects_over_255_bytes(self):
        self.assertFalse(validators.valid_proxy_credential('a' * 256))
        ## Byte length, not character count: a 2-byte char at 128 chars = 256.
        self.assertFalse(validators.valid_proxy_credential('\u00e9' * 128))

    def test_none_is_invalid(self):
        self.assertFalse(validators.valid_proxy_credential(None))

    def test_always_returns_bool(self):
        for value in ('bob', '', 'x\ny', None, 'a' * 300):
            with self.subTest(value=value):
                self.assertIsInstance(
                    validators.valid_proxy_credential(value), bool)


if __name__ == '__main__':
    unittest.main()
