#!/usr/bin/python3 -Bsu

## Copyright (C) 2025 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Asserts that the troubleshooting output does not carry proxy credentials.
## The check is that the secret VALUE is absent from what gets printed, not
## merely that a redaction function exists.
##
## Source resolution goes through tcp_testlib, which prefers TCP_REPO and
## otherwise imports the INSTALLED package. The earlier per-package copy of
## this test walked '../../../lib/python3/dist-packages' relative to its own
## file, so it always validated the checkout it sat in and stayed green against
## a stale install.

import io
import os
import contextlib
import tempfile
import unittest

import tcp_testlib  # noqa: F401  -- sys.path setup for tor_control_panel
from tor_control_panel import tor_status

secret = 'hunter2SuperSecretValue'

torrc_sample = f"""\
UseBridges 1
Socks5Proxy 192.0.2.1:1080
Socks5ProxyUsername alice
Socks5ProxyPassword {secret}
   HTTPSProxyAuthenticator alice:{secret}
HashedControlPassword 16:AAAA{secret}
"""


class TestRedactCredentials(unittest.TestCase):

    def test_secret_value_absent(self):
        redacted = tor_status.redact_credentials(torrc_sample)
        self.assertNotIn(secret, redacted)

    def test_option_names_kept(self):
        ## The log must still show WHICH options were set; only the value goes.
        redacted = tor_status.redact_credentials(torrc_sample)
        for option in ('Socks5ProxyUsername', 'Socks5ProxyPassword',
                       'HTTPSProxyAuthenticator', 'HashedControlPassword'):
            self.assertIn(option, redacted)
            self.assertIn(f'{option} [REDACTED]', redacted)

    def test_non_credential_lines_untouched(self):
        redacted = tor_status.redact_credentials(torrc_sample)
        self.assertIn('UseBridges 1', redacted)
        ## The proxy address is not a credential and stays readable, which is
        ## what makes the output useful for troubleshooting.
        self.assertIn('Socks5Proxy 192.0.2.1:1080', redacted)

    def test_case_insensitive_and_indented(self):
        redacted = tor_status.redact_credentials(
            f'  socks5proxypassword {secret}\n')
        self.assertNotIn(secret, redacted)

    def test_valueless_option_does_not_swallow_the_next_line(self):
        ## The separator must be space/tab, not '\s' -- '\s' matches a newline,
        ## so a credential option left without a value consumed the line break
        ## and redacted the FOLLOWING directive, silently hiding it from the
        ## troubleshooting output.
        redacted = tor_status.redact_credentials(
            'Socks5ProxyPassword\nUseBridges 1\nDisableNetwork 0\n')
        self.assertIn('UseBridges 1', redacted)
        self.assertIn('DisableNetwork 0', redacted)
        self.assertNotIn('[REDACTED]', redacted)

    def test_unusual_whitespace_separators_redacted(self):
        ## Tor's config tokenizer treats vertical tab (0x0b) and form feed
        ## (0x0c) as whitespace, so a credential written with one of them is a
        ## valid directive whose value must still be redacted -- '[ \t]+' alone
        ## would let it slip through.
        for sep in ('\x0b', '\x0c'):
            redacted = tor_status.redact_credentials(
                f'HTTPSProxyAuthenticator{sep}alice:{secret}\n')
            self.assertNotIn(secret, redacted)
            self.assertIn('HTTPSProxyAuthenticator [REDACTED]', redacted)

    def test_append_line_prefix_redacted(self):
        ## Tor accepts a leading '+' (append to a list option); the credential
        ## after it must still be redacted, and the '+' preserved.
        redacted = tor_status.redact_credentials(
            f'+Socks5ProxyPassword {secret}\n')
        self.assertNotIn(secret, redacted)
        self.assertIn('+Socks5ProxyPassword [REDACTED]', redacted)

    def test_additional_credential_options_redacted(self):
        ## The legacy HTTP proxy authenticator and Tor's internal hashed control
        ## session password are credential directives too.
        for option in ('HTTPProxyAuthenticator', '__HashedControlSessionPassword'):
            redacted = tor_status.redact_credentials(f'{option} 16:{secret}\n')
            self.assertNotIn(secret, redacted)
            self.assertIn(f'{option} [REDACTED]', redacted)

    def test_commented_credential_redacted(self):
        ## A commented-out credential still holds the secret in the file, so it
        ## must not survive into troubleshooting output either.
        for line in (f'#Socks5ProxyPassword {secret}\n',
                     f'# Socks5ProxyPassword {secret}\n'):
            redacted = tor_status.redact_credentials(line)
            self.assertNotIn(secret, redacted)
            self.assertIn('Socks5ProxyPassword [REDACTED]', redacted)

    def test_write_to_temp_then_move_redacts_debug_output(self):
        ## write_to_temp_then_move() prints the staged content for debugging;
        ## that print is a second troubleshooting-output path and must redact
        ## too (only the privileged plumbing is stubbed, so the REAL function
        ## runs).
        with tempfile.TemporaryDirectory() as tmp:
            saved_torrc = tor_status.torrc_file_path
            saved_comm = tor_status.acw_comm_file_path
            saved_check_call = tor_status.subprocess.check_call
            tor_status.torrc_file_path = os.path.join(tmp, '40_tcp.conf')
            tor_status.acw_comm_file_path = os.path.join(tmp, 'tor.conf')
            tor_status.subprocess.check_call = lambda *a, **k: 0
            try:
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    tor_status.write_to_temp_then_move(
                        f'DisableNetwork 0\nSocks5ProxyPassword {secret}\n')
                out = captured.getvalue()
            finally:
                tor_status.torrc_file_path = saved_torrc
                tor_status.acw_comm_file_path = saved_comm
                tor_status.subprocess.check_call = saved_check_call
        self.assertNotIn(secret, out)
        self.assertIn('Socks5ProxyPassword [REDACTED]', out)

    def test_cat_output_redacted(self):
        ## Integration: the real cat() is one of the two functions that print
        ## torrc content, so it is exercised rather than only the helper.
        with tempfile.NamedTemporaryFile('w', suffix='.conf',
                                         delete=False) as torrc_file:
            torrc_file.write(torrc_sample)
            torrc_path = torrc_file.name
        try:
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                tor_status.cat(torrc_path)
            self.assertNotIn(secret, captured.getvalue())
            self.assertIn('Socks5ProxyPassword [REDACTED]',
                          captured.getvalue())
        finally:
            os.unlink(torrc_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
