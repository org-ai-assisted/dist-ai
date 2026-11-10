#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for TcplTorConfInfo credential redaction (CWE-532).

tor_control_panel.py keeps a development trace, print(self.tor_conf_info), and
the stdout/stderr of a .desktop-launched GUI is captured by the systemd user
journal. So the config object MUST be safe to print: its repr/str must never
contain the proxy password. The redaction is display-only -- the stored field
and __eq__ keep the real value, which torrc generation needs.
"""

import unittest

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl

tcp_testlib.require_app()

SECRET = 'hunter2SuperSecretValue'


def _conf_with_password(password):
    return tcpl.TcplTorConfInfo(
        network_enabled=True,
        bridges_enabled=False,
        bridge_type_set=set(),
        bridge_line_list=[],
        proxy_type='SOCKS5',
        proxy_host='192.0.2.1',
        proxy_port=1080,
        proxy_username='alice',
        proxy_password=password,
    )


class TestRedactCredentials(unittest.TestCase):
    def test_password_absent_from_repr(self):
        self.assertNotIn(SECRET, repr(_conf_with_password(SECRET)))

    def test_password_absent_from_str(self):
        ## str() falls back to __repr__ for a dataclass; print() uses str().
        self.assertNotIn(SECRET, str(_conf_with_password(SECRET)))

    def test_set_password_is_masked(self):
        self.assertIn('[REDACTED]', repr(_conf_with_password(SECRET)))

    def test_none_password_stays_visible(self):
        ## "is a password set?" must survive redaction, so None is shown as-is
        ## and never masked.
        conf_repr = repr(_conf_with_password(None))
        self.assertIn('proxy_password=None', conf_repr)
        self.assertNotIn('[REDACTED]', conf_repr)

    def test_redaction_is_display_only(self):
        ## Rendering must have NO side effect on the credential: a redaction
        ## that mutated the field would still write a torrc with the real
        ## password lost. Render first, THEN assert the field survived.
        conf = _conf_with_password(SECRET)
        repr(conf)
        str(conf)
        self.assertEqual(conf.proxy_password, SECRET)
        self.assertEqual(conf.proxy_username, 'alice')

    def test_non_credential_fields_still_shown(self):
        conf_repr = repr(_conf_with_password(SECRET))
        self.assertIn("proxy_type='SOCKS5'", conf_repr)
        self.assertIn('proxy_port=1080', conf_repr)
        self.assertIn("proxy_host='192.0.2.1'", conf_repr)

    def test_eq_unaffected_by_redaction(self):
        ## Redaction touches __repr__ only; equality still compares real fields.
        self.assertEqual(
            _conf_with_password(SECRET), _conf_with_password(SECRET)
        )
        self.assertNotEqual(
            _conf_with_password(SECRET), _conf_with_password('other')
        )


if __name__ == '__main__':
    unittest.main()
