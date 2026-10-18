#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for sdwdate.proxy_settings.proxy_settings -- resolves the SOCKS
(ip, port) the time fetch dials:
  * non-Whonix default        -> ('127.0.0.1', '9050')
  * Whonix                    -> GATEWAY_IP from settings_echo, port '9108'
  * /etc/sdwdate.d PROXY_IP / PROXY_PORT drop-in overrides either.

Also pins (does NOT fix) a latent startup crash: on Whonix, if settings_echo
output lacks a GATEWAY_IP="..." line, re.search(...).group(1) raises
AttributeError on None. settings_echo always emits GATEWAY_IP in practice, so
this is defensive-robustness rather than a live bug; it is flagged for review,
not patched here (changing sdwdate to satisfy a test is out of scope).

The filesystem + settings_echo edges are stubbed; the subject is imported for
real via sdwdate_testlib (SDWDATE_REPO).
"""

import os
import tempfile
import unittest
from typing import Any

import sdwdate_testlib

WHONIX_MARKER = '/usr/share/whonix'
SDWDATE_D = '/etc/sdwdate.d/'


class ProxySettingsBase(unittest.TestCase):
    mod: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = sdwdate_testlib.import_sdwdate_submodule('proxy_settings')

    def setUp(self) -> None:
        self._saved: list[tuple] = []
        self._exists = {WHONIX_MARKER: False, SDWDATE_D: False}
        real_exists = os.path.exists
        self._stub(
            self.mod.os.path, 'exists',
            lambda p: self._exists.get(p, real_exists(p)))

    _MISSING = object()

    def tearDown(self) -> None:
        for owner, name, value in reversed(self._saved):
            if value is self._MISSING:
                delattr(owner, name)
            else:
                setattr(owner, name, value)

    def _stub(self, owner, name, value) -> None:
        self._saved.append((owner, name, getattr(owner, name, self._MISSING)))
        setattr(owner, name, value)

    def _enable_whonix(self, settings_echo_output: bytes) -> None:
        self._exists[WHONIX_MARKER] = True
        self._stub(self.mod.os, 'access', lambda path, mode: True)
        self._stub(self.mod, 'check_output', lambda path: settings_echo_output)

    def _dropin(self, content: str) -> None:
        self._exists[SDWDATE_D] = True
        workdir = tempfile.mkdtemp(prefix='sdwdate-proxy.')
        self.addCleanup(self._rmtree, workdir)
        path = os.path.join(workdir, '50_proxy.conf')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(content)
        self._stub(self.mod.glob, 'glob', lambda pattern: [path])

    @staticmethod
    def _rmtree(path: str) -> None:
        for root, _dirs, files in os.walk(path, topdown=False):
            for name in files:
                os.unlink(os.path.join(root, name))
        os.rmdir(path)


class ProxySettingsTest(ProxySettingsBase):
    def test_non_whonix_default(self) -> None:
        self.assertEqual(self.mod.proxy_settings(), ('127.0.0.1', '9050'))

    def test_whonix_uses_gateway_ip_and_port_9108(self) -> None:
        self._enable_whonix(b'GATEWAY_IP="10.152.152.10"\nFOO="bar"\n')
        self.assertEqual(
            self.mod.proxy_settings(), ('10.152.152.10', '9108'))

    def test_dropin_overrides_ip_and_port(self) -> None:
        self._dropin('PROXY_IP=192.0.2.5\nPROXY_PORT=9999\n')
        self.assertEqual(self.mod.proxy_settings(), ('192.0.2.5', '9999'))

    def test_dropin_overrides_whonix_values(self) -> None:
        self._enable_whonix(b'GATEWAY_IP="10.152.152.10"\n')
        self._dropin('PROXY_IP=192.0.2.5\n')
        ip_address, port_number = self.mod.proxy_settings()
        self.assertEqual(ip_address, '192.0.2.5')
        ## port not overridden -> Whonix default retained.
        self.assertEqual(port_number, '9108')

    def test_whonix_without_gateway_ip_raises_attributeerror(self) -> None:
        ## FLAGGED latent crash (not fixed here): a settings_echo output with no
        ## GATEWAY_IP="..." makes re.search return None and .group(1) raise. This
        ## test documents the CURRENT behaviour so a future hardening (guard the
        ## None match) will visibly change it.
        self._enable_whonix(b'SOME_OTHER_KEY="value"\n')
        with self.assertRaises(AttributeError):
            self.mod.proxy_settings()


if __name__ == '__main__':
    unittest.main()
