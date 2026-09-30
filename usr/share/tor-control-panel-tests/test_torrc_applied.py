#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
CONTENT / VALID: after a configuration change, the torrc drop-in that
tor-control-panel writes contains the directives Tor needs -- and, fed to a real
``tor --verify-config``, Tor actually accepts it. Asserting the bytes
(test_torrc_gen.py) is good; proving a real Tor parses them is stronger. The
test also shows the ignored-vs-applied difference: a drop-in is only honoured if
the top-level torrc ``%include``s its directory.

The live tests skip automatically when no ``tor`` binary is installed (e.g. a
minimal CI image), so the suite still runs everywhere.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import tcp_testlib as T  # noqa: F401  (sets up sys.path / offscreen Qt)
from tor_control_panel import torrc_gen


TOR = shutil.which('tor')


def _dropin_for(args):
    """The exact drop-in tor-control-panel would write for `args`."""
    with T.sandbox() as torrc:
        torrc_gen.gen_torrc(args)
        return torrc.read_text(encoding='utf-8')


@unittest.skipUnless(TOR, 'tor binary not installed')
class TorVerifyConfigTest(unittest.TestCase):
    """Feed the *actually generated* drop-in to a real ``tor --verify-config``."""

    ## Each is a gen_torrc() argument list; label is only for subTest output.
    CONFIGS = [
        ('none', ['None', 'None', 'None']),
        ('obfs4', ['obfs4', 'None', 'None']),
        ('meek', ['meek', 'None', 'None']),
        ('snowflake', ['snowflake', 'None', 'None']),
        ('custom-obfs4',
         ['None',
          'obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01',
          'None']),
        ('socks5', ['None', 'None', 'SOCKS5', '127.0.0.1', '9050', '', '']),
        ('socks5-auth',
         ['None', 'None', 'SOCKS5', '127.0.0.1', '9050', 'bob', 'secret']),
        ('https-proxy',
         ['None', 'None', 'HTTP / HTTPS', '127.0.0.1', '8080', '', '']),
    ]

    def _verify(self, dropin_text, include=True):
        """Write `dropin_text` as the drop-in, build a top-level torrc that may
        or may not %include it, and run ``tor --verify-config``. Returns
        (returncode, combined_output)."""
        with tempfile.TemporaryDirectory(prefix='tcp-verify-') as tmp:
            tmp_path = Path(tmp)
            (tmp_path / 'torrc.d').mkdir()
            (tmp_path / 'data').mkdir()
            (tmp_path / 'torrc.d' / '40_tor_control_panel.conf').write_text(
                dropin_text, encoding='utf-8')
            main = 'DataDirectory {0}/data\nSocksPort 0\n'.format(tmp_path)
            if include:
                main += '%include {0}/torrc.d/*.conf\n'.format(tmp_path)
            main_path = tmp_path / 'torrc'
            main_path.write_text(main, encoding='utf-8')
            assert TOR is not None  # guarded by skipUnless(TOR, ...) on the class
            proc = subprocess.run(
                [TOR, '-f', str(main_path), '--verify-config'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=90, encoding='utf-8')
            return proc.returncode, proc.stdout

    def test_generated_dropins_are_valid_tor_config(self):
        ## Every configuration tor-control-panel can produce must be accepted
        ## by Tor when it is actually read (via the %include).
        for label, args in self.CONFIGS:
            with self.subTest(config=label):
                rc, out = self._verify(_dropin_for(args))
                self.assertEqual(
                    rc, 0, 'tor rejected the {0} drop-in:\n{1}'.format(label, out))

    def test_dropin_is_ignored_without_the_include(self):
        ## The exact failure mode a plain-Debian user would hit: an invalid
        ## directive in the drop-in is SILENTLY IGNORED when the main torrc
        ## lacks the %include (verify wrongly passes), but is READ and rejected
        ## once the include is present. This is what makes "did the config
        ## actually get applied?" a real question worth a test.
        bad = 'ThisIsNotARealTorOption 1\n'
        rc_noinc, _ = self._verify(bad, include=False)
        self.assertEqual(
            rc_noinc, 0,
            'drop-in should be ignored (config valid) without the %include')
        rc_inc, out = self._verify(bad, include=True)
        self.assertNotEqual(
            rc_inc, 0,
            'with the %include present Tor must READ and reject the drop-in:\n'
            + out)

    def test_disablenetwork_both_states_accepted(self):
        ## DisableNetwork is the directive the Enable/Disable Tor button flips;
        ## prove Tor accepts our drop-in in both states.
        for value in ('0', '1'):
            with self.subTest(DisableNetwork=value):
                rc, out = self._verify('DisableNetwork {0}\n'.format(value))
                self.assertEqual(rc, 0, out)


if __name__ == '__main__':
    unittest.main()
