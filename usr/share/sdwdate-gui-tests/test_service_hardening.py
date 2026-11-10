#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of sdwdate-gui's W^X hardening units -- no root, no systemd, via the
shared dist_ai_wx_lint engine.

Three units, TWO memfd modes (assert each at its REAL value):
  * user sdwdate-gui.service -- a bash launcher whose backgrounded PyQt5 GUI
    (SdwdateGuiFrame window) INHERITS this filter and calls memfd_create to map
    its shm draw buffer. Under the systemd DEFAULT (SIGSYS) it was killed on
    draw; the fix is SystemCallErrorNumber=EPERM -> memfd MUST be 'soft'. This
    test is the regression test for that GUI-render rollout bug.
  * sdwdate-gui-qubes@.service + sdwdate-gui-qubes-proxy-helper.service --
    systemd-socket-proxyd (tiny C forwarders, map NO surface, never call
    memfd_create), so the stricter SIGSYS default is correct -> memfd 'kill'.

Resolved via SDWDATE_GUI_REPO, else the installed path.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(
    os.path.dirname(os.path.dirname(HERE)), 'lib', 'python3', 'dist-packages')
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# pylint: disable=wrong-import-position
from dist_ai_wx_lint import denylist_findings, read_text, self_check  # noqa: E402


class ServiceHardeningTest(unittest.TestCase):
    repo: str

    @classmethod
    def setUpClass(cls) -> None:
        ## Prove the lint can distinguish a correct unit from a broken one before
        ## trusting its verdict on the real units.
        self_check()
        cls.repo = os.environ.get('SDWDATE_GUI_REPO', '').strip()

    def _check(self, relpath: str, **profile) -> None:
        base = self.repo if self.repo else '/'
        path = os.path.join(base, relpath)
        if not os.path.isfile(path):
            if self.repo:
                self.fail('SDWDATE_GUI_REPO set but unit missing: %s' % path)
            ## style-ok: allow-skip: unit absent and no SDWDATE_GUI_REPO
            ## (installed-only run without sdwdate-gui) -- an optional target.
            self.skipTest(
                '%s not found -- set SDWDATE_GUI_REPO or install sdwdate-gui'
                % path)
        for name, ok, detail in denylist_findings(read_text(path), **profile):
            self.assertTrue(ok, '%s: %s (%s)' % (relpath, name, detail))

    def test_user_service_denies_memfd_soft_eperm(self) -> None:
        ## Its backgrounded PyQt5 GUI renders -> EPERM so it falls back to
        ## shm_open instead of SIGSYS-dying on first draw.
        self._check('usr/lib/systemd/user/sdwdate-gui.service',
                    noexecpaths='/tmp /var/tmp /dev/shm', memfd='soft')  # nosec B108 -- systemd NoExecPaths directive value, not a temp path

    def test_qubes_proxy_stays_sigsys(self) -> None:
        ## systemd-socket-proxyd: maps no surface, never calls memfd_create, so
        ## the stricter SIGSYS default is correct.
        self._check('usr/lib/systemd/system/sdwdate-gui-qubes@.service',
                    noexecpaths='/run /tmp /var/tmp /dev/shm /dev', memfd='kill')

    def test_qubes_proxy_helper_stays_sigsys(self) -> None:
        self._check(
            'usr/lib/systemd/system/sdwdate-gui-qubes-proxy-helper.service',
            noexecpaths='/run /tmp /var/tmp /dev/shm /dev', memfd='kill')


if __name__ == '__main__':
    unittest.main()
