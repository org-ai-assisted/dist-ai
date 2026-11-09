#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: a systemcheck W^X unit that filters SystemCallFilter=~memfd_create
AND spawns a memfd-using GUI helper as a DIRECT child must deny memfd_create
via a soft errno (SystemCallErrorNumber=), never the default SIGSYS kill.

Why: ~memfd_create is a defense-in-depth denylist (it blocks the anonymous-memfd
W^X exec-bypass). With NO SystemCallErrorNumber= the denied call SIGSYS-KILLS the
caller. Both GTK (yad) and Qt/xcb (PyQt, kdialog) allocate their shared-memory
buffer via memfd_create, so a GUI child inheriting the filter is killed outright
-- and in updatecheck that kill was silently masked as success. EPERM blocks the
bypass identically (no memfd is created) while letting the toolkit fall back and
render. The kill adds no security over EPERM here, so for these GUI-spawning
units it is simply the wrong failure mode.

Scope (units whose process tree includes a DIRECT memfd-using GUI child):
  * updatecheck.service -- forks one-time-popup.py (PyQt5) directly.
  * systemcheck.service -- the --progressbarx path forks yad (GTK3) directly
                           (msgcollector -> msgprogressbar -> yad).
canary.service is intentionally EXCLUDED: it is a bash+curl system daemon with
no GUI child, where the aggressive SIGSYS kill on an anomalous memfd_create is a
deliberate, sound choice -- so this lint does not require a soft errno there.

Resolves units via SYSTEMCHECK_REPO (dist-ai/CLAUDE.md).
"""

import os
import unittest

from systemcheck_testlib import read, systemcheck_dir

## systemd renders/accepts this as "kill the caller with SIGSYS" (the default
## when SystemCallErrorNumber= is unset). A real errno (EPERM) fails soft.
KILL_VALUES = {'', 'kill'}

## user-scope units that spawn a memfd-using GUI helper as a direct child.
GUI_UNITS = ('updatecheck.service', 'systemcheck.service')


def _usr_dir() -> str:
    ## systemcheck_dir() -> <repo>/usr/libexec/systemcheck; climb to <repo>/usr.
    return os.path.dirname(os.path.dirname(systemcheck_dir()))


def _directive_values(text: str, key: str) -> list:
    """All values assigned to `key` (last one wins in systemd; empty resets)."""
    out = []
    prefix = key + '='
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('#'):
            continue
        if line.startswith(prefix):
            out.append(line[len(prefix):].strip())
    return out


class WxSeccompErrnoTest(unittest.TestCase):
    def _unit_text(self, unit: str) -> str:
        path = os.path.join(_usr_dir(), 'lib', 'systemd', 'user', unit)
        if not os.path.isfile(path):
            ## style-ok: allow-skip: systemd unit absent (not a --component run)
            raise unittest.SkipTest(f"{path} not found -- set SYSTEMCHECK_REPO")
        return read(path)

    def test_gui_units_deny_memfd_soft_not_sigsys(self) -> None:
        for unit in GUI_UNITS:
            with self.subTest(unit=unit):
                text = self._unit_text(unit)
                filters = _directive_values(text, 'SystemCallFilter')
                self.assertTrue(
                    any('~memfd_create' in value for value in filters),
                    f"{unit}: expected SystemCallFilter=~memfd_create (the W^X "
                    'memfd denylist this lint guards)')
                errnos = _directive_values(text, 'SystemCallErrorNumber')
                self.assertTrue(
                    errnos,
                    f"{unit}: SystemCallFilter=~memfd_create with NO "
                    'SystemCallErrorNumber= -- a denied memfd_create SIGSYS-kills '
                    'the inherited GUI child (yad/PyQt). Set '
                    'SystemCallErrorNumber=EPERM so it fails soft.')
                effective = errnos[-1]
                self.assertNotIn(
                    effective.lower(), KILL_VALUES,
                    f"{unit}: SystemCallErrorNumber={effective!r} still means a "
                    'SIGSYS kill; it must be a soft errno (EPERM).')


if __name__ == '__main__':
    unittest.main()
