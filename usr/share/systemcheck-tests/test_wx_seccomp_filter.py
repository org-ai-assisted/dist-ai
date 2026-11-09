#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: a systemcheck W^X unit that filters SystemCallFilter=~memfd_create
AND spawns a memfd-using GUI helper as a DIRECT child must deny memfd_create via
a soft errno (SystemCallErrorNumber=EPERM), never the default SIGSYS kill.

Why: ~memfd_create is a defense-in-depth denylist (it blocks the anonymous-memfd
W^X exec-bypass). With NO SystemCallErrorNumber= the denied call SIGSYS-KILLS the
caller. Both GTK (yad) and Qt/xcb (PyQt, kdialog) allocate their shared-memory
buffer via memfd_create, so a GUI child inheriting the filter is killed outright
-- and in updatecheck that kill was silently masked as success. EPERM blocks the
bypass identically (no memfd is created) while letting the toolkit fall back and
render. The kill adds no security over EPERM here, so for these GUI-spawning
units it is simply the wrong failure mode.

The check models systemd's effective-policy semantics (memfd_denial): the
[Service] section only, SystemCallFilter= empty-reset, a per-syscall ':' action
that overrides the global SystemCallErrorNumber, and errno validity -- a lint
fooled by any of those would report a confident wrong pass. (The parser mirrors
privleap-tests/service_hardening_test.py; a cross-suite shared module is not on
either suite's import path, so the two are kept in step by hand.)

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

## systemd accepts an errno name or a number 1..4095; anything else (empty,
## 'kill', 0, out of range, junk) is NOT a soft-fail errno.
_ERRNO_MIN, _ERRNO_MAX = 1, 4095

## user-scope units that spawn a memfd-using GUI helper as a direct child.
GUI_UNITS = ('updatecheck.service', 'systemcheck.service')


def _usr_dir() -> str:
    ## systemcheck_dir() -> <repo>/usr/libexec/systemcheck; climb to <repo>/usr.
    return os.path.dirname(os.path.dirname(systemcheck_dir()))


def _service_lines(text: str) -> list:
    """Logical directive lines inside [Service], '\\'-continuations joined.
    Directives outside [Service] are inert, so the lint ignores them too."""
    out: list = []
    buf: str = ''
    in_service: bool = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            in_service = stripped.lower() == '[service]'
            continue
        if not in_service or stripped.startswith('#'):
            continue
        if stripped.endswith('\\'):
            buf += stripped[:-1] + ' '
        else:
            out.append((buf + stripped).strip())
            buf = ''
    if buf:
        out.append(buf.strip())
    return out


def _service_values(lines: list, key: str) -> list:
    prefix = key + '='
    return [line[len(prefix):].strip() for line in lines
            if line.startswith(prefix)]


def _errno_is_soft(value: str) -> bool:
    val = value.strip()
    if not val or val.lower() == 'kill':
        return False
    if val.isdigit():
        return _ERRNO_MIN <= int(val) <= _ERRNO_MAX
    ## an errno NAME (EPERM / EACCES / ENOSYS ...): all uppercase, starts with E.
    ## Full spelling validity is systemd-analyze verify's job; here we only reject
    ## obvious junk and lowercase.
    return (val.startswith('E') and val.isupper()
            and val.replace('_', '').isalpha())


def memfd_denial(text: str) -> str:
    """'none' | 'soft' | 'kill' for memfd_create under [Service], honoring
    SystemCallFilter= empty-reset, a per-syscall ':' action (overrides the global
    errno), and the global SystemCallErrorNumber. Only '~' denylists are modelled
    -- the form these units use."""
    lines = _service_lines(text)
    effective: list = []
    for value in _service_values(lines, 'SystemCallFilter'):
        if value == '':
            effective = []
        else:
            effective.append(value)
    denied = False
    per_syscall = None
    for value in effective:
        if not value.startswith('~'):
            continue
        for token in value[1:].split():
            if token.split(':', 1)[0] == 'memfd_create':
                denied = True
                per_syscall = token.split(':', 1)[1] if ':' in token else None
    if not denied:
        return 'none'
    if per_syscall is not None:
        return 'soft' if _errno_is_soft(per_syscall) else 'kill'
    errnos = _service_values(lines, 'SystemCallErrorNumber')
    if errnos and _errno_is_soft(errnos[-1]):
        return 'soft'
    return 'kill'


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
                self.assertEqual(
                    memfd_denial(text), 'soft',
                    f"{unit}: memfd_create must be denied via a soft errno "
                    '(SystemCallErrorNumber=EPERM), not the default SIGSYS kill '
                    '-- otherwise the inherited GUI child (yad/PyQt) is killed. '
                    "memfd_denial reported it as not 'soft' (see effective "
                    'filter / per-syscall action / errno).')


if __name__ == '__main__':
    unittest.main()
