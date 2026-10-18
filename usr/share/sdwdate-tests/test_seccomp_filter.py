#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: sdwdate.service's SystemCallFilter must stay an ALLOWLIST (no
leading '~') listing the syscalls the daemon genuinely needs.

If a '~' crept in, the directive would flip to a DENYLIST and permit everything
not named -- silently removing the sandbox. If a required syscall were dropped,
the daemon would be SIGSYS-killed at runtime (e.g. clock_settime is how it sets
the clock; splice/mincore show up in the Python/Tor path). This static parse
catches both at CI time, no root.

Scans usr/lib/systemd/system/sdwdate.service (resolved via SDWDATE_REPO),
joining the '\\'-continued SystemCallFilter= assignment.
"""

import os
import unittest

## A conservative core that must always be present; not the whole set, so adding
## a syscall does not need a test edit, but dropping one of these fails.
REQUIRED_SYSCALLS = {
    'read', 'write', 'openat', 'close', 'socket', 'connect', 'sendto',
    'recvfrom', 'clone', 'execve', 'clock_settime', 'splice', 'mincore',
    'getrandom', 'rt_sigaction',
}


def _service_path() -> str:
    repo = os.environ.get('SDWDATE_REPO', '').strip()
    base = repo if repo else '/'
    return os.path.join(
        base, 'usr', 'lib', 'systemd', 'system', 'sdwdate.service')


def _parse_syscall_filter(lines):
    """Return the whitespace-joined SystemCallFilter value, following '\\'
    line continuations, or None if the directive is absent."""
    collecting = False
    parts = []
    for raw in lines:
        line = raw.rstrip('\n')
        if not collecting:
            if line.startswith('SystemCallFilter='):
                collecting = True
                body = line[len('SystemCallFilter='):]
                continued = body.endswith('\\')
                parts.append(body[:-1] if continued else body)
                if not continued:
                    break
        else:
            continued = line.endswith('\\')
            parts.append(line[:-1] if continued else line)
            if not continued:
                break
    if not parts:
        return None
    return ' '.join(parts)


class SeccompFilterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = _service_path()
        if not os.path.exists(cls.path):
            ## style-ok: allow-skip: systemd unit absent (not a --component run)
            raise unittest.SkipTest(
                '%s not found -- set SDWDATE_REPO or install sdwdate' % cls.path)
        with open(cls.path, encoding='utf-8') as handle:
            cls.value = _parse_syscall_filter(handle.readlines())

    def test_directive_present(self) -> None:
        self.assertIsNotNone(
            self.value, '%s has no SystemCallFilter=' % self.path)

    def test_is_an_allowlist_not_a_denylist(self) -> None:
        stripped = self.value.strip()
        self.assertFalse(
            stripped.startswith('~'),
            'SystemCallFilter starts with "~" -- that is a DENYLIST, which '
            'permits every unnamed syscall and removes the sandbox')

    def test_required_syscalls_present(self) -> None:
        tokens = set(self.value.split())
        missing = REQUIRED_SYSCALLS - tokens
        self.assertEqual(
            missing, set(),
            'SystemCallFilter is missing required syscalls %s -- the daemon '
            'would be SIGSYS-killed on that call' % sorted(missing))


if __name__ == '__main__':
    unittest.main()
