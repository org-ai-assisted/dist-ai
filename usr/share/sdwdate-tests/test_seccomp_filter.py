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

The SystemCallFilter model (section-aware parse, systemd empty/'~' reset
semantics) is the SINGLE source dist_ai_seccomp, shared with the W^X denylist
lints (privleap/systemcheck + the per-daemon lints via dist_ai_wx_lint) -- no
hand-synced copy to drift. This suite imports it via a `__file__`-relative
sys.path.insert of dist-ai's dist-packages tree (the dm_test_results idiom).

Scans usr/lib/systemd/system/sdwdate.service (resolved via SDWDATE_REPO).
"""

import os
import sys
import unittest
from typing import Any

HERE: str = os.path.dirname(os.path.abspath(__file__))
## dist_ai_seccomp lives in dist-ai's dist-packages tree (../../lib/python3/...
## from this usr/share/<suite> dir); add it to the path so the allowlist model is
## the one shared implementation, not a hand-synced copy.
_LIB: str = os.path.join(
    os.path.dirname(os.path.dirname(HERE)), 'lib', 'python3', 'dist-packages')
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# pylint: disable=wrong-import-position
from dist_ai_seccomp import (  # noqa: E402
    effective_allowset, is_allowlist, syscall_filter_simple,
    syscall_filter_values)

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


class SeccompFilterTest(unittest.TestCase):
    path: Any
    text: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.path = _service_path()
        if not os.path.exists(cls.path):
            ## style-ok: allow-skip: systemd unit absent (not a --component run)
            raise unittest.SkipTest(
                '%s not found -- set SDWDATE_REPO or install sdwdate' % cls.path)
        with open(cls.path, encoding='utf-8') as handle:
            cls.text = handle.read()

    def test_directive_present(self) -> None:
        self.assertTrue(
            syscall_filter_values(self.text),
            '%s has no SystemCallFilter=' % self.path)

    def test_is_an_allowlist_not_a_denylist(self) -> None:
        self.assertTrue(
            is_allowlist(self.text),
            'a SystemCallFilter directive is a DENYLIST (a "~" value) in %s -- '
            'that permits every unnamed syscall and removes the sandbox' % self.path)

    def test_filter_is_simple_enough_to_reason_about(self) -> None:
        ## The allowlist / required-syscalls reasoning is sound only over PLAIN
        ## syscall tokens; a @group ('@system-service' CONTAINS the core calls) or
        ## a per-syscall action would hide or neuter a required syscall. Fail
        ## closed if sdwdate.service ever used one.
        self.assertTrue(
            syscall_filter_simple(self.text),
            '%s uses a @group / per-syscall action / escape the lint cannot '
            'model -- list syscalls explicitly or extend the lint' % self.path)

    def test_required_syscalls_present(self) -> None:
        missing = REQUIRED_SYSCALLS - effective_allowset(self.text)
        self.assertEqual(
            missing, set(),
            'SystemCallFilter is missing required syscalls %s -- the daemon '
            'would be SIGSYS-killed on that call' % sorted(missing))


if __name__ == '__main__':
    unittest.main()
