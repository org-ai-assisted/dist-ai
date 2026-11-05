#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for kloak.service's seccomp SystemCallFilter arch-completeness.

Bug (Whonix 18.2.4.2 arm64 / Apple Silicon): kloak.service crash-looped with
SIGSYS (status=31/SYS). The allowlist (SystemCallArchitectures=native, no '~'
prefix) listed the x86-only syscalls 'open' and 'access' plus 'faccessat2', but
NOT bare 'faccessat'. On arm64 there is no access()/open() syscall, so glibc
emits faccessat (nr 48) and openat; 'openat' was listed but bare 'faccessat' was
not, so access() was killed by seccomp. faccessat2 (nr 439) is a DIFFERENT
syscall used only for the flags path and does NOT cover bare access().

Verified both directions before this test: 'qemu-aarch64-static -strace' on a
cross-compiled binary shows access()->faccessat, open()->openat; and the exact
filter run under systemd (SystemCallArchitectures=native) kills a bare-faccessat
caller with status=31/SYS.

Invariant guarded: whenever a legacy x86-only file-op syscall is in the
allowlist, its arch-neutral replacement (the one glibc emits on arm64) is also
present -- otherwise the daemon dies on that arch. Drives the REAL kloak.service
(resolved via KLOAK_REPO); no copy, no body-cut.
"""

import os
import re
import unittest

## Legacy (x86-only) syscall -> the arch-neutral syscall glibc emits on arm64.
## If the legacy name is in the allowlist, the replacement MUST be too.
LEGACY_TO_MODERN = {
    'open': 'openat',
    'access': 'faccessat',
    'poll': 'ppoll',
    'unlink': 'unlinkat',
    'epoll_wait': 'epoll_pwait',
    'stat': 'newfstatat',
    'lstat': 'newfstatat',
}


def _repo() -> str:
    return os.path.abspath(os.environ.get('KLOAK_REPO', '').strip() or '/')


class SeccompFilterArchComplete(unittest.TestCase):
    service_path: str
    allow_tokens: set[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.service_path = os.path.join(
            _repo(), 'usr', 'lib', 'systemd', 'system', 'kloak.service')
        if not os.path.exists(cls.service_path):
            ## style-ok: allow-skip: kloak source absent (not a --component run)
            raise unittest.SkipTest(
                'kloak.service not found under %s -- set KLOAK_REPO or install '
                'the kloak source' % cls.service_path)

        allow: set[str] = set()
        with open(cls.service_path, encoding='utf-8') as handle:
            for line in handle:
                match = re.match(r'\s*SystemCallFilter=(.*)', line)
                if match is None:
                    continue
                value = match.group(1).strip()
                ## A '~' prefix is a DENY list -- kloak uses an allow list, and
                ## the arch-completeness invariant below is an allow-list claim.
                if value.startswith('~'):
                    raise AssertionError(
                        'kloak.service uses a deny-list SystemCallFilter (%r); '
                        'this test asserts the allow-list invariant and must be '
                        'revisited' % value)
                allow.update(value.split())
        cls.allow_tokens = allow

    def test_is_nonempty_allowlist(self) -> None:
        self.assertTrue(
            self.allow_tokens,
            'no SystemCallFilter allow-list tokens found in %s'
            % self.service_path)

    def test_bare_faccessat_present(self) -> None:
        ## The reported arm64 SIGSYS: access() -> faccessat, which was omitted.
        self.assertIn(
            'faccessat', self.allow_tokens,
            "bare 'faccessat' missing from the allow-list: arm64 glibc access() "
            "emits faccessat (nr 48), so the daemon is killed by seccomp "
            "(SIGSYS/31). 'faccessat2' (nr 439) does NOT cover it.")

    def test_legacy_syscalls_have_arch_neutral_counterpart(self) -> None:
        for legacy, modern in sorted(LEGACY_TO_MODERN.items()):
            if legacy in self.allow_tokens:
                self.assertIn(
                    modern, self.allow_tokens,
                    "allow-list has the x86-only '%s' but not its arch-neutral "
                    "counterpart '%s' (what glibc emits on arm64) -- the daemon "
                    "would die with SIGSYS on arm64" % (legacy, modern))


if __name__ == '__main__':
    unittest.main()
