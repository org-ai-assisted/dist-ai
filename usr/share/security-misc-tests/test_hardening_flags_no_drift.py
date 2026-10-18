#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Anti-drift guard for the C compiler hardening-flag set.

security-misc defines the canonical hardening set once, as the
`gcc_hardening_options` bash array in
usr/libexec/security-misc/compile-emerg-shutdown#security-misc-shared. Other
packages that compile C (sdwdate's sclockadj, bindp) COPY that flag set into
their own Makefiles -- a duplication that drifts silently: if security-misc
adds a hardening flag, a consumer Makefile keeps building WITHOUT it and nobody
notices. This test fails when a consumer lags the canonical set.

Comparison is the artifact-AGNOSTIC CORE: every canonical flag EXCEPT the
executable-only position-independence pair (-fPIE / -pie), because bindp is a
shared library and correctly uses -fPIC / -shared instead. The core (FORTIFY,
stack-protector, stack-clash, cf-protection, zero-call-used-regs,
branch-protection, trivial-auto-var-init, strict-flex-arrays, fno-strict-overflow,
the -W set, RELRO/now/noexecstack/separate-code/nodlopen, ...) must be present in
EVERY consumer.

Cross-package: needs the derivative-maker monorepo (security-misc + the consumers
as sibling packages), i.e. --repo-root. In a standalone single-component checkout
the consumers are absent and the test is an authorized skip.
"""

import os
import re
import unittest

## The compiler flags whose presence depends on the artifact kind (executable
## vs shared library), so they are NOT part of the artifact-agnostic core.
ARTIFACT_LINKAGE = frozenset({'-fPIE', '-pie', '-fPIC', '-shared', '-nostartfiles'})

CANONICAL_REL = ('usr/libexec/security-misc/'
                 'compile-emerg-shutdown#security-misc-shared')

## consumer package name -> its Makefile path (relative to the package dir).
CONSUMERS = {
    'sdwdate': 'usr/src/sdwdate/Makefile',
    'bindp': 'usr/src/bindp/Makefile',
}

_QUOTED_FLAG = re.compile(r"""['"](-[^'"]+)['"]""")
_MAKE_FLAG = re.compile(r'(-[A-Za-z][^\s]*)')


def _security_misc_repo():
    return os.environ.get('SECURITY_MISC_REPO', '').strip()


def _canonical_flags(repo):
    """The gcc_hardening_options tokens from the compile script (both quote
    styles, across the initial array + the arch '+=' blocks)."""
    path = os.path.join(repo, CANONICAL_REL)
    with open(path, encoding='utf-8') as handle:
        lines = handle.read().splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if 'gcc_hardening_options=(' in ln), None)
    if start is None:
        return set()
    ## The array region ends where the compiler is actually invoked.
    end = next((i for i in range(start + 1, len(lines))
                if re.match(r'\s*gcc\b', lines[i])), len(lines))
    flags = set()
    for ln in lines[start:end]:
        flags.update(_QUOTED_FLAG.findall(ln))
    return flags


def _makefile_flags(makefile):
    """The -flags from a Makefile's CFLAGS/LDFLAGS (:= and += lines)."""
    flags = set()
    with open(makefile, encoding='utf-8') as handle:
        for ln in handle:
            if re.match(r'\s*(CFLAGS|LDFLAGS)\s*[:+]?=', ln):
                flags.update(m.rstrip(',') for m in _MAKE_FLAG.findall(ln))
    return flags


def _consumer_makefiles(repo):
    """Resolve present consumer Makefiles from security-misc's sibling packages
    (monorepo mode). Empty in a standalone checkout."""
    pkg_dir = os.path.dirname(repo.rstrip('/'))  ## .../packages/kicksecure
    found = {}
    for name, rel in CONSUMERS.items():
        mk = os.path.join(pkg_dir, name, rel)
        if os.path.exists(mk):
            found[name] = mk
    return found


class HardeningFlagDriftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo = _security_misc_repo()
        if not repo:
            ## style-ok: allow-skip: cross-package check needs SECURITY_MISC_REPO
            raise unittest.SkipTest('SECURITY_MISC_REPO unset')
        if not os.path.exists(os.path.join(repo, CANONICAL_REL)):
            ## style-ok: allow-skip: canonical compile script not in this checkout
            raise unittest.SkipTest('canonical %s not found' % CANONICAL_REL)
        cls.canonical = _canonical_flags(repo)
        cls.consumers = _consumer_makefiles(repo)
        if not cls.consumers:
            ## style-ok: allow-skip: consumers are sibling packages, present only
            ## in a derivative-maker monorepo (--repo-root), not standalone.
            raise unittest.SkipTest(
                'no consumer packages beside security-misc (standalone checkout)')

    def test_canonical_set_is_nonempty(self) -> None:
        self.assertGreater(
            len(self.canonical), 20,
            'parsed too few canonical flags (%d) -- the compile-script array '
            'format likely changed; fix the parser' % len(self.canonical))

    def test_consumers_carry_the_core_hardening_set(self) -> None:
        core = self.canonical - ARTIFACT_LINKAGE
        for name, makefile in self.consumers.items():
            with self.subTest(consumer=name):
                have = _makefile_flags(makefile)
                missing = sorted(core - have)
                self.assertFalse(
                    missing,
                    "%s (%s) has DRIFTED from security-misc's canonical "
                    "hardening set -- missing %r. Re-sync the Makefile CFLAGS "
                    "with gcc_hardening_options." % (name, makefile, missing))


if __name__ == '__main__':
    unittest.main()
