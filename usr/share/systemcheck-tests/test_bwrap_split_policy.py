#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Pins the bwrap skip policy of the systemcheck-tests-bwrap sub-suite:

  * run with an UNUSABLE bwrap, the sub-suite is FATAL (exit 1) unless
    DIST_AI_SKIP_AUTHORIZED=1, and then env-unmet (exit 78) -- never a silent
    green with every isolated scenario skipped;
  * no bwrap-dependent case remains in this strict parent suite, whose skips CI
    does not authorize.

Runs the REAL sub-suite; only bwrap itself is replaced, by a PATH stub that
fails the way bwrap does without unprivileged user namespaces. Lives in the
parent suite so it runs where bwrap is unusable too (GitHub runners).
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

## A parent case using any of these needs a working bwrap sandbox.
BWRAP_USE = re.compile(
    r"run_check_scenario_isolated\(|bwrap_available\(|LogCheckerHardeningBase|'bwrap'")


def _sub_suite_runner() -> str:
    checkout = os.path.join(HERE, '..', '..', 'bin', 'systemcheck-tests-bwrap')
    if os.path.isfile(checkout):
        return checkout
    return '/usr/bin/systemcheck-tests-bwrap'


class TestBwrapSplitPolicy(unittest.TestCase):
    stub_dir: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.stub_dir = tempfile.mkdtemp()
        stub = os.path.join(cls.stub_dir, 'bwrap')
        with open(stub, 'w', encoding='utf-8') as handle:
            handle.write('#!/bin/sh\n'
                         'echo "bwrap: No permissions to create new namespace" >&2\n'
                         'exit 1\n')
        os.chmod(stub, 0o755)  # nosec B103

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.stub_dir)

    def _run_sub_suite(self, authorized: bool) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env['PATH'] = self.stub_dir + os.pathsep + env['PATH']
        env.pop('DIST_AI_SKIP_AUTHORIZED', None)
        if authorized:
            env['DIST_AI_SKIP_AUTHORIZED'] = '1'
        return subprocess.run([_sub_suite_runner()], env=env,
                              capture_output=True, text=True, timeout=300)

    def test_unusable_bwrap_unauthorized_is_fatal(self) -> None:
        proc = self._run_sub_suite(authorized=False)
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        self.assertIn('not authorized', proc.stderr)

    def test_unusable_bwrap_authorized_is_env_unmet(self) -> None:
        proc = self._run_sub_suite(authorized=True)
        self.assertEqual(proc.returncode, 78, proc.stderr[-2000:])

    def test_no_bwrap_case_in_parent_suite(self) -> None:
        strays = []
        for name in sorted(os.listdir(HERE)):
            if (not name.startswith('test_') or not name.endswith('.py')
                    or name == os.path.basename(__file__)):
                continue
            with open(os.path.join(HERE, name), encoding='utf-8') as handle:
                if BWRAP_USE.search(handle.read()):
                    strays.append(name)
        self.assertEqual(strays, [],
                         'bwrap-dependent case(s) in the strict parent suite; '
                         'move them to systemcheck-tests-bwrap')


if __name__ == '__main__':
    unittest.main()
