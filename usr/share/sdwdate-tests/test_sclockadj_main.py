#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for sclockadj's IMPURE main() -- the part compiled OUT of the
CBMC/unit harness by -DSCLOCKADJ_TEST, so previously unverified: the sign
reconstruction for a NEGATIVE nanosecond argument, the full-jump loop, and the
always-executed final partial step.

The real usr/src/sdwdate/sclockadj.c is built WITHOUT SCLOCKADJ_TEST and linked
with sclockadj_main_shim.c under -Wl,--wrap so clock_gettime/clock_settime/sleep
are intercepted (no root, no clock, no waiting). The shim prints the applied
delta per step; the asserts are that the deltas sum to exactly the signed input,
each full step is +-FULL_JUMP, and the final partial step always runs.

gcc is REQUIRED (an absent compiler is an environment bug, FATAL, not a skip);
only a missing subject source skips, matching test_sclockadj_verification.py.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any

HERE = os.path.dirname(os.path.realpath(__file__))
FULL_JUMP = 5000000


def _src_dir() -> str:
    repo = os.environ.get('SDWDATE_REPO', '').strip()
    base = repo if repo else '/'
    return os.path.join(base, 'usr', 'src', 'sdwdate')


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        print('FATAL: %r not found -- declare it in dm-consumer.yml '
              'apt-packages' % tool, file=sys.stderr)
        sys.exit(1)
    return path


class SclockadjMain(unittest.TestCase):
    src_dir: Any
    gcc: Any
    binary: Any
    _workdir: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.src_dir = _src_dir()
        source = os.path.join(cls.src_dir, 'sclockadj.c')
        if not os.path.exists(source):
            ## style-ok: allow-skip: sclockadj source absent (not a --component run)
            raise unittest.SkipTest(
                'sclockadj.c not found under %s -- set SDWDATE_REPO or install '
                'the sdwdate source' % cls.src_dir)
        cls.gcc = _require('gcc')
        cls._workdir = tempfile.mkdtemp(prefix='sclockadj-main.')
        cls.binary = os.path.join(cls._workdir, 'sclockadj_main')
        ## Build main() in (no -DSCLOCKADJ_TEST) and wrap the clock/sleep edges.
        subprocess.run(
            [cls.gcc, '-O2', '-I', cls.src_dir,
             os.path.join(HERE, 'sclockadj_main_shim.c'),
             source, '-o', cls.binary,
             '-Wl,--wrap=clock_gettime,--wrap=clock_settime,--wrap=sleep'],
            check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._workdir, ignore_errors=True)

    def _run(self, arg: str):
        return subprocess.run(
            [self.binary, arg], capture_output=True, text=True)

    def _deltas(self, arg: str):
        result = self._run(arg)
        self.assertEqual(
            result.returncode, 0,
            'sclockadj main exited %s for %r: %s'
            % (result.returncode, arg, result.stderr))
        deltas = [int(line.split()[1])
                  for line in result.stdout.splitlines()
                  if line.startswith('DELTA ')]
        self.assertTrue(deltas, 'no clock change recorded for %r' % arg)
        return deltas

    def test_positive_sum_and_steps(self) -> None:
        ## +5000001 -> one full +FULL_JUMP step, then a +1 remainder step.
        deltas = self._deltas('5000001')
        self.assertEqual(sum(deltas), 5000001)
        self.assertEqual(deltas[-1], 1, 'final partial step wrong')
        for step in deltas[:-1]:
            self.assertEqual(step, FULL_JUMP, 'full step not +FULL_JUMP')

    def test_negative_sign_reconstruction(self) -> None:
        ## -5000001 -> the magnitude is split unsigned then re-signed: a
        ## -FULL_JUMP full step and a -1 remainder step.
        deltas = self._deltas('-5000001')
        self.assertEqual(sum(deltas), -5000001)
        self.assertEqual(deltas[-1], -1, 'final partial step wrong sign')
        for step in deltas[:-1]:
            self.assertEqual(step, -FULL_JUMP, 'full step not -FULL_JUMP')

    def test_final_partial_step_always_runs_on_exact_multiple(self) -> None:
        ## An exact multiple of FULL_JUMP still does one final (zero) step.
        deltas = self._deltas(str(FULL_JUMP))
        self.assertEqual(sum(deltas), FULL_JUMP)
        self.assertEqual(deltas[-1], 0, 'final partial step did not run')

    def test_too_few_args_fails(self) -> None:
        result = subprocess.run([self.binary], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Too few args', result.stderr)

    def test_too_many_args_fails(self) -> None:
        result = subprocess.run(
            [self.binary, '1', '2'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Too many args', result.stderr)

    def test_unparseable_arg_fails(self) -> None:
        result = self._run('not-a-number')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Failed to parse', result.stderr)

    def test_zero_arg_rejected(self) -> None:
        result = self._run('0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nothing to do', result.stderr)


if __name__ == '__main__':
    unittest.main()
