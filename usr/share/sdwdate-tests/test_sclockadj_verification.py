#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests, fuzz AND formal verification (CBMC) for sdwdate's sclockadj -- the
privileged C clock setter (threat-model high-severity target: memory/format/
bounds correctness of a time setter fed numbers derived from untrusted network
time).

Drives three artefacts against the REAL usr/src/sdwdate/sclockadj.c (resolved
via SDWDATE_REPO), compiling its pure arithmetic with -DSCLOCKADJ_TEST (main and
the clock syscalls excluded):
  * sclockadj_harness.c -- C unit tests (known values, Euclidean/negative edges,
    overflow rejection, LLONG_MIN) + a 2e6-iteration randomized fuzz asserting
    the invariants (tv_nsec in [0,1e9), bounded remainder, no crash).
  * sclockadj_cbmc.c -- CBMC proofs that, for ALL 64-bit inputs (the pure
    functions are loop-free, so this is exhaustive), there is no signed-overflow
    UB and tv_nsec is always normalised to [0,1e9).

gcc and cbmc are REQUIRED (declare in dm-consumer.yml apt-packages); their
absence is an environment bug (FATAL), not a skip. Only a missing subject skips.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))

CBMC_FUNCTIONS = (
    'verify_split_ns_since_epoch',
    'verify_timespec_add_ns',
    'verify_compute_jumps',
)


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


class SclockadjVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.src_dir = _src_dir()
        if not os.path.exists(os.path.join(cls.src_dir, 'sclockadj.c')):
            ## style-ok: allow-skip: sclockadj source absent (not a --component run)
            raise unittest.SkipTest(
                'sclockadj.c not found under %s -- set SDWDATE_REPO or install '
                'the sdwdate source' % cls.src_dir)
        cls.gcc = _require('gcc')
        cls.cbmc = _require('cbmc')

    def test_unit_tests_and_fuzz_pass(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            binary = os.path.join(workdir, 'sclockadj_harness')
            subprocess.run(
                [self.gcc, '-O2', '-I', self.src_dir,
                 os.path.join(HERE, 'sclockadj_harness.c'), '-o', binary],
                check=True, capture_output=True, text=True)
            result = subprocess.run(
                [binary], check=True, capture_output=True, text=True)
            self.assertIn('all assertions passed', result.stdout)

    def test_cbmc_proofs_verify(self) -> None:
        harness = os.path.join(HERE, 'sclockadj_cbmc.c')
        for function in CBMC_FUNCTIONS:
            with self.subTest(function=function):
                result = subprocess.run(
                    [self.cbmc, harness, '-I', self.src_dir,
                     '--function', function,
                     '--signed-overflow-check', '--unsigned-overflow-check',
                     '--conversion-check', '--div-by-zero-check',
                     '--pointer-check', '--bounds-check'],
                    capture_output=True, text=True)
                self.assertIn(
                    'VERIFICATION SUCCESSFUL', result.stdout,
                    'CBMC did not verify %s:\n%s'
                    % (function, result.stdout[-2000:]))


if __name__ == '__main__':
    unittest.main()
