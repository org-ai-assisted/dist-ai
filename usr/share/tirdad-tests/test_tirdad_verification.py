#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Formal verification (CBMC) for tirdad -- the kernel livepatch that replaces the
TCP Initial Sequence Number generator to close a CPU-timing side channel
(threat-model: a predictable or fingerprintable ISN defeats the module's whole
purpose).

Drives tirdad_cbmc.c, which #includes the REAL, unmodified module/tirdad.c
behind the shiminc/ kernel-header shim (resolved via TIRDAD_REPO), and asks
CBMC to prove, for ALL inputs (the hook path is loop-free, so this is
exhaustive, not sampled):
  * the tcp_seq_and_ts_off union packs seq into the low 32 bits and ts_off into
    the high 32 bits of the u64 the kernel consumes; and
  * when the kernel has TCP timestamps disabled, the returned timestamp offset
    is zero -- via get_isn_ts and via both exported hooks -- so tirdad never
    re-introduces a fingerprinting surface the kernel switched off;
with no signed/unsigned-overflow, conversion, div-by-zero, pointer or bounds
UB along the way.

cbmc is REQUIRED (declared in dm-consumer.yml apt-packages); its absence is an
environment bug (FATAL), not a skip. Only a missing subject skips.
"""

import glob
import os
import re
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
SHIM_DIR = os.path.join(HERE, 'shiminc')

CBMC_FUNCTIONS = (
    'verify_union_layout',
    'verify_ts_off_zero_when_disabled',
    'verify_hook_v4_ts_off_zero',
    'verify_hook_v6_ts_off_zero',
)

CBMC_CHECKS = (
    '--signed-overflow-check', '--unsigned-overflow-check',
    '--conversion-check', '--div-by-zero-check',
    '--pointer-check', '--bounds-check',
)


def _src_dir() -> str:
    ## Checkout path first (the gating lane: TIRDAD_REPO is the tirdad checkout
    ## root, source at module/tirdad.c). Else the DKMS-installed source tree.
    repo = os.environ.get('TIRDAD_REPO', '').strip()
    if repo:
        return os.path.join(repo, 'module')
    ## Newest DKMS version first: numeric-component order (plain sort would rank
    ## tirdad-0.10 below tirdad-0.9), so CBMC proves the version that will be built.
    def ver_key(path):
        return [int(n) for n in re.findall(r'\d+', os.path.basename(path))]
    for candidate in sorted(glob.glob('/usr/src/tirdad-*'), key=ver_key, reverse=True) \
            + ['/usr/src/tirdad']:
        ## DKMS ships the source under module/ (tirdad-dkms.install:
        ## 'module/* usr/src/tirdad-0.1/module'); the bare candidate is the fallback.
        for source_dir in (os.path.join(candidate, 'module'), candidate):
            if os.path.isfile(os.path.join(source_dir, 'tirdad.c')):
                return source_dir
    return os.path.join(repo if repo else '/', 'module')


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        print('FATAL: %r not found -- declare it in dm-consumer.yml '
              'apt-packages' % tool, file=sys.stderr)
        sys.exit(1)
    return path


class TirdadVerification(unittest.TestCase):
    src_dir: str
    cbmc: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.src_dir = _src_dir()
        if not os.path.exists(os.path.join(cls.src_dir, 'tirdad.c')):
            ## style-ok: allow-skip: tirdad source absent (not a --component run)
            raise unittest.SkipTest(
                'tirdad.c not found under %s -- set TIRDAD_REPO or install the '
                'tirdad source' % cls.src_dir)
        cls.cbmc = _require('cbmc')

    def test_cbmc_proofs_verify(self) -> None:
        harness = os.path.join(HERE, 'tirdad_cbmc.c')
        for function in CBMC_FUNCTIONS:
            with self.subTest(function=function):
                result = subprocess.run(
                    [self.cbmc, harness, '-I', SHIM_DIR, '-I', self.src_dir,
                     '--function', function, *CBMC_CHECKS],
                    capture_output=True, text=True)
                self.assertIn(
                    'VERIFICATION SUCCESSFUL', result.stdout,
                    'CBMC did not verify %s:\n%s'
                    % (function, result.stdout[-2000:]))


if __name__ == '__main__':
    unittest.main()
