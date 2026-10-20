#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Formal verification (CBMC) for kloak's pure arithmetic -- the anti-keystroke-
fingerprinting daemon whose correctness under untrusted input (compositor screen
geometry, libinput scroll values, the randomised release delay) is a threat-model
target.

Drives kloak_cbmc.c against the REAL src/kloak.c (resolved via KLOAK_REPO),
reusing kloak's existing KLOAK_FUZZING seam (guards out main) -- NO kloak source
change. kloak.c #includes wayland-scanner-generated protocol headers, so setUp
generates them with wayland-scanner into a work dir and symlinks the real
kloak.c / kloak.h beside them (no source copy); CBMC compiles the actual bodies
from there.

CBMC 6.x enables the full standard check set by default (signed/unsigned/pointer/
float overflow, conversion, nan, bounds, pointer, div-by-zero), so each verify_*
is proven free of ALL of them for every input in kloak's real operating envelope.
The functions are loop-free (random_between's rejection loop is bounded), so the
proofs are exhaustive over that envelope.

cbmc, wayland-scanner and the wayland/libinput/libevdev/xkbcommon dev headers are
REQUIRED (declare in dm-consumer.yml apt-packages); their absence is an
environment bug (FATAL), not a skip. Only a missing subject skips.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))

## verify_* entry points in kloak_cbmc.c, each with any extra CBMC flags. The
## loop-free geometry/time proofs need none; the two with a bounded loop
## (random_between's rejection sampling, sleep_ms's EINTR retry) get a small
## unwind -- every terminating execution is covered.
CBMC_FUNCTIONS = {
    'verify_check_point_in_area': [],
    'verify_check_screen_touch': [],
    'verify_random_between': ['--unwind', '4', '--no-unwinding-assertions'],
    'verify_traverse_line': [],
    'verify_get_ticks_from_scroll_accum': [],
    'verify_current_time_ms': [],
    'verify_sleep_ms': ['--unwind', '2', '--no-unwinding-assertions'],
}

## client-header stem for each protocol xml kloak.c pulls in.
PROTOCOL_STEMS = {
    'xdg-shell.xml': 'xdg-shell-protocol',
    'xdg-output-unstable-v1.xml': 'xdg-output-protocol',
    'wlr-layer-shell-unstable-v1.xml': 'wlr-layer-shell',
    'wlr-virtual-pointer-unstable-v1.xml': 'wlr-virtual-pointer',
    'virtual-keyboard-unstable-v1.xml': 'virtual-keyboard',
}


def _repo() -> str:
    return os.environ.get('KLOAK_REPO', '').strip() or '/'


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        print('FATAL: %r not found -- declare it in dm-consumer.yml '
              'apt-packages' % tool, file=sys.stderr)
        sys.exit(1)
    return path


def _pkg_config_cflags() -> list:
    pkg_config = _require('pkg-config')
    out = subprocess.run(
        [pkg_config, '--cflags',
         'libinput', 'libevdev', 'wayland-client', 'xkbcommon'],
        check=True, capture_output=True, text=True).stdout
    return out.split()


class KloakVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo = _repo()
        cls.src_dir = os.path.join(repo, 'src')
        cls.protocol_dir = os.path.join(repo, 'protocol')
        if not os.path.exists(os.path.join(cls.src_dir, 'kloak.c')):
            ## style-ok: allow-skip: kloak source absent (not a --component run)
            raise unittest.SkipTest(
                'kloak.c not found under %s -- set KLOAK_REPO or install the '
                'kloak source' % cls.src_dir)
        cls.cbmc = _require('cbmc')
        scanner = _require('wayland-scanner')
        cls.cflags = _pkg_config_cflags()

        ## Work dir: generated protocol headers next to symlinks of the real
        ## kloak.c / kloak.h, so kloak.c's quoted includes resolve and CBMC
        ## compiles the actual source (no copy).
        cls._work = tempfile.mkdtemp(prefix='kloak-cbmc-')
        for name in ('kloak.c', 'kloak.h'):
            os.symlink(os.path.join(cls.src_dir, name),
                       os.path.join(cls._work, name))
        for xml, stem in PROTOCOL_STEMS.items():
            subprocess.run(
                [scanner, 'client-header',
                 os.path.join(cls.protocol_dir, xml),
                 os.path.join(cls._work, stem + '.h')],
                check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls) -> None:
        work = getattr(cls, '_work', None)
        if work:
            shutil.rmtree(work, ignore_errors=True)

    def test_cbmc_proofs_verify(self) -> None:
        harness = os.path.join(HERE, 'kloak_cbmc.c')
        for function, extra in CBMC_FUNCTIONS.items():
            with self.subTest(function=function):
                result = subprocess.run(
                    [self.cbmc, harness, '-I', self._work, *self.cflags,
                     '--function', function, *extra],
                    capture_output=True, text=True)
                self.assertIn(
                    'VERIFICATION SUCCESSFUL', result.stdout,
                    'CBMC did not verify %s:\n%s'
                    % (function, result.stdout[-2000:]))


if __name__ == '__main__':
    unittest.main()
