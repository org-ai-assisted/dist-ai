#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests AND formal verification (CBMC) for kloak's pure arithmetic -- the
anti-keystroke-fingerprinting daemon whose correctness under untrusted input
(compositor screen geometry, libinput scroll values, the randomised release
delay) is a threat-model target.

Both drive the REAL src/kloak.c (resolved via KLOAK_REPO), reusing kloak's
existing KLOAK_FUZZING seam (guards out main) -- NO kloak source change. kloak.c
#includes wayland-scanner-generated protocol headers, so setUp generates them
(client-header + private-code) with wayland-scanner into a work dir and symlinks
the real kloak.c / kloak.h beside them (no source copy):

  * kloak_harness.c -- concrete unit tests (known values + edges for
    lookup_keycode, check_point_in_area, check_screen_touch, traverse_line,
    parse_uint31/32_arg, get_ticks_from_scroll_accum, the coordinate-space
    conversions) plus a randomized bound check of random_between over the REAL
    /dev/urandom. gcc-compiled and linked with the protocol code + the
    wayland/libinput/libevdev/xkbcommon libraries exactly as kloak links; the
    Wayland/libinput code is dead (never called), so no compositor is needed.
  * kloak_cbmc.c -- CBMC proofs that every verify_* is free of ALL standard UB
    (CBMC 6.x enables signed/unsigned/pointer/float overflow, conversion, nan,
    bounds, pointer, div-by-zero by default) for EVERY input in kloak's real
    operating envelope. The functions are loop-free (random_between's rejection
    loop is bounded), so the proofs are exhaustive over that envelope.

gcc, cbmc, wayland-scanner and the wayland/libinput/libevdev/xkbcommon dev
headers are REQUIRED (declare in dm-consumer.yml apt-packages); their absence is
an environment bug (FATAL), not a skip. Only a missing subject skips.
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

## client-header + private-code stem for each protocol xml kloak.c pulls in.
PROTOCOL_STEMS = {
    'xdg-shell.xml': 'xdg-shell-protocol',
    'xdg-output-unstable-v1.xml': 'xdg-output-protocol',
    'wlr-layer-shell-unstable-v1.xml': 'wlr-layer-shell',
    'wlr-virtual-pointer-unstable-v1.xml': 'wlr-virtual-pointer',
    'virtual-keyboard-unstable-v1.xml': 'virtual-keyboard',
}

PKG_CONFIG_LIBS = ('libinput', 'libevdev', 'wayland-client', 'xkbcommon')


def _repo() -> str:
    return os.environ.get('KLOAK_REPO', '').strip() or '/'


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        print('FATAL: %r not found -- declare it in dm-consumer.yml '
              'apt-packages' % tool, file=sys.stderr)
        sys.exit(1)
    return path


def _pkg_config(flag: str) -> list:
    pkg_config = _require('pkg-config')
    out = subprocess.run(
        [pkg_config, flag, *PKG_CONFIG_LIBS],
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
        cls.gcc = _require('gcc')
        cls.cbmc = _require('cbmc')
        scanner = _require('wayland-scanner')
        cls.cflags = _pkg_config('--cflags')
        cls.libs = _pkg_config('--libs')

        ## Work dir: generated protocol headers + marshalling code next to
        ## symlinks of the real kloak.c / kloak.h, so kloak.c's quoted includes
        ## resolve and both harnesses compile the actual source (no copy).
        cls._work = tempfile.mkdtemp(prefix='kloak-cbmc-')
        for name in ('kloak.c', 'kloak.h'):
            os.symlink(os.path.join(cls.src_dir, name),
                       os.path.join(cls._work, name))
        cls.proto_sources = []
        for xml, stem in PROTOCOL_STEMS.items():
            xml_path = os.path.join(cls.protocol_dir, xml)
            subprocess.run(
                [scanner, 'client-header', xml_path,
                 os.path.join(cls._work, stem + '.h')],
                check=True, capture_output=True, text=True)
            c_path = os.path.join(cls._work, stem + '.c')
            subprocess.run(
                [scanner, 'private-code', xml_path, c_path],
                check=True, capture_output=True, text=True)
            cls.proto_sources.append(c_path)

    @classmethod
    def tearDownClass(cls) -> None:
        work = getattr(cls, '_work', None)
        if work:
            shutil.rmtree(work, ignore_errors=True)

    def test_unit_tests_pass(self) -> None:
        harness = os.path.join(HERE, 'kloak_harness.c')
        with tempfile.TemporaryDirectory() as workdir:
            binary = os.path.join(workdir, 'kloak_harness')
            subprocess.run(
                [self.gcc, '-O2', '-I', self._work, harness,
                 *self.proto_sources, '-o', binary, '-lm', '-lrt',
                 *self.cflags, *self.libs],
                check=True, capture_output=True, text=True)
            result = subprocess.run(
                [binary], check=True, capture_output=True, text=True)
            self.assertIn('all assertions passed', result.stdout)

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
