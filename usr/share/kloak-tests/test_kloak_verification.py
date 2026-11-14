#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests AND formal verification (CBMC) for kloak's pure arithmetic -- the
anti-keystroke-fingerprinting daemon whose correctness under untrusted input
(compositor screen geometry, libinput scroll values, the randomised release
delay) is a threat-model target.

Both drive the REAL src/kloak.c.in (resolved via KLOAK_REPO), rendered to kloak.c
by the build's own scripts/src-transform, reusing kloak's existing KLOAK_FUZZING
seam (guards out main) -- NO kloak source change. kloak.c #includes
wayland-scanner-generated protocol headers, so setUp generates them (client-header
+ private-code) with wayland-scanner into a work dir, renders kloak.c / kloak.h
there with src-transform, and symlinks the non-templated sources beside them (no
source copy):

  * kloak_harness.c / kloakwl_harness.c -- concrete unit tests (known values +
    edges). The proxy harness covers lookup_keycode, parse_uint_arg at both caps
    (signed-wrap AND strtoul ERANGE rejection), the escape-key parser and its
    malformed-value rejections, register_esc_combo_event (the teardown trigger:
    combo activation, release-underflow clamp, all-combos-held exit), the getopt
    dup-option guard, calc_next_led_state, fill_with_rand_alphabetic's [A-Za-z]
    invariant, the evdev node-name regex, and parse_inotify_events
    (IN_CREATE/IN_DELETE/IN_Q_OVERFLOW). The adapter harness covers
    check_screen_touch, traverse_line, the coordinate-space conversions,
    get_ticks_from_scroll_accum, a randomized bound check of random_between over
    the REAL /dev/urandom, the keymap guards (kb_handle_keymap), and regressions
    pinning the now-fixed cross-overlap and offset-global-space audit bugs.
    gcc-compiled and linked with the protocol code + the
    wayland/libinput/libevdev/xkbcommon libraries exactly as kloak links; no
    compositor is needed (the handlers are driven over a plain fd).
  * kloak_cbmc.c -- CBMC proofs that every verify_* is free of ALL standard UB
    (CBMC 6.x enables signed/unsigned/pointer/float overflow, conversion, nan,
    bounds, pointer, div-by-zero by default) for EVERY input in kloak's real
    operating envelope. The loop-free geometry/time proofs are exhaustive; the
    bounded loops (random_between, sleep_ms, traverse_line) run under --unwind.

gcc, clang, cbmc, wayland-scanner and the wayland/libinput/libevdev/xkbcommon
dev headers are REQUIRED (declare in dm-consumer.yml apt-packages); their absence
is an environment bug (FATAL), not a skip. Only a missing subject skips.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))

## verify_* entry points in kloak_cbmc.c, each with any extra CBMC flags. The
## loop-free geometry/time proofs need none; the ones with a bounded loop
## (random_between's rejection sampling, sleep_ms's EINTR retry, traverse_line's
## Bresenham walk) get a small unwind -- the unwound prefix covers the arithmetic
## of every structurally identical step.
## The geometry scans run to MAX_SCREEN_COUNT (128); --unwind 129 covers them
## fully (exhaustive, not truncated), so no --no-unwinding-assertions there.
## function -> (harness file, extra CBMC flags). The refactor split kloak's
## arithmetic: sleep_ms stays in the libinput proxy (kloak.c -> kloak_cbmc.c);
## the geometry/scroll/time/random functions moved to the Wayland adapter
## (kloakwl.c -> kloakwl_cbmc.c).
CBMC_FUNCTIONS = {
    'verify_sleep_ms': ('kloak_cbmc.c',
                        ['--unwind', '2', '--no-unwinding-assertions']),
    ## fill_with_rand_alphabetic: outer loop over len=4; the inner rejection
    ## loop only reduces modulo bias (the domain is fixed unconditionally after
    ## it), so a prefix unwind is sound -- --no-unwinding-assertions.
    'verify_fill_with_rand_alphabetic': ('kloak_cbmc.c',
                        ['--unwind', '5', '--no-unwinding-assertions']),
    ## parse_inotify_events: the walk consumes >= sizeof(struct inotify_event)
    ## (16) per step over a 64-byte buffer, so <= 4 steps; --unwind 6 covers
    ## every step EXHAUSTIVELY (unwinding assertions ON, no prefix).
    'verify_parse_inotify_events': ('kloak_cbmc.c', ['--unwind', '6']),
    'verify_check_screen_touch': ('kloakwl_cbmc.c', []),
    'verify_abs_coord_to_screen_local_coord': ('kloakwl_cbmc.c',
                                               ['--unwind', '129']),
    'verify_screen_local_coord_to_abs_coord': ('kloakwl_cbmc.c',
                                               ['--unwind', '129']),
    'verify_random_between': ('kloakwl_cbmc.c',
                              ['--unwind', '4', '--no-unwinding-assertions']),
    'verify_traverse_line': ('kloakwl_cbmc.c',
                             ['--unwind', '8', '--no-unwinding-assertions']),
    'verify_get_ticks_from_scroll_accum': ('kloakwl_cbmc.c', []),
    'verify_current_time_ms': ('kloakwl_cbmc.c', []),
    ## draw_block: two nested loops bounded by the 8x8 symbolic layer, so
    ## <= 8 iterations each; --unwind 9 covers them EXHAUSTIVELY (assertions on).
    'verify_draw_block': ('kloakwl_cbmc.c', ['--unwind', '9']),
    ## grow_line_segment: loop-free; full-int32 symbolic inputs, default checks.
    'verify_grow_line_segment': ('kloakwl_cbmc.c', []),
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
    ## Absolute: setUpClass symlinks KLOAK_REPO/src/kloak.c into a tmp work dir,
    ## and a relative target would resolve against the symlink's dir (not cwd)
    ## and break the compile.
    return os.path.abspath(os.environ.get('KLOAK_REPO', '').strip() or '/')


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        print('FATAL: %r not found -- declare it in dm-consumer.yml '
              'apt-packages' % tool, file=sys.stderr)
        sys.exit(1)
    return path


def _pkg_config(flag: str) -> list[str]:
    pkg_config = _require('pkg-config')
    out = subprocess.run(
        [pkg_config, flag, *PKG_CONFIG_LIBS],
        check=True, capture_output=True, text=True).stdout
    return out.split()


class KloakVerification(unittest.TestCase):
    ## Set in setUpClass; declared so mypy sees them as class attributes.
    src_dir: str
    protocol_dir: str
    gcc: str
    clang: str
    cbmc: str
    cflags: list[str]
    libs: list[str]
    _work: str
    proto_sources: list[str]

    @classmethod
    def setUpClass(cls) -> None:
        repo = _repo()
        cls.src_dir = os.path.join(repo, 'src')
        cls.protocol_dir = os.path.join(repo, 'protocol')
        if not os.path.exists(os.path.join(cls.src_dir, 'kloak.c.in')):
            ## style-ok: allow-skip: kloak source absent (not a --component run)
            raise unittest.SkipTest(
                'kloak.c.in not found under %s -- set KLOAK_REPO or install the '
                'kloak source' % cls.src_dir)
        cls.gcc = _require('gcc')
        cls.clang = _require('clang')
        cls.cbmc = _require('cbmc')
        scanner = _require('wayland-scanner')
        cls.cflags = _pkg_config('--cflags')
        cls.libs = _pkg_config('--libs')

        ## Work dir: generated protocol headers + marshalling code, plus kloak.c
        ## / kloak.h rendered from their .in templates, next to symlinks of the
        ## non-templated sources, so kloak.c's quoted includes resolve and both
        ## harnesses compile the actual generated source (no copy of the subject).
        cls._work = tempfile.mkdtemp(prefix='kloak-cbmc-')
        for name in ('kloakwl.c', 'kloakwl.h', 'kloak-shared.h'):
            os.symlink(os.path.join(cls.src_dir, name),
                       os.path.join(cls._work, name))
        ## Render kloak.c (from kloak.c.in) and kloak.h (from kloak.h.in) with
        ## the build's OWN scripts/src-transform -- the real generator, not a
        ## reimplementation of its substitutions. It writes <template-without-.in>
        ## beside the template, so copy each .in into the work dir and transform
        ## it there: the generated kloak.c / kloak.h land in the work dir without
        ## writing into the (possibly shared) checkout. kloak.h.in bakes in a
        ## <bindir>/kloakwl path; the harnesses never exec kloakwl, so any valid
        ## bindir works.
        transform = os.path.join(repo, 'scripts', 'src-transform')
        if not os.access(transform, os.X_OK):
            print('FATAL: %r missing or not executable -- kloak restructured its '
                  'build without it?' % transform, file=sys.stderr)
            sys.exit(1)
        for template, args in (('kloak.c.in', []), ('kloak.h.in', ['/usr/bin'])):
            staged = os.path.join(cls._work, template)
            shutil.copyfile(os.path.join(cls.src_dir, template), staged)
            subprocess.run([transform, staged, *args],
                           check=True, capture_output=True, text=True)
            os.unlink(staged)
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
        ## Two harnesses: the libinput proxy (kloak.c) and the Wayland adapter
        ## (kloakwl.c). Both link the protocol code + wayland/libinput/xkbcommon;
        ## kloakwl additionally needs libcap. The extra libs are harmless to the
        ## harness that does not use them.
        for harness_name in ('kloak_harness.c', 'kloakwl_harness.c'):
            with self.subTest(harness=harness_name):
                harness = os.path.join(HERE, harness_name)
                with tempfile.TemporaryDirectory() as workdir:
                    binary = os.path.join(workdir, 'harness')
                    subprocess.run(
                        [self.gcc, '-O2', '-I', self._work, harness,
                         *self.proto_sources, '-o', binary, '-lm', '-lrt',
                         *self.cflags, *self.libs, '-lcap'],
                        check=True, capture_output=True, text=True)
                    result = subprocess.run(
                        [binary], check=True, capture_output=True, text=True)
                    self.assertIn('all assertions passed', result.stdout)

    def test_make_build_warning_clean(self) -> None:
        ## The harness compiles above use plain gcc -O2 and so MISS the shipped
        ## Makefile's -Werror set (WARN_CFLAGS: -Wconversion/-Wformat=2/
        ## -Wtype-limits/...). Drive the REAL Makefile in the checkout (no copy --
        ## KLOAK_REPO is a throwaway CI / ephemeral sandbox tree) so a -Werror
        ## regression fails in this suite, not only in a downstream package
        ## build. `make clean` restores the tree whether the build passes or
        ## fails (it removes the binaries + the wayland-scanner-generated
        ## protocol sources). Native arch only -- a 32-bit (i386/armhf)
        ## format/conversion check needs a cross/multilib toolchain not assumed
        ## present.
        make = _require('make')
        repo = _repo()
        self.addCleanup(subprocess.run, [make, '-C', repo, 'clean'],
                        capture_output=True, text=True, check=True)
        subprocess.run([make, '-C', repo, 'clean'], capture_output=True,
                       text=True, check=True)
        result = subprocess.run(
            [make, '-C', repo], capture_output=True, text=True)
        self.assertEqual(
            result.returncode, 0,
            'make failed (WARN_CFLAGS is -Werror):\n%s' % result.stderr[-3000:])

    def test_unsigned_char_portability(self) -> None:
        ## char's signedness is implementation-defined: signed on x86, UNSIGNED
        ## on arm64. fill_with_rand_alphabetic (kloak-shared.h) normalizes a
        ## random byte in the signed [-128, 127] domain (abs() to fold the
        ## negative half, SCHAR_MIN/SCHAR_MAX bounds), so a plain-char version
        ## both miscompiles the modulo-bias math on arm64 AND trips the Makefile's
        ## -Werror on -Wabsolute-value (abs() of an unsigned value is a no-op).
        ## Reproduce arm64's char signedness on this host by appending
        ## -funsigned-char to the REAL Makefile build (env CFLAGS is appended
        ## last, after WARN_CFLAGS's -Werror, per the Makefile's CFLAGS :=); the
        ## build must stay clean. Regression guard for the arm64 cross-compile
        ## break; RED on the pre-fix plain-char source.
        ##
        ## Keep the Makefile's own default optimization (-O2 -g): a bare
        ## CFLAGS=-funsigned-char would drop -O2, and at -O0 GCC's value-range
        ## propagation no longer suppresses provably-safe narrowing conversions,
        ## producing -Wsign-conversion false positives unrelated to char
        ## signedness (e.g. an ssize_t->size_t calloc arg). The real arm64
        ## package build runs at -O2, so match it.
        make = _require('make')
        repo = _repo()
        self.addCleanup(subprocess.run, [make, '-C', repo, 'clean'],
                        capture_output=True, text=True, check=True)
        subprocess.run([make, '-C', repo, 'clean'], capture_output=True,
                       text=True, check=True)
        env = dict(os.environ)
        env['CFLAGS'] = ('%s -O2 -g -funsigned-char'
                         % env.get('CFLAGS', '')).strip()
        result = subprocess.run(
            [make, '-C', repo], capture_output=True, text=True, env=env)
        self.assertEqual(
            result.returncode, 0,
            'make with -funsigned-char failed -- char-signedness portability '
            'bug (breaks the arm64 cross-compile):\n%s' % result.stderr[-3000:])

    def test_cbmc_proofs_verify(self) -> None:
        for function, (cbmc_file, extra) in CBMC_FUNCTIONS.items():
            with self.subTest(function=function):
                harness = os.path.join(HERE, cbmc_file)
                result = subprocess.run(
                    [self.cbmc, harness, '-I', self._work, *self.cflags,
                     '--function', function, *extra],
                    capture_output=True, text=True)
                self.assertIn(
                    'VERIFICATION SUCCESSFUL', result.stdout,
                    'CBMC did not verify %s:\n%s'
                    % (function, result.stdout[-2000:]))

    def test_fuzzer_build_suppresses_signed_overflow(self) -> None:
        ## Production hardens with -ftrapv (signed overflow TRAPS -> kloak
        ## crashes and restarts). The fuzzer must NOT abort on a mere wrap, so
        ## ci/cfuzz-build.sh appends flags that drop the signed-integer-overflow
        ## check (the realistic envelope is overflow-free; the CBMC suite proves
        ## it). Two properties are REQUIRED of the append and both are checked:
        ##   * -fwrapv is present, so signed overflow stays DEFINED (two's-
        ##     complement wrap). Without it the -O1 fuzzer build leaves overflow
        ##     UB and the optimiser deletes overflow-guard branches -- suppressing
        ##     the abort alone (just -fno-sanitize=signed-integer-overflow) must
        ##     NOT satisfy this test.
        ##   * ONLY signed-integer-overflow is dropped: a blanket -fno-sanitize=
        ##     all / =undefined would also blind ASan and the rest of UBSan.
        ## Then the REAL appended flags are driven against clang -- the fuzzer
        ## compiler, which KEEPS an explicitly-listed signed-integer-overflow
        ## under -fwrapv -- in BOTH the -fsanitize=undefined GROUP (local-dev
        ## CFLAGS) and the explicit signed-integer-overflow (OSS-Fuzz base-
        ## builder) form, at the fuzzer's real -O1. A no-append control proves
        ## each base otherwise aborts (so the suppression, not a toothless base,
        ## is what the pass measures).
        build_sh = os.path.join(_repo(), 'ci', 'cfuzz-build.sh')
        if not os.path.exists(build_sh):
            ## style-ok: allow-skip: kloak ci/ absent (not a --component run)
            raise unittest.SkipTest('ci/cfuzz-build.sh not found under KLOAK_REPO')
        with open(build_sh, encoding='utf-8') as handle:
            script = handle.read()
        ## Union EVERY `CFLAGS="${CFLAGS} ..."` append (findall, not just the
        ## first), so splitting the suffix across lines does not capture a
        ## partial set and fail a correct build. Capture is quote-bounded:
        ## indentation or a trailing inline comment cannot leak into the flags.
        appended = [flag
                    for chunk in re.findall(
                        r'^[ \t]*CFLAGS="\$\{CFLAGS\} ([^"]+)"',
                        script, re.MULTILINE)
                    for flag in chunk.split()]
        self.assertTrue(
            appended, 'ci/cfuzz-build.sh no longer appends to the fuzzer CFLAGS')
        self.assertIn(
            '-fwrapv', appended,
            'fuzzer CFLAGS must keep signed overflow DEFINED (-fwrapv); '
            'suppressing the sanitizer abort alone leaves it UB at -O1')
        for blanket in ('-fno-sanitize=all', '-fno-sanitize=undefined'):
            self.assertNotIn(
                blanket, appended,
                '%s disables far more than signed-integer-overflow (ASan and '
                'the rest of UBSan)' % blanket)

        prog = ('#include <limits.h>\n'
                'int main(void) {\n'
                '  volatile int a = INT_MAX;\n'
                '  volatile int b = 1;\n'
                '  volatile int c = a + b;\n'
                '  (void)c;\n'
                '  return 0;\n'
                '}\n')
        ## Both ways the signed-overflow check reaches the fuzzer build, at the
        ## -O1 cfuzz-build.sh compiles with.
        bases = {
            'undefined-group': ['-O1', '-fsanitize=undefined'],
            'explicit-sio': ['-O1', '-fsanitize=signed-integer-overflow'],
        }
        with tempfile.TemporaryDirectory() as workdir:
            src = os.path.join(workdir, 'overflow.c')
            with open(src, 'w', encoding='utf-8') as handle:
                handle.write(prog)

            def run(flags: list[str]) -> int:
                binary = os.path.join(workdir, 'overflow')
                subprocess.run([self.clang, *flags, src, '-o', binary],
                               check=True, capture_output=True, text=True)
                return subprocess.run(
                    [binary], capture_output=True, text=True).returncode

            for name, base in bases.items():
                common = [*base, '-fno-sanitize-recover=all']
                with self.subTest(case='%s/control' % name):
                    self.assertNotEqual(
                        run(common), 0,
                        '%s must abort on signed overflow without the '
                        'suppressor' % name)
                with self.subTest(case='%s/suppressed' % name):
                    self.assertEqual(
                        run([*common, *appended]), 0,
                        "cfuzz-build.sh's appended flags must suppress the "
                        '%s signed-overflow abort under clang' % name)


if __name__ == '__main__':
    unittest.main()
