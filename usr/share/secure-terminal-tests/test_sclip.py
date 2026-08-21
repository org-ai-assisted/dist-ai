#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for the sclip clipboard filter (secure_terminal.clipboard) and the
## st-wl-paste / st-wl-copy / st-xclip drop-in wrappers. The filter is driven
## IN-PROCESS (so coverage.py measures it) with stdin/stdout/stderr redirected;
## the wrappers are driven as real subprocesses against STUBBED native tools on
## PATH, so the test is hermetic and needs no real xclip/wl-clipboard.
##
## Source stays pure ASCII: every deceptive fixture is a chr()/\\u escape -- a test
## for a sanitizer must not smuggle raw bidi/homoglyph bytes into the file. No Qt.

import io
import os
import shutil
import subprocess
import sys
import tempfile

try:
    from secure_terminal import clipboard
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: %s\n' % exc)
    sys.exit(1)

_failures = 0


def ok(cond, msg):
    global _failures
    if cond:
        print('ok   %s' % msg)
    else:
        _failures += 1
        print('FAIL: %s' % msg)


def eq(got, want, msg):
    ok(got == want, '%s (got %r, want %r)' % (msg, got, want))


# deceptive fixtures, built from escapes only
ZWSP = '\u200b'      # zero-width space (invisible)
RLO = '\u202e'       # right-to-left override (bidi)
CYR_A = '\u0430'     # Cyrillic a -- a homoglyph posing as ASCII 'a'


def run_filter(argv, data):
    """Drive clipboard.main(argv) in-process with stdin=data and captured out/err."""
    old = (sys.stdin, sys.stdout, sys.stderr)
    sys.stdin = io.TextIOWrapper(io.BytesIO(data))
    out_bytes = io.BytesIO()
    sys.stdout = io.TextIOWrapper(out_bytes)
    err = io.StringIO()
    sys.stderr = err
    try:
        rc = clipboard.main(argv)
        sys.stdout.flush()
        out = out_bytes.getvalue()     # read while the buffer is still open
        errtext = err.getvalue()
    finally:
        sys.stdin, sys.stdout, sys.stderr = old
    return rc, out, errtext


def run():
    payload = ('a' + ZWSP + 'b' + RLO + 'cd' + CYR_A + 'e').encode('utf-8')

    # 1. Default = strictest ASCII strip: invisibles, bidi AND the homoglyph go.
    rc, out, err = run_filter([], payload)
    eq(rc, 0, 'filter: default exit 0')
    eq(out, b'abcde', 'filter: default drops invisible/bidi/homoglyph to ASCII')

    # 2. --unicode keeps the printable homoglyph but still drops invisible/bidi.
    rc, out, _ = run_filter(['--unicode'], payload)
    eq(out, ('abcd' + CYR_A + 'e').encode('utf-8'),
       'filter: --unicode keeps printable non-ASCII, drops invisible/bidi')

    # 3. --summary is MODE-ACCURATE on stderr; stdout is unchanged.
    rc, out, err = run_filter(['--summary'], payload)
    eq(out, b'abcde', 'filter: --summary does not alter stdout')
    ok('removed 1 bidirectional control, 1 invisible character, 1 non-ASCII character'
       in err, 'filter: ASCII-mode summary names every removed class')
    _, _, err = run_filter(['--unicode', '--summary'], payload)
    ok('removed 1 bidirectional control, 1 invisible character' in err
       and 'kept 1 non-ASCII character' in err,
       'filter: unicode-mode summary reports the kept non-ASCII as kept, not removed')

    # 4. summary on clean text: nothing removed.
    _, _, err = run_filter(['--summary'], b'plain ascii\n')
    ok('nothing removed' in err, 'filter: summary on clean text says nothing removed')

    # 5. --help -> usage on stdout, exit 0.
    rc, out, _ = run_filter(['--help'], b'')
    eq(rc, 0, 'filter: --help exit 0')
    ok(b'usage: sclip' in out, 'filter: --help prints usage')

    # 6. unknown option -> exit 2 with a message.
    rc, _, err = run_filter(['--nope'], b'')
    eq(rc, 2, 'filter: unknown option exit 2')
    ok('unknown option: --nope' in err, 'filter: unknown option names the offender')

    # 7. undecodable bytes never crash and never survive the strict strip.
    rc, out, _ = run_filter([], b'a\xff\xfeb')
    eq(rc, 0, 'filter: undecodable input exit 0')
    eq(out, b'ab', 'filter: raw undecodable bytes are dropped')

    # 8. an OSError reading stdin (e.g. stdin is a directory) -> exit 1, clean.
    class _RaisingIn:
        class buffer:
            @staticmethod
            def read():
                raise OSError('Is a directory')
    old = (sys.stdin, sys.stdout, sys.stderr)
    sys.stdin = _RaisingIn()
    sys.stdout = io.TextIOWrapper(io.BytesIO())
    err = io.StringIO()
    sys.stderr = err
    try:
        rc = clipboard.main([])
    finally:
        sys.stdin, sys.stdout, sys.stderr = old
    eq(rc, 1, 'filter: OSError on stdin -> exit 1')
    ok('sclip:' in err.getvalue(), 'filter: OSError is reported cleanly')

    # 9. a downstream pipe closing early (BrokenPipeError) -> exit 1, no traceback.
    class _BrokenOut:
        class buffer:
            @staticmethod
            def write(_data):
                raise BrokenPipeError()
        @staticmethod
        def write(_data):
            pass
    old = (sys.stdin, sys.stdout, sys.stderr)
    sys.stdin = io.TextIOWrapper(io.BytesIO(b'abc'))
    sys.stdout = _BrokenOut()
    sys.stderr = io.StringIO()
    try:
        rc = clipboard.main([])
    finally:
        sys.stdin, sys.stdout, sys.stderr = old
    eq(rc, 1, 'filter: BrokenPipe on stdout -> exit 1')

    _wrapper_tests()

    print('\n%s' % ('PASS' if _failures == 0 else 'FAIL'))
    return 1 if _failures else 0


def _bin_dir():
    """The checkout's usr/bin, a sibling of the package's dist-packages root."""
    pkg = os.path.dirname(os.path.realpath(clipboard.__file__))
    usr = os.path.normpath(os.path.join(pkg, '..', '..', '..', '..'))
    return os.path.join(usr, 'bin')


def _write_stub(path, body):
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write('#!/bin/sh\n' + body + '\n')
    os.chmod(path, 0o700)   # owner-only: executable by this test, not world-readable


def _wrapper_tests():
    bindir = _bin_dir()
    st_wl_paste = os.path.join(bindir, 'st-wl-paste')
    st_wl_copy = os.path.join(bindir, 'st-wl-copy')
    st_xclip = os.path.join(bindir, 'st-xclip')
    for path in (st_wl_paste, st_wl_copy, st_xclip):
        if not os.path.isfile(path):
            ok(False, 'wrapper: %s is present in the checkout' % os.path.basename(path))
            return

    payload = ('x' + ZWSP + 'y' + RLO + 'z' + CYR_A)
    with tempfile.TemporaryDirectory() as stub:
        # payload the wl-paste stub emits; files the copy/xclip stubs capture into
        with open(os.path.join(stub, 'payload'), 'w', encoding='utf-8') as handle:
            handle.write(payload)
        def q(name):
            return '"' + os.path.join(stub, name) + '"'
        # NB: `printf "%s" "$*"` stays LITERAL shell -- do not %-format the body.
        _write_stub(os.path.join(stub, 'wl-paste'),
                    'printf "%s" "$*" > ' + q('paste_args') + '; cat ' + q('payload'))
        _write_stub(os.path.join(stub, 'wl-copy'),
                    'printf "%s" "$*" > ' + q('copy_args') + '; cat > ' + q('copied'))
        _write_stub(os.path.join(stub, 'xclip'),
                    'printf "%s" "$*" > ' + q('xclip_args') + '; cat > ' + q('xclipped'))
        env = dict(os.environ)
        env['PATH'] = stub + os.pathsep + env.get('PATH', '')

        def read(name):
            with open(os.path.join(stub, name), 'rb') as handle:
                return handle.read()

        # st-wl-paste: sanitize on read, forward native args
        out = subprocess.run([st_wl_paste, '--primary'], capture_output=True,
                             env=env).stdout
        eq(out, b'xyz', 'st-wl-paste: sanitizes read output to ASCII')
        eq(read('paste_args'), b'--primary', 'st-wl-paste: forwards native args')
        out = subprocess.run([st_wl_paste], capture_output=True,
                             env=dict(env, SCLIP_MODE='unicode')).stdout
        eq(out, ('xyz' + CYR_A).encode('utf-8'),
           'st-wl-paste: SCLIP_MODE=unicode keeps the printable homoglyph')

        # st-wl-copy: sanitize on write, forward native args
        subprocess.run([st_wl_copy, '--foo'], input=payload.encode('utf-8'),
                       capture_output=True, env=env)
        eq(read('copied'), b'xyz', 'st-wl-copy: sanitizes write input to ASCII')
        eq(read('copy_args'), b'--foo', 'st-wl-copy: forwards native args')

        # st-xclip: sanitize a stdin (-i) write, forward selection flags
        subprocess.run([st_xclip, '-selection', 'clipboard'],
                       input=payload.encode('utf-8'), capture_output=True, env=env)
        eq(read('xclipped'), b'xyz', 'st-xclip: sanitizes a stdin write to ASCII')
        eq(read('xclip_args'), b'-selection clipboard',
           'st-xclip: forwards native selection flags')

        # st-xclip: a READ (-o) passes through UNCHANGED (raw bytes reach xclip).
        # Clear the stale write-case capture first so this asserts the -o run, not
        # leftover content (a missing file then fails loudly rather than silently).
        os.remove(os.path.join(stub, 'xclipped'))
        subprocess.run([st_xclip, '-o'], input=payload.encode('utf-8'),
                       capture_output=True, env=env)
        eq(read('xclipped'), payload.encode('utf-8'),
           'st-xclip: -o read passes stdin through unsanitized (no sclip stage)')

        # fail CLOSED on the native modes the wrapper cannot sanitize (bypass holes)
        r = subprocess.run([st_wl_copy, 'literal text'], input=b'',
                           capture_output=True, env=env)
        eq(r.returncode, 2, 'st-wl-copy: rejects a text operand (would bypass sclip)')
        ok(b'pipe the text' in r.stderr, 'st-wl-copy: reject guides to piping')
        # a value-taking option (--type VALUE) is NOT mistaken for a text operand
        r = subprocess.run([st_wl_copy, '--type', 'text/plain'],
                           input=payload.encode('utf-8'), capture_output=True, env=env)
        eq(r.returncode, 0, 'st-wl-copy: --type VALUE is not treated as a text operand')

        r = subprocess.run([st_wl_paste, '--watch', 'cat'], capture_output=True, env=env)
        eq(r.returncode, 2, 'st-wl-paste: rejects --watch (would bypass sclip)')
        ok(b'watch' in r.stderr, 'st-wl-paste: reject names --watch')

        operand = os.path.join(stub, 'payload')     # an existing file
        r = subprocess.run([st_xclip, '-selection', 'clipboard', operand],
                           input=payload.encode('utf-8'), capture_output=True, env=env)
        eq(r.returncode, 2, 'st-xclip: rejects a file operand on a write (would bypass)')
        ok(b'file operand' in r.stderr, 'st-xclip: reject names the file operand')

    # loud-fail when the native tool is absent: a PATH with the coreutils the
    # wrapper needs (dirname/readlink) but NO wl-paste.
    with tempfile.TemporaryDirectory() as onlybin:
        for tool in ('dirname', 'readlink', 'cat', 'sh', 'bash'):
            src = shutil.which(tool)
            if src:
                os.symlink(src, os.path.join(onlybin, tool))
        bare = subprocess.run([st_wl_paste], capture_output=True,
                              env=dict(os.environ, PATH=onlybin))
    eq(bare.returncode, 127, 'st-wl-paste: exits 127 when wl-paste is absent')
    ok(b'wl-clipboard' in bare.stderr,
       'st-wl-paste: the not-found message names the package')


if __name__ == '__main__':
    sys.exit(run())
