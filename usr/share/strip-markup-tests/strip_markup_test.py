#!/usr/bin/env python3
"""
Comprehensive test + fuzz for strip-markup: the helper-scripts markup stripper
(the strip_markup package). It removes complete HTML/markup tags and then
neutralizes EVERY residual markup metacharacter -- '<', '>' and '&' all become
'_' -- so that no tag or HTML entity can survive to be interpreted by a
downstream renderer (e.g. Qt's QTextBrowser).

Contract (see strip_markup_lib.py / strip_markup.py):
  - strip_markup(s): a single HTMLParser strip pass (complete tags removed,
    character references decoded to text), then an unconditional pass turning
    every '<', '>' and '&' into '_'. On a parser-internal exception it falls
    back to underscore-sanitizing the ORIGINAL input, so an exception never
    reaches the caller.
  - CLI grammar: strip-markup [--help|-h] [string]; the string comes from the
    argument, or from stdin when no argument is given; more than one positional
    is a usage error (exit 1). Normal runs exit 0.

This suite proves, end to end against the real CLI:

  [G] golden: representative hostile / doubled-tag / entity-encoded inputs map
      to their exact sanitized output.
  [I] invariant: the output NEVER contains '<', '>' or '&' -- the whole point.
  [F] fallback: an input that makes CPython's HTMLParser raise is still
      sanitized (underscored), not propagated as a traceback.
  [C] CLI: the argument path and the stdin path produce identical output;
      a second positional argument is a usage error (exit 1); a CLOSED stdin
      with no argument is a clean empty run (exit 0, no output, no crash);
      empty input is clean.
  [Z] fuzz: random valid-Unicode strings and random byte streams never crash,
      never hang, keep exit in {0,1}, and never leave a '<', '>' or '&' in the
      output.

No root, no network. The tool is resolved from STRIP_MARKUP_REPO (a
helper-scripts checkout, run via the module) else the installed
/usr/bin/strip-markup.

Usage: strip_markup_test.py [--iterations N] [--seed N]
"""

import argparse
import os
import random
import subprocess
import sys
from unittest import mock

REPO = os.environ.get('STRIP_MARKUP_REPO')

## Make the library importable in-process (for the parser-fallback branch, which
## the CLI cannot force): a checkout via STRIP_MARKUP_REPO, else the installed
## dist-packages already on sys.path.
if REPO:
    sys.path.insert(0, os.path.join(REPO, 'usr/lib/python3/dist-packages'))

## Run the installed CLI, or the module out of a checkout.
REPO_CODE = 'import sys; from strip_markup.strip_markup import main; sys.exit(main())'

## Per-invocation wall-clock limit; any input that makes it hang is a failure.
TIMEOUT_SECONDS = 30

## Markup metacharacters that must NEVER survive in the output.
FORBIDDEN = ('<', '>', '&')

failures = 0


def tool_argv(string=None):
    if REPO:
        argv = [sys.executable, '-c', REPO_CODE]
        env_repo = os.path.join(REPO, 'usr/lib/python3/dist-packages')
    else:
        argv = ['/usr/bin/strip-markup']
        env_repo = None
    if string is not None:
        argv.append(string)
    return argv, env_repo


def run(string=None, stdin_bytes=None, close_stdin=False):
    """Run strip-markup; return (exit_code, stdout_bytes)."""
    argv, env_repo = tool_argv(string)
    env = dict(os.environ)
    if env_repo is not None:
        existing = env.get('PYTHONPATH', '')
        env['PYTHONPATH'] = (
            env_repo + os.pathsep + existing if existing else env_repo
        )
    kwargs = {
        'env': env,
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE,
        'timeout': TIMEOUT_SECONDS,
        'check': False,
    }
    if close_stdin:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, **kwargs)
    elif stdin_bytes is not None:
        proc = subprocess.run(argv, input=stdin_bytes, **kwargs)
    else:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, **kwargs)
    return proc.returncode, proc.stdout


def check(label, condition):
    global failures
    if condition:
        print('PASS: ' + label)
    else:
        print('FAIL: ' + label, file=sys.stderr)
        failures += 1


def no_forbidden(data):
    text = data.decode('utf-8', 'surrogateescape')
    return not any(ch in text for ch in FORBIDDEN)


def golden_cases():
    ## (input, expected-output-without-trailing-newline). Verified against the
    ## real sanitizer: complete tags are removed, residual '<'/'>'/'&' -> '_'.
    cases = [
        ('Tom & Jerry <b>rule</b>', 'Tom _ Jerry rule'),
        ('&lt;script&gt;alert(1)&lt;/script&gt;', '_script_alert(1)_/script_'),
        ('<img src=x onerror=alert(1)>', ''),
        ('a < b and c > d', 'a _ b and c _ d'),
        ('<<b>b>Bold!<</b>/b>', '_b_Bold!_/b_'),
        (
            '<<sc<script>script>alert(1)<</sc</script>/script>',
            '_script_alert(1)_/script_',
        ),
        ('plain text', 'plain text'),
        ('', ''),
    ]
    for src, expected in cases:
        rc, out = run(string=src)
        got = out.decode('utf-8', 'surrogateescape').rstrip('\n')
        check(
            'G:arg %r -> %r' % (src, expected),
            rc == 0 and got == expected,
        )
        ## [C] the stdin path must match the argument path.
        rc2, out2 = run(stdin_bytes=src.encode('utf-8'))
        got2 = out2.decode('utf-8', 'surrogateescape').rstrip('\n')
        check('C:stdin==arg %r' % src, rc2 == 0 and got2 == expected)
        ## [I] no metacharacter survives.
        check('I:no-forbidden %r' % src, no_forbidden(out))


def fallback_case():
    ## A bogus declaration must be handled cleanly by the CLI whatever the
    ## installed HTMLParser does with it (older CPython raised on '<![...',
    ## newer versions parse it as a bogus comment): no crash, no metacharacter
    ## left behind.
    rc, out = run(string='<![x] a & b')
    check('F:bogus-declaration handled cleanly', rc == 0 and no_forbidden(out))

    ## The parser-fallback branch itself: force StripMarkupEngine.feed to raise
    ## and assert strip_markup underscore-sanitizes the ORIGINAL input instead
    ## of propagating the exception. This branch cannot be reached from the CLI,
    ## so it is exercised in-process against the library.
    try:
        from strip_markup import strip_markup_lib
    except ImportError:
        check('F:parser-fallback branch (lib import)', False)
        return
    with mock.patch.object(
        strip_markup_lib.StripMarkupEngine,
        'feed',
        side_effect=AssertionError('parser exploded'),
    ):
        result = strip_markup_lib.strip_markup('<b>x & y')
    check(
        'F:parser-fallback underscores the original',
        result == '_b_x _ y',
    )


def cli_cases():
    ## A second positional argument is a usage error (exit 1).
    argv, env_repo = tool_argv()
    env = dict(os.environ)
    if env_repo is not None:
        env['PYTHONPATH'] = env_repo + os.pathsep + env.get('PYTHONPATH', '')
    proc = subprocess.run(
        argv + ['one', 'two'],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    check('C:two-positionals usage error (exit 1)', proc.returncode == 1)

    ## A closed stdin with no argument is a clean empty run (exit 0, no output).
    rc, out = run(close_stdin=True)
    check('C:closed-stdin clean', rc == 0 and out == b'')


def fuzz(iterations, seed):
    rng = random.Random(seed)
    alphabet = "<>&/=\"' abcHTMLtag!-;\t\n" + '\u202e\u200b\U0001f600'
    bad_exit = 0
    leaked = 0
    for _ in range(iterations):
        if rng.random() < 0.5:
            length = rng.randint(0, 200)
            src = ''.join(rng.choice(alphabet) for _ in range(length))
            rc, out = run(stdin_bytes=src.encode('utf-8'))
        else:
            length = rng.randint(0, 200)
            raw = bytes(rng.randint(0, 255) for _ in range(length))
            rc, out = run(stdin_bytes=raw)
        if rc not in (0, 1):
            bad_exit += 1
        if not no_forbidden(out):
            leaked += 1
    check('Z:fuzz exit stayed in {0,1}', bad_exit == 0)
    check('Z:fuzz never leaked a metacharacter', leaked == 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iterations', type=int, default=300)
    parser.add_argument('--seed', type=int, default=1)
    args = parser.parse_args()

    golden_cases()
    fallback_case()
    cli_cases()
    fuzz(args.iterations, args.seed)

    total = 'strip-markup: %d check(s) failed' % failures
    print('=' * 5 + ' ' + total + ' ' + '=' * 5)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
