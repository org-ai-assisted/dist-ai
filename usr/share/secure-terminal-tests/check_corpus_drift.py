#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Check the git-diffs-lie fixtures vendored into test_corpus.py against the real
upstream corpus.

test_corpus.py cannot reach the corpus repo (CI checks out only the code under
test and dist-ai), so the content/* fixtures are inlined. An inline copy that
silently diverges is worse than no copy: it still passes, while testing bytes
nobody chose. This compares each vendored fixture against the bytes on its
upstream branch and fails on a mismatch, a missing fixture, or a NEW content/*
branch that has not been vendored.

Scope is the content/* class. Upstream path/*, type/* and refname branches are
git-METADATA attacks on a diff viewer, not byte-stream attacks on a terminal, so
they are deliberately not vendored; they are ignored here rather than reported as
drift.

Fails closed: a missing checkout is an error, not a skip, unless --allow-missing
is given explicitly.

    check_corpus_drift.py [--git-diffs-lie DIR] [--allow-missing]
"""

import argparse
import importlib.util
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _vendored_fixtures():
    """Pull git_diffs_lie_fixtures() out of test_corpus.py without executing it.

    Importing the module would run its whole assertion suite (and needs
    secure_terminal); only the one function is wanted here.
    """
    path = os.path.join(_HERE, 'test_corpus.py')
    with open(path, encoding='utf-8') as handle:
        source = handle.read()
    marker = 'def git_diffs_lie_fixtures'
    start = source.index(marker)
    end = source.index('\n# ---', start)
    namespace = {}
    exec(compile(source[start:end], path, 'exec'), namespace)   # noqa: S102
    return namespace['git_diffs_lie_fixtures']()


def _git(repo, *args):
    return subprocess.run(('git', '-C', repo) + args,
                          capture_output=True, check=False)


def _content_branches(repo):
    out = _git(repo, 'branch', '-a', '--format=%(refname:short)').stdout
    names = out.decode('utf-8', 'replace').split()
    branches = {}
    for ref in names:
        short = ref.split('origin/', 1)[1] if ref.startswith('origin/') else ref
        if short.startswith('content/'):
            # prefer the remote-tracking ref when both exist
            branches.setdefault(short.split('/', 1)[1], ref)
            if ref.startswith('origin/'):
                branches[short.split('/', 1)[1]] = ref
    return branches


def _branch_payload(repo, ref):
    """The bytes of the single file the payload branch carries."""
    stat = _git(repo, 'show', '--stat', '--format=', ref).stdout
    lines = [ln for ln in stat.decode('utf-8', 'replace').splitlines() if '|' in ln]
    if not lines:
        return None, None
    path = lines[0].split('|')[0].strip()
    blob = _git(repo, 'show', '%s:%s' % (ref, path))
    if blob.returncode != 0:
        return path, None
    return path, blob.stdout


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--git-diffs-lie', default=None,
                        help='git-diffs-lie checkout (or $GIT_DIFFS_LIE_DIR)')
    parser.add_argument('--allow-missing', action='store_true',
                        help='exit 77 instead of failing when the checkout is absent')
    opts = parser.parse_args(argv)

    repo = (opts.git_diffs_lie
            or os.environ.get('GIT_DIFFS_LIE_DIR')
            or os.path.join(os.path.expanduser('~'), 'private-sources', 'git-diffs-lie'))

    if not os.path.isdir(os.path.join(repo, '.git')):
        if opts.allow_missing:
            sys.stderr.write('check-corpus-drift: SKIP (no git-diffs-lie checkout '
                             'at %s)\n' % repo)
            return 77
        sys.stderr.write('check-corpus-drift: FAIL no git-diffs-lie checkout at %s '
                         '(pass --git-diffs-lie DIR, or --allow-missing to skip)\n'
                         % repo)
        return 1

    vendored = _vendored_fixtures()
    branches = _content_branches(repo)
    if not branches:
        sys.stderr.write('check-corpus-drift: FAIL no content/* branches in %s; a '
                         'shallow or single-branch clone cannot verify drift\n' % repo)
        return 1

    failures = 0
    for name in sorted(branches):
        path, data = _branch_payload(repo, branches[name])
        if data is None:
            sys.stderr.write('FAIL: %s: cannot read payload (%s)\n' % (name, path))
            failures += 1
            continue
        if name not in vendored:
            sys.stderr.write('FAIL: %s: NEW upstream content/* fixture (%s, %d bytes) '
                             'not vendored in test_corpus.py\n'
                             % (name, path, len(data)))
            failures += 1
            continue
        if vendored[name] != data:
            sys.stderr.write('FAIL: %s: vendored %d bytes != upstream %d bytes (%s)\n'
                             % (name, len(vendored[name]), len(data), path))
            failures += 1
            continue
        print('ok   %-24s %d bytes' % (name, len(data)))

    for name in sorted(set(vendored) - set(branches)):
        sys.stderr.write('FAIL: %s: vendored but has no upstream content/* branch\n'
                         % name)
        failures += 1

    print('check-corpus-drift: %d fixture(s) checked, %d drifted'
          % (len(branches), failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
