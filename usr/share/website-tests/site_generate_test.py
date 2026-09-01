#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for site-generate's write-safety guards, the concrete bugs an
AI review surfaced:
 - the dirty-work-tree guard failed OPEN when 'git status' itself errored (a
   corrupt index read as "clean" and let a write proceed);
 - writes followed a symlink, so a tracked/planted link could redirect a
   derived artifact write outside the checkout.

Canary intent: each check FAILS against the pre-fix site-generate.

Uses git (real repos in a tempdir) + stdlib. Run directly: ./site_generate_test.py
"""

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_SG = os.path.normpath(os.path.join(_HERE, '..', '..', 'bin', 'site-generate'))


def _load():
    loader = importlib.machinery.SourceFileLoader('site_generate', _SG)
    spec = importlib.util.spec_from_loader('site_generate', loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


sg = _load()
cs = sg._load_check_site()

_INDEX = ('<!doctype html>\n<html lang="en">\n'
          '<link rel="canonical" href="https://example.github.io/">\n')


def _git(root, *args):
    subprocess.run(['git', '-C', root, *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _repo(root):
    _git(root, 'init', '-q')
    _git(root, 'config', 'user.name', 'T')
    _git(root, 'config', 'user.email', 't@example.com')


def _write(path, data):
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(data)


results = []


def check(name, ok, detail=''):
    results.append((name, bool(ok), detail))


def run():
    # 1. dirty guard fails CLOSED when 'git status' cannot run
    with tempfile.TemporaryDirectory() as root:
        _repo(root)
        _write(os.path.join(root, 'index.html'), _INDEX)
        _git(root, 'add', 'index.html')
        _git(root, 'commit', '-qm', 'init')
        with open(os.path.join(root, '.git', 'index'), 'wb') as handle:
            handle.write(b'corrupt')
        raised = False
        try:
            sg._refuse_dirty(root, False)
        except SystemExit:
            raised = True
        check('dirty guard fails closed on git status error', raised)

    # 2. a symlinked output is refused; the outside target is not overwritten
    with tempfile.TemporaryDirectory() as root, \
            tempfile.TemporaryDirectory() as outside:
        _repo(root)
        _write(os.path.join(root, 'index.html'), _INDEX)
        victim = os.path.join(outside, 'victim')
        _write(victim, 'KEEP')
        os.symlink(victim, os.path.join(root, 'sitemap.xml'))
        _git(root, 'add', '-A')
        _git(root, 'commit', '-qm', 'init')
        rc = sg._generate(root, False, cs)
        check('symlink output refused (returns 1)', rc == 1, repr(rc))
        with open(victim, encoding='utf-8') as handle:
            check('symlink victim not overwritten',
                  handle.read() == 'KEEP')

    # 3. _write_if_changed replaces the entry, never writes THROUGH a symlink
    with tempfile.TemporaryDirectory() as root, \
            tempfile.TemporaryDirectory() as outside:
        victim = os.path.join(outside, 'victim')
        _write(victim, 'KEEP')
        link = os.path.join(root, 'robots.txt')
        os.symlink(victim, link)
        sg._write_if_changed(link, 'NEW')
        with open(victim, encoding='utf-8') as handle:
            check('_write_if_changed leaves the symlink target intact',
                  handle.read() == 'KEEP')
        check('_write_if_changed replaced the link with a real file',
              os.path.isfile(link) and not os.path.islink(link))
        with open(link, encoding='utf-8') as handle:
            check('_write_if_changed wrote the new content',
                  handle.read() == 'NEW')

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        status = 'pass' if ok else 'FAIL'
        line = 'site_generate_test: %s %s' % (status, name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('site_generate_test: %d pass, %d fail, 0 skip\n'
                     % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
