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
import shutil
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

    # 4. invoked THROUGH A SYMLINK, site-generate must find its CO-LOCATED
    #    check_site (realpath), not the stale /usr/share fallback. Canary: the
    #    pre-fix abspath code keeps the symlink dir, whose ../share is absent, so
    #    it loads a different check_site (or none) and the sentinel output below
    #    never lands. Environment-independent: the assertion is the sentinel
    #    content, so it fails on the old code whether /usr/share is fresh, stale,
    #    or missing.
    with tempfile.TemporaryDirectory() as base:
        pkg_bin = os.path.join(base, 'pkg', 'usr', 'bin')
        pkg_share = os.path.join(base, 'pkg', 'usr', 'share', 'website-tests')
        os.makedirs(pkg_bin)
        os.makedirs(pkg_share)
        shutil.copy(_SG, os.path.join(pkg_bin, 'site-generate'))
        _write(os.path.join(pkg_share, 'check_site.py'),
               'def seo_host(root):\n'
               "    return 'example.github.io'\n"
               'def render_sitemap(root, host):\n'
               "    return 'COLOCATED-SITEMAP\\n'\n"
               'def render_robots(host):\n'
               "    return 'COLOCATED-ROBOTS\\n'\n")
        linkdir = os.path.join(base, 'linkdir')
        os.makedirs(linkdir)
        link = os.path.join(linkdir, 'site-generate')
        os.symlink(os.path.join(pkg_bin, 'site-generate'), link)
        site = os.path.join(base, 'site')
        os.makedirs(site)
        _write(os.path.join(site, 'index.html'), _INDEX)
        proc = subprocess.run([sys.executable, link, '--force', site],
                              capture_output=True, text=True)
        sm_path = os.path.join(site, 'sitemap.xml')
        rb_path = os.path.join(site, 'robots.txt')
        got_sm = open(sm_path).read() if os.path.isfile(sm_path) else None
        got_rb = open(rb_path).read() if os.path.isfile(rb_path) else None
        check('symlink-invoked site-generate uses the co-located check_site',
              proc.returncode == 0 and got_sm == 'COLOCATED-SITEMAP\n'
              and got_rb == 'COLOCATED-ROBOTS\n',
              'rc=%r sitemap=%r robots=%r' % (proc.returncode, got_sm, got_rb))

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
