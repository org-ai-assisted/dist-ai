#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
TARGETED mutation-testing lane for secure-terminal's security-critical code:
sanitize.py (the paste sanitizer + the marking-class boundaries) and the
terminal.py paste path. Whole-repo mutation (mutmut / cosmic-ray over the package)
would take far longer than one CI slot and, at the reviewed layout (source in
secure-terminal, tests out-of-tree in dist-ai, a custom runner), is awkward to
wire; this lane instead applies a HAND-PICKED set of high-value mutants -- the ones
a reviewer would most want proven dead -- to a COPY of the real package, runs the
REAL test suite that should catch each, and asserts the mutant is KILLED (some test
fails). Nothing is written back to the source tree.

A mutant is KILLED when its designated real killer suite, which PASSES on the clean
package, FAILS on the mutated package. A SURVIVOR (the killer still passes) is a gap
in the tests and is reported with a triage note -- never silently.

Required mutants (per #31): paste_is_multiline `text[:-1]`->`text`; the paste
auto-submit strip (paste_no_autosubmit / the terminal.py _dispatch_paste call);
sanitize_paste's ASCII bound; and the marking-class boundaries (is_structural,
is_bidi_control). Extend MUTANTS to widen the scoped set.

This lane is TRUSTED TOOLING (it reports whether a mutant died); it must get an
ai-review pass before any CI gate relies on its verdict.

Env: SECURE_TERMINAL_REPO (source checkout); the tests dir is this file's dir.
Exit 0 iff every mutant in the scoped set is killed; 1 on any survivor / error;
77 if the package or a killer suite cannot be located.
"""

import os
import sys
import shutil
import tempfile
import subprocess


def _repo():
    repo = os.environ.get('SECURE_TERMINAL_REPO', '')
    if not repo:
        default = os.path.expanduser(
            '~/private-sources/secure-terminal')
        if os.path.isdir(os.path.join(default, 'usr', 'lib', 'python3',
                                      'dist-packages', 'secure_terminal')):
            repo = default
    pkg = os.path.join(repo, 'usr', 'lib', 'python3', 'dist-packages',
                       'secure_terminal') if repo else ''
    if not repo or not os.path.isdir(pkg):
        sys.stderr.write('mutation_lane: SKIP (secure_terminal not found; set '
                         'SECURE_TERMINAL_REPO)\n')
        sys.exit(77)
    return repo, pkg


REPO, PKG = _repo()
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


# Each mutant: a UNIQUE source substring in one package module, its mutation, and
# the REAL suite(s) that must catch it. `old` must occur EXACTLY once in the file
# (asserted -- a silent no-op mutation would falsely read as an un-killable mutant).
MUTANTS = [
    dict(id='paste_is_multiline: text[:-1] -> text',
         module='sanitize.py',
         old="return '\\n' in text[:-1] or '\\r' in text[:-1]",
         new="return '\\n' in text or '\\r' in text",
         killers=['test_secure_terminal.py'],
         note='a single-line paste with a trailing newline would be mis-held as '
              'multi-line (or, other direction, a hidden CR missed).'),
    dict(id='paste_no_autosubmit: drop the trailing-submit strip',
         module='sanitize.py',
         old="return safe.rstrip('\\r')",
         new="return safe",
         killers=['test_invariants.py'],
         note='a single-line paste would keep its submit CR and AUTO-EXECUTE.'),
    dict(id='sanitize_paste: ASCII bound 0x7E -> 0x7F (admit DEL)',
         module='sanitize.py',
         old='elif ch == \'\\t\' or 0x20 <= cp <= 0x7E:',
         new='elif ch == \'\\t\' or 0x20 <= cp <= 0x7F:',
         killers=['test_corpus.py'],
         note='DEL (0x7F) would ride a paste into the shell.'),
    dict(id='is_structural: upper bound 0x259F -> < 0x259F',
         module='sanitize.py',
         old='return 0x2500 <= cp <= 0x259F and cp not in _ascii_confusables()',
         new='return 0x2500 <= cp < 0x259F and cp not in _ascii_confusables()',
         killers=['test_secure_terminal.py'],
         note='the last block element (U+259F) would misclassify.'),
    dict(id='is_bidi_control: upper bound 0x202E -> < 0x202E',
         module='sanitize.py',
         old='return (0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069',
         new='return (0x202A <= cp < 0x202E or 0x2066 <= cp <= 0x2069',
         killers=['test_secure_terminal.py'],
         note='the RIGHT-TO-LEFT OVERRIDE (U+202E) would no longer be classed bidi.'),
    dict(id='terminal.py _dispatch_paste: drop paste_no_autosubmit()',
         module='terminal.py',
         old='safe = paste_no_autosubmit(safe)',
         new='safe = safe',
         killers=['test_invariants.py'],
         note='the GUI paste path would auto-execute a single-line paste.'),
]


_PKG_REL = os.path.join('usr', 'lib', 'python3', 'dist-packages')


def _run_suite(repo_copy, suite):
    """Run a real test suite against the staged repo copy: its package dir first on
    PYTHONPATH and SECURE_TERMINAL_REPO pointed at the copy root, so the suite's
    sibling-resource resolution (hooklib under usr/share, the fuzz/ harnesses at the
    repo root, walked from the package __file__) stays intact. Returns the exit code.
    A killer PASSES (0) on the clean copy and must FAIL (non-zero, not 77) mutated."""
    env = dict(os.environ)
    env['PYTHONPATH'] = os.path.join(repo_copy, _PKG_REL) \
        + os.pathsep + env.get('PYTHONPATH', '')
    env['SECURE_TERMINAL_REPO'] = repo_copy
    env['QT_QPA_PLATFORM'] = 'offscreen'
    try:
        proc = subprocess.run([sys.executable, '-Bsu',
                               os.path.join(TESTS_DIR, suite)],
                              env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=600,
                              check=False)
    except subprocess.TimeoutExpired as exc:
        # A mutant that hangs the suite (e.g. an unbounded loop) is a KILL, not a lane
        # crash: report a non-zero, non-77 code so the caller counts it as caught.
        out = (exc.stdout or '') + (exc.stderr or '')
        if isinstance(out, bytes):
            out = out.decode('utf-8', 'replace')
        return 124, out + '\n[mutation_lane: suite timed out after 600s]\n'
    return proc.returncode, (proc.stdout + proc.stderr)


def _staged_pkg(mutate=None):
    """Copy the WHOLE repo (minus .git) into a temp dir -- so the package keeps its
    real repo layout -- and (optionally) apply `mutate` = (module, old, new) to the
    copied module. Returns (repo_copy, cleanup). Asserts the mutation is a real edit
    (the anchor occurs exactly once), so a silent no-op never reads as un-killable."""
    root = tempfile.mkdtemp(prefix='st-mut-')
    dst = os.path.join(root, 'secure-terminal')
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns('.git'))
    if mutate is not None:
        module, old, new = mutate
        if new == old:
            # A no-op "mutation" runs the CLEAN package, so its killer passes and the lane
            # would falsely report a SURVIVOR -- the exact false signal the anchor check
            # guards against. Fail loud instead.
            shutil.rmtree(root, ignore_errors=True)
            raise AssertionError('mutation is a no-op (new == old) for %s' % module)
        path = os.path.join(dst, _PKG_REL, 'secure_terminal', module)
        with open(path, encoding='utf-8') as handle:
            src = handle.read()
        count = src.count(old)
        if count != 1:
            shutil.rmtree(root, ignore_errors=True)
            raise AssertionError('mutation anchor %r occurs %d times in %s (want 1)'
                                 % (old, count, module))
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(src.replace(old, new))
    return dst, (lambda: shutil.rmtree(root, ignore_errors=True))


def main():
    # Baseline: every killer suite must PASS on the CLEAN (copied) package, or a
    # "mutant killed" verdict would be meaningless (the suite fails regardless).
    killers = sorted({s for m in MUTANTS for s in m['killers']})
    # A renamed/absent killer suite must SKIP (77, per the docstring contract), not surface
    # later as a misleading baseline FAIL from python3 failing to open the script.
    for suite in killers:
        if not os.path.isfile(os.path.join(TESTS_DIR, suite)):
            sys.stderr.write('mutation_lane: SKIP (killer suite %s not found)\n' % suite)
            sys.exit(77)
    print('== baseline: killer suites on the clean package ==')
    clean_root, clean_cleanup = _staged_pkg()
    baseline_ok = True
    try:
        for suite in killers:
            rc, _out = _run_suite(clean_root, suite)
            print('  %-28s %s (exit %d)'
                  % (suite, 'PASS' if rc == 0 else 'FAIL', rc))
            if rc != 0:
                baseline_ok = False
    finally:
        clean_cleanup()
    if not baseline_ok:
        sys.stderr.write('mutation_lane: a killer suite fails on CLEAN code -- fix '
                         'that first; a mutation verdict would be meaningless.\n')
        return 1

    print('\n== mutants ==')
    killed = 0
    survivors = []
    for mut in MUTANTS:
        root, cleanup = _staged_pkg((mut['module'], mut['old'], mut['new']))
        try:
            caught_by = None
            for suite in mut['killers']:
                rc, _out = _run_suite(root, suite)
                if rc not in (0, 77):
                    caught_by = suite
                    break
            if caught_by:
                killed += 1
                print('  KILLED   %-52s by %s' % (mut['id'], caught_by))
            else:
                survivors.append(mut)
                print('  SURVIVED %-52s -- TRIAGE: %s' % (mut['id'], mut['note']))
        finally:
            cleanup()

    total = len(MUTANTS)
    score = 100.0 * killed / total if total else 100.0
    print('\n== mutation score (scoped set) ==')
    print('  %d/%d mutants killed (%.1f%%)' % (killed, total, score))
    if survivors:
        print('  SURVIVORS (a test gap -- add a killer):')
        for mut in survivors:
            print('    - %s :: %s' % (mut['id'], mut['note']))
    sys.stdout.write('secure-terminal-tests(mutation): %d/%d killed, %d survivor(s)\n'
                     % (killed, total, len(survivors)))
    return 0 if not survivors else 1


if __name__ == '__main__':
    sys.exit(main())
