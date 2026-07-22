#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Gather truthful secure-terminal test / coverage / fuzz metrics as JSON.

Runs each test suite and sums its assertion count, measures line coverage of the
secure_terminal package, counts the fuzz harnesses and the hypothesis property
count, and reads the reflection spec-surface corpus size. Emits one JSON object so
the project's Pages site cites GENERATED, drift-checked figures instead of
hand-maintained ones (honest-claims): re-run it and update the page from the JSON.

Coverage here is REPORTED (a number for the page); it is ENFORCED separately by
`secure-terminal-tests-coverage` (a 100% ratchet gate on the security-critical
modules). This tool computes its own figure so it always yields a number even when
that gate is red.

Resolves the target checkout from SECURE_TERMINAL_REPO (the wrapper sets it and
PYTHONPATH). Run via the `secure-terminal-metrics` wrapper, not directly.

    secure-terminal-metrics [--no-coverage] [--pretty]
"""

import ast
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

# every suite the test runner runs, in the same order
TEST_FILES = ('test_secure_terminal.py', 'test_fuzz.py', 'test_corpus.py',
              'test_cli.py', 'test_modules.py', 'test_review.py',
              'test_mainwin.py', 'test_widget.py')

_PASSED_RE = re.compile(r'(\d+) passed')
_PROPS_RE = re.compile(r'(\d+) properties checked')


def _here():
    return os.path.dirname(os.path.abspath(__file__))


def _run(argv, env=None):
    """Run argv, return (returncode, stdout+stderr)."""
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          env=env, text=True, check=False)
    return proc.returncode, proc.stdout


def _assert_count(output):
    """A suite either prints 'N passed' or one 'ok ' line per assertion; count
    whichever it reports so every suite yields a number."""
    m = _PASSED_RE.search(output)
    if m:
        return int(m.group(1))
    return sum(1 for line in output.splitlines() if line.startswith('ok '))


def suite_counts(tests_dir):
    """Run each suite; return per-file assertion counts + the total. A suite that
    SKIPs (exit 77, e.g. PyQt6 absent) is recorded as skipped, not counted."""
    per = {}
    total = 0
    props = 0
    for name in TEST_FILES:
        path = os.path.join(tests_dir, name)
        if not os.path.isfile(path):
            continue
        rc, out = _run([sys.executable, '-Bsu', path])
        if rc == 77:
            per[name] = {'skipped': True}
            continue
        count = _assert_count(out)
        per[name] = {'assertions': count, 'failed': rc != 0}
        total += count
        pm = _PROPS_RE.search(out)
        if pm:
            props += int(pm.group(1))
    return per, total, props


# the security-critical modules the site reports coverage for individually
_KEY_MODULES = ('sanitize.py', 'terminal.py')


def coverage_stats(tests_dir, repo):
    """Line coverage of the secure_terminal package across the whole suite.
    Runs each suite under coverage.py in parallel mode into a private data file,
    combines, and returns {'whole': pct, 'by_module': {name: pct, ...}} (rounded
    ints) for the whole package plus the security-critical modules, or None on any
    failure."""
    pkg = os.path.join(repo, 'usr', 'lib', 'python3', 'dist-packages')
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env['COVERAGE_FILE'] = os.path.join(tmp, '.coverage')
        env['PYTHONPATH'] = pkg + os.pathsep + env.get('PYTHONPATH', '')
        for name in TEST_FILES:
            path = os.path.join(tests_dir, name)
            if not os.path.isfile(path):
                continue
            # coverage run does not forward python -B/-s interpreter flags
            _run([sys.executable, '-m', 'coverage', 'run', '--parallel-mode',
                  '--source=secure_terminal', path], env=env)
        _run([sys.executable, '-m', 'coverage', 'combine'], env=env)
        report = os.path.join(tmp, 'coverage.json')
        rc, _ = _run([sys.executable, '-m', 'coverage', 'json', '-o', report],
                     env=env)
        if rc != 0 or not os.path.isfile(report):
            return None
        with open(report, encoding='ascii') as handle:
            data = json.load(handle)
        by_module = {}
        for path, info in data.get('files', {}).items():
            base = os.path.basename(path)
            if base in _KEY_MODULES:
                by_module[base] = round(info['summary']['percent_covered'])
        return {'whole': round(data['totals']['percent_covered']),
                'by_module': by_module}


def fuzz_harness_count(repo):
    """The in-tree libFuzzer/atheris harnesses (fuzz/fuzz_*.py)."""
    return len(sorted(glob.glob(os.path.join(repo, 'fuzz', 'fuzz_*.py'))))


def spec_surface_corpus_size(tests_dir):
    """Size of the reflection spec-surface corpus the pages cite. Extract and run
    just the _spec_surface_corpus() function from test_widget.py (which also
    asserts this exact length), so the figure is the real, test-enforced count."""
    path = os.path.join(tests_dir, 'test_widget.py')
    try:
        src = open(path, encoding='ascii').read()
    except OSError:
        return None
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == '_spec_surface_corpus':
            namespace = {}
            module = ast.Module(body=[node], type_ignores=[])
            exec(compile(module, path, 'exec'), namespace)   # noqa: S102
            return len(namespace['_spec_surface_corpus']())
    return None


def main(argv):
    do_coverage = '--no-coverage' not in argv
    pretty = '--pretty' in argv
    tests_dir = _here()
    repo = os.environ.get('SECURE_TERMINAL_REPO', '')
    if not repo:
        sys.stderr.write('metrics: SECURE_TERMINAL_REPO unset (run via the wrapper)\n')
        return 2

    per, total, props = suite_counts(tests_dir)
    metrics = {
        'test_assertions_total': total,
        'test_assertions_by_suite': per,
        'test_suite_files': sum(1 for v in per.values() if not v.get('skipped')),
        'hypothesis_properties': props,
        'fuzz_harnesses': fuzz_harness_count(repo),
        'spec_surface_corpus': spec_surface_corpus_size(tests_dir),
        'line_coverage': coverage_stats(tests_dir, repo) if do_coverage else None,
    }
    sys.stdout.write(json.dumps(metrics, indent=2 if pretty else None,
                                sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
