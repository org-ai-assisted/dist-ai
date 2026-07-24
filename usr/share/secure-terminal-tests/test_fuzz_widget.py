#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Deterministic driver for the GUI fuzzer (fuzz_widget.py): run every fuzz phase
against the LIVE SecureTerminal widget with fixed seeds, so the harness is exercised
end to end under coverage and the widget's render / paste / key / mode-switch paths
are fuzzed as part of the gated suite (the heavy randomized runs go through
secure-terminal-tests-fuzz-gui). SKIPs (exit 77) when PyQt6/pyte are absent."""

import os
import sys
import random

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication
    import pyte                                    # noqa: F401 - probe TUI availability
    from secure_terminal.terminal import SecureTerminal   # noqa: F401 - probe import
except Exception as exc:                           # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(fuzz-widget): SKIP (PyQt6/pyte '
                     'unavailable: {0})\n'.format(exc))
    sys.exit(77)

_APP = QApplication.instance() or QApplication(sys.argv)

# fuzz_widget.py sits beside this file; its dir is sys.path[0] when run directly.
import fuzz_widget as F                            # noqa: E402

SEED = 20260724
FAIL = 0


def _fail(message):
    global FAIL
    FAIL += 1
    sys.stderr.write('FAIL: {0}\n'.format(message))


# Every phase, enough iterations to reach each generator/branch of the harness
# (a fast, deterministic smoke -- the heavy randomized run is the fuzz-gui entrypoint).
_rnd = random.Random(SEED)
for _name, _func in F.PHASES:
    try:
        _func(_rnd, 40, SEED)
    except Exception as exc:                       # pylint: disable=broad-except
        _fail('fuzz-widget phase {0}: {1}'.format(_name, exc))

# run() with a single-phase filter and unfiltered (its `only` branch + accumulator).
try:
    _one = F.run(_rnd, 5, SEED, only='feed')
    _all = F.run(_rnd, 3, SEED)
    if _one != ['feed'] or 'keys' not in _all:
        _fail('run() phase filtering returned {0} / {1}'.format(_one, _all))
except Exception as exc:                           # pylint: disable=broad-except
    _fail('fuzz-widget run(): {0}'.format(exc))

# helper edge branches: the cell check on a CLI terminal (no pyte screen -> early
# return) and the assertion helper's failure path.
try:
    F._check_cells_bounded(SecureTerminal(command='/bin/cat'), SEED, 'no-screen')
except Exception as exc:                           # pylint: disable=broad-except
    _fail('_check_cells_bounded on a CLI (screenless) terminal raised: {0}'.format(exc))

try:
    F._assert(False, 'intentional', 0)
except AssertionError:
    pass
else:
    _fail('_assert did not raise on a false condition')

sys.stdout.write('secure-terminal-tests(fuzz-widget): {0} phases driven, {1} failed\n'
                 .format(len(F.PHASES), FAIL))
sys.exit(0 if FAIL == 0 else 1)
