#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for check_static_deps.py -- the static website-consistency lane's dep preflight.
## Present deps -> rc 0; a genuinely-absent dep -> rc 1 naming the apt package. The absent case is
## reproduced with `python3 -S` (drops dist-packages, i.e. exactly the clean-CI-runner condition
## that let python3-bs4 / python3-html5lib lag the CSP-meta import unnoticed and silently block the
## Pages deploy), so the failing assertion is NON-VACUOUS, not a mock.
##
## Exit: 0 pass | 1 fail.

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUBJECT = os.path.join(HERE, 'check_static_deps.py')


def main():
    if not os.path.isfile(SUBJECT):
        sys.stderr.write('FATAL: subject not found: %s\n' % SUBJECT)
        return 1
    fails = 0

    ## deps present (this interpreter sees dist-packages) -> rc 0
    r = subprocess.run([SUBJECT], capture_output=True, text=True)
    if r.returncode == 0:
        print('PASS: deps present -> rc 0')
    else:
        print('FAIL: deps present but rc=%d (%s)' % (r.returncode, r.stderr.strip()))
        fails += 1

    ## deps absent (-S drops dist-packages) -> rc 1 naming the apt package(s)
    r = subprocess.run([sys.executable, '-S', '-B', '-s', SUBJECT],
                       capture_output=True, text=True)
    if (r.returncode == 1 and 'python3-bs4' in r.stderr
            and 'CI install step must add' in r.stderr):
        print('PASS: absent dep -> rc 1 naming python3-bs4')
    else:
        print('FAIL: absent-dep path rc=%d stderr=%r' % (r.returncode, r.stderr[:160]))
        fails += 1

    print('\ncheck_static_deps_test.py: %d pass, %d fail' % (2 - fails, fails))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
