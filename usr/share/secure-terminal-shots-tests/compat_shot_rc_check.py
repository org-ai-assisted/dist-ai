#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression helper for compat_shot_test.sh: a compat command that does NOT run
## cleanly must FAIL LOUD, not silently back the compatibility page's "was run and
## verified" claim with a blank/partial shot. run_capture rc-checks the shot command
## (against prog.expect_rc) AND every verify tool a multi-tool row's label claims.
## CANARY: on the pre-fix compat-shot.py run_capture did no rc-check and there was no
## _run_checked at all, so this import/use fails and a missing/failing tool produced a
## shot with exit 0.
##
## Usage: compat_shot_rc_check.py <compat-shot.py path> <writable work dir>

import importlib.util
import os
import sys


def main():
    if len(sys.argv) != 3:
        sys.stderr.write('usage: compat_shot_rc_check.py <gen> <workdir>\n')
        return 2
    gen, work = sys.argv[1], sys.argv[2]
    spec = importlib.util.spec_from_file_location('compat_shot', gen)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    env = dict(os.environ)

    def expect_raise(label, fn):
        try:
            fn()
        except RuntimeError:
            return
        raise SystemExit('FAIL: %s did not raise' % label)

    # a clean command at its expected rc returns output
    assert mod._run_checked('printf hi', work, env, 0) == b'hi', 'clean command lost output'
    # a non-expected exit raises (false -> 1, expected 0)
    expect_raise('_run_checked(false, expect 0)',
                 lambda: mod._run_checked('false', work, env, 0))
    # a MISSING tool (bash -> 127) raises, not a silent blank
    expect_raise('_run_checked(missing tool)',
                 lambda: mod._run_checked('this_tool_does_not_exist_xyz', work, env, 0))
    # run_capture propagates a failing VERIFY tool (a row-claimed tool that did not run)
    bad = mod.Prog('x', 'x', 'printf ok', verify=('false',))
    expect_raise('run_capture(bad verify)', lambda: mod.run_capture(bad, work, env))
    # a Prog whose command exits its DECLARED expect_rc passes (diff-style rc 1)
    assert mod.run_capture(mod.Prog('d', 'd', 'false', expect_rc=1), work, env) == b''
    print('ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
