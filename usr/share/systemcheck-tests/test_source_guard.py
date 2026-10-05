#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Silent-green guard for the check_runtime.bsh source.

updatecheck, the systemcheck orchestrator, and canary each source the required
runtime lib check_runtime.bsh (which provides was_executed) at the very top,
BEFORE anything else runs. They carry a '#!/bin/bash -e' shebang, but errexit
from the shebang is NOT applied when a script is invoked as `bash <script>`
(only when executed directly). So the source failure is caught ONLY by an
explicit guard that fails loud when the runtime lib did not load. These tests are
behavioral: they assert the loud-fail CONTRACT, not a specific guard syntax -- any
guard that aborts with the marker satisfies them (whether it checks `source`'s
exit status or the was_executed POSTCONDITION, the `sourceable` skill's current
recommended form).

Without such a guard a failed source would fall through and the script would reach
its end and exit 0 -- a health check falsely reporting success (silent green).

These tests invoke each script as `bash <script>` (shebang -e deliberately NOT
applied, the exact condition the guard must cover) with HELPER_SCRIPTS_PATH
pointed at an empty directory so check_runtime.bsh cannot be found, and assert
the script FAILS LOUD: nonzero exit, the guard's error on stderr, and nothing on
stdout (the guard is the first executable statement, so no check can have run).
"""

import os
import subprocess
import tempfile
import unittest

from systemcheck_testlib import systemcheck_dir

_GUARD_MARKER = 'cannot source check_runtime.bsh'


class TestCheckRuntimeSourceGuard(unittest.TestCase):
    """Each script that sources check_runtime.bsh must exit nonzero (not silent
    green) when that source fails under a `bash <script>` invocation."""

    updatecheck: str
    orchestrator: str
    canary: str
    empty_hs: str
    _tmp: "tempfile.TemporaryDirectory[str]"

    @classmethod
    def setUpClass(cls) -> None:
        sc_dir = systemcheck_dir()
        usr = os.path.dirname(os.path.dirname(sc_dir))
        cls.updatecheck = os.path.join(usr, 'bin', 'updatecheck')
        cls.orchestrator = os.path.join(sc_dir, 'systemcheck')
        cls.canary = os.path.join(sc_dir, 'canary')
        ## systemcheck_dir() already exit-77s when the sources are genuinely
        ## absent; reaching here means they resolved, so all three scripts are
        ## REQUIRED. A missing one is a corrupt checkout / incomplete install --
        ## an environment bug that must fail LOUD, never a silent skip-to-green.
        for path in (cls.updatecheck, cls.orchestrator, cls.canary):
            if not os.path.isfile(path):
                raise FileNotFoundError(
                    f"required systemcheck script absent: {path!r}")
        ## A real but empty directory: ${HELPER_SCRIPTS_PATH}/usr/libexec/
        ## helper-scripts/check_runtime.bsh resolves under it and is absent, so
        ## the source fails deterministically on any host.
        cls._tmp = tempfile.TemporaryDirectory(prefix='no-helper-scripts-')
        cls.empty_hs = cls._tmp.name

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _assert_guard_fails_loud(self, script: str) -> None:
        env = dict(os.environ)
        ## `bash <script>` reads $BASH_ENV first; a startup file there could fake
        ## the marker + exit 1 + empty stdout and make this very anti-silent-green
        ## test pass without the guard running. Strip it so the script's own
        ## guard is the ONLY thing that can satisfy the assertions.
        env.pop('BASH_ENV', None)
        ## Point at the empty dir so check_runtime.bsh cannot be sourced. The
        ## script is run as `bash <script>` so its '#!/bin/bash -e' shebang is
        ## NOT honoured -- only the explicit guard can catch the failure.
        env['HELPER_SCRIPTS_PATH'] = self.empty_hs
        res = subprocess.run(['bash', script], env=env,
                             capture_output=True, text=True, timeout=30)
        self.assertNotEqual(
            res.returncode, 0,
            f"{os.path.basename(script)} exited 0 on an un-sourceable "
            f"check_runtime.bsh (silent green); stderr={res.stderr.strip()!r}")
        self.assertIn(_GUARD_MARKER, res.stderr)
        ## The guard is the first executable statement, so a clean abort emits
        ## nothing on stdout -- proof no health check ran before exiting.
        self.assertEqual(res.stdout.strip(), '')

    def test_updatecheck_guard_fails_loud(self) -> None:
        self._assert_guard_fails_loud(self.updatecheck)

    def test_orchestrator_guard_fails_loud(self) -> None:
        self._assert_guard_fails_loud(self.orchestrator)

    def test_canary_guard_fails_loud(self) -> None:
        self._assert_guard_fails_loud(self.canary)


if __name__ == '__main__':
    unittest.main()
