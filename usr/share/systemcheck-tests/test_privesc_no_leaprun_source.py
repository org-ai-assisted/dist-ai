#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test: check_privilege_escalation_tool.bsh must NOT source
use_leaprun.sh.

use_leaprun.sh runs a privleap-usability probe at source time. systemcheck
sources check_privilege_escalation_tool.bsh during load (before its header), so
sourcing use_leaprun.sh there made the probe's "Cannot use privleap" warning the
very first line of systemcheck output during the boot race. systemcheck never
uses the ${use_leaprun} variable (it calls leaprun directly and reports privleap
health via check_privilege_escalation_tools), so the source was pure noise and
was removed.

Invariant: after sourcing the fragment, ${use_leaprun} is UNSET. This holds
regardless of privleap's runtime state -- if the fragment sourced use_leaprun.sh
the probe would define the variable either way. Also asserts nothing about
privleap reaches stdout at source time.
"""

import os
import subprocess
import sys
import unittest

from systemcheck_testlib import SystemcheckTestBase


class TestNoGratuitousLeaprunSource(SystemcheckTestBase):
    fragment: str
    helper_scripts_path: str

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.fragment = os.path.join(cls.dir, 'check_privilege_escalation_tool.bsh')
        if not os.path.isfile(cls.fragment):
            raise unittest.SkipTest(f"fragment not found: {cls.fragment!r}")
        ## The fragment sources use_sudo.sh / use_pkexec.sh via ${HELPER_SCRIPTS_PATH:-}
        ## (empty -> installed /usr/libexec/helper-scripts). Resolve the same base the
        ## fragment will and SKIP if those siblings are absent (matches the suite's
        ## has.bsh cross-repo convention).
        cls.helper_scripts_path = os.environ.get('HELPER_SCRIPTS_PATH', '').strip()
        base = cls.helper_scripts_path or '/'
        use_sudo = os.path.join(base, 'usr/libexec/helper-scripts/use_sudo.sh')
        if not os.path.isfile(use_sudo):
            raise unittest.SkipTest(
                f"use_sudo.sh not found at {use_sudo!r} (set HELPER_SCRIPTS_PATH)")

    def _source_fragment(self):
        script = (
            'source "${FRAGMENT}"\n'
            'printf "USE_LEAPRUN_STATE=%s\\n" "${use_leaprun+SET}"\n'
        )
        env = dict(os.environ)
        env['FRAGMENT'] = self.fragment
        env['HELPER_SCRIPTS_PATH'] = self.helper_scripts_path
        return subprocess.run(
            ['bash', '-c', script],
            capture_output=True, text=True, env=env, timeout=30,
        )

    def test_use_leaprun_unset_after_source(self) -> None:
        proc = self._source_fragment()
        self.assertNotIn(
            'command not found', proc.stderr,
            f"bash error while sourcing fragment: {proc.stderr.strip()!r}")
        state = None
        for line in proc.stdout.splitlines():
            if line.startswith('USE_LEAPRUN_STATE='):
                state = line.split('=', 1)[1]
        self.assertEqual(
            state, '',
            "use_leaprun is set after sourcing check_privilege_escalation_tool.bsh; "
            "the gratuitous 'source use_leaprun.sh' (with its source-time probe) is back")

    def test_no_privleap_warning_on_stdout(self) -> None:
        proc = self._source_fragment()
        self.assertNotIn(
            'Cannot use privleap', proc.stdout,
            "privleap warning reached stdout at fragment source time")


if __name__ == '__main__':
    sys.exit(unittest.main())
