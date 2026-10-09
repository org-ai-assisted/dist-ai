#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
onion-time-pre-script source-ability contract.

Every other test in this suite sources the real script and calls its
functions. That only isolates the function under test if sourcing defines
functions and does nothing else: no auto-run of main, no strict mode and no
ERR/EXIT trap leaking into the sourcing shell.
"""

import unittest

from onion_time_pre_script_testlib import PreScriptTestBase

DONE = 'source-contract-done'


class TestSourceContract(PreScriptTestBase):
    """Sourcing the real subject must be side-effect free."""

    def assert_body_ok(self, body: str) -> str:
        result = self.run_sourced(body + '\nprintf "%s\\n" "' + DONE + '"')
        self.assertEqual(
            result.returncode,
            0,
            'stdout:\n%s\nstderr:\n%s' % (result.stdout, result.stderr),
        )
        ## Not a vacuous pass: the body must have run to its end.
        self.assertIn(DONE, result.stdout)
        return result.stdout

    def test_sourcing_is_silent(self) -> None:
        result = self.run_sourced('')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_main_is_defined_not_run(self) -> None:
        out = self.assert_body_ok('declare -F main >/dev/null')
        self.assertNotIn('### START', out)

    def test_no_errexit_leak(self) -> None:
        self.assert_body_ok('false')

    def test_no_nounset_leak(self) -> None:
        self.assert_body_ok(
            'unset source_contract_unset\n'
            'true "${source_contract_unset}"'
        )

    def test_no_pipefail_leak(self) -> None:
        self.assert_body_ok('! shopt -o -q pipefail')

    def test_no_traps_installed(self) -> None:
        self.assert_body_ok('[ -z "$(trap -p EXIT ERR)" ]')


if __name__ == '__main__':
    unittest.main()
