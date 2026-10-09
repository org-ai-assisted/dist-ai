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

    def run_to_end(self, body: str) -> str:
        """Run `body` after sourcing; assert the shell reached the line after
        it and exited 0. For leak probes, where reaching the end IS the
        assertion (a leaked errexit/nounset aborts before it)."""
        result = self.run_sourced(body + '\nprintf "%s\\n" "' + DONE + '"')
        detail = 'stdout:\n%s\nstderr:\n%s' % (result.stdout, result.stderr)
        self.assertEqual(result.returncode, 0, detail)
        self.assertIn(DONE, result.stdout, detail)
        return result.stdout

    def assert_predicate(self, predicate: str) -> None:
        """Run ONE predicate command after sourcing and assert its own exit
        status is 0. The status is captured before anything else runs, so a
        trailing command cannot mask a false predicate."""
        result = self.run_sourced(
            predicate + '\nrc="$?"\nprintf "%s %s\\n" "' + DONE + '" "${rc}"')
        detail = 'stdout:\n%s\nstderr:\n%s' % (result.stdout, result.stderr)
        self.assertIn(DONE + ' 0', result.stdout, detail)

    def test_sourcing_is_silent(self) -> None:
        result = self.run_sourced('')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def test_main_is_defined(self) -> None:
        self.assert_predicate('declare -F main >/dev/null')

    def test_main_is_not_run(self) -> None:
        self.assertNotIn('### START', self.run_to_end(''))

    def test_no_errexit_leak(self) -> None:
        self.run_to_end('false')

    def test_no_nounset_leak(self) -> None:
        self.run_to_end(
            'unset source_contract_unset\n'
            'true "${source_contract_unset}"'
        )

    def test_no_pipefail_leak(self) -> None:
        self.assert_predicate('! shopt -o -q pipefail')

    def test_no_traps_installed(self) -> None:
        self.assert_predicate('[ -z "$(trap -p EXIT ERR)" ]')


if __name__ == '__main__':
    unittest.main()
