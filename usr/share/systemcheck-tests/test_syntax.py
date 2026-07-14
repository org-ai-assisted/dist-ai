#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Every bash script systemcheck ships must parse under `bash -n`.

This covers the *.bsh fragments AND every other bash script: the main
`systemcheck` entrypoint plus the sibling scripts (canary, check-env,
crypt-check, pkexec-test, ...) that do not end in .bsh. A syntax error in any
of them breaks systemcheck at runtime, so none may be left unchecked.
"""

import subprocess
import unittest

from systemcheck_testlib import SystemcheckTestBase, bash_scripts


class TestSyntax(SystemcheckTestBase):
    def test_bash_n_all_bash_scripts(self) -> None:
        scripts = bash_scripts()
        ## Guard against the collector silently returning nothing (e.g. a walk
        ## that matched no files) and passing vacuously.
        self.assertGreater(
            len(scripts), len(self.files),
            "bash_scripts() must find more than the .bsh fragments "
            "(the entrypoint and sibling scripts); got "
            f"{len(scripts)} vs {len(self.files)} fragments.",
        )
        for path in scripts:
            with self.subTest(path=path):
                result = subprocess.run(
                    ["bash", "-n", "--", path],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    f"bash -n failed for {path}:\n{result.stderr}",
                )


if __name__ == "__main__":
    unittest.main()
