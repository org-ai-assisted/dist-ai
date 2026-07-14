#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Every systemcheck fragment and entrypoint must parse under `bash -n`."""

import subprocess
import unittest

from systemcheck_testlib import SystemcheckTestBase


class TestSyntax(SystemcheckTestBase):
    def test_bash_n_all_fragments(self) -> None:
        for path in self.files:
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
