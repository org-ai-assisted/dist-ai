#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Source hygiene: the shipped wizard module must stay pure ASCII (R-001).
"""

import unittest

import swd_testlib as T


class SourceHygieneTestCase(unittest.TestCase):
    def test_module_is_ascii(self):
        source_path = T.swd.__file__
        with open(source_path, "rb") as handle:
            data = handle.read()
        try:
            data.decode("ascii")
        except UnicodeDecodeError as exc:  # pragma: no cover
            self.fail(f"{source_path} contains non-ASCII bytes: {exc}")


if __name__ == "__main__":
    unittest.main()
