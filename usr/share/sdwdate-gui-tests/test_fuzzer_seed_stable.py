#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression guard: the fuzzer's per-mode RNG salt must be PROCESS-STABLE so a
--seed replays a run across processes.

The harness previously salted the per-mode RNG with builtins.hash(mode); str
hashing is randomized per process by PYTHONHASHSEED, so the same --seed drew a
different protocol/lifecycle sequence on every run and a found crash could not
be replayed. The fix uses zlib.crc32. This asserts the salt equals the stable
crc32 (never a per-process hash), failing if the hash form is reintroduced.
"""

# pylint: disable=invalid-name,wrong-import-position,import-outside-toplevel

import os
import sys
import unittest
import zlib

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "fuzz"))

import sdwdate_gui_fuzzer as fuzzer


class FuzzerSeedSalt(unittest.TestCase):
    """mode_rng_salt is the stable crc32, not a per-process hash."""

    def test_salt_is_stable_crc32(self) -> None:
        for mode in ("qubes", "nonqubes", "both"):
            with self.subTest(mode=mode):
                self.assertEqual(
                    fuzzer.mode_rng_salt(mode),
                    zlib.crc32(mode.encode("ascii")),
                    "per-mode RNG salt is not the process-stable crc32 "
                    "(a builtins.hash form breaks --seed replay)",
                )

    def test_salt_is_deterministic(self) -> None:
        ## Same input -> same salt within this process (necessary, not
        ## sufficient; the crc32 assertion above pins cross-process stability).
        self.assertEqual(
            fuzzer.mode_rng_salt("qubes"), fuzzer.mode_rng_salt("qubes")
        )


if __name__ == "__main__":
    unittest.main()
