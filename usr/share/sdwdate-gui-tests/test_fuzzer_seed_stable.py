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

## Capture the process excepthook BEFORE importing the fuzzer, to prove the
## import does not replace it (see test_import_does_not_install_excepthook).
_EXCEPTHOOK_BEFORE_IMPORT = sys.excepthook

import sdwdate_gui_fuzzer as fuzzer


class FuzzerImportIsSideEffectFree(unittest.TestCase):
    """Importing the fuzzer must not install its process-wide hooks."""

    def test_import_does_not_install_excepthook(self) -> None:
        ## The fuzzer installs its Qt-slot excepthook only from main(), never
        ## at import: an import-time install would replace sys.excepthook for
        ## the whole test process and let a slot exception in any other
        ## discovered test pass silently.
        self.assertIsNot(
            sys.excepthook,
            fuzzer._excepthook,  # pylint: disable=protected-access
            "importing the fuzzer installed its excepthook process-wide",
        )
        self.assertIs(
            sys.excepthook,
            _EXCEPTHOOK_BEFORE_IMPORT,
            "importing the fuzzer changed sys.excepthook",
        )


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

    def test_call_site_uses_the_stable_salt(self) -> None:
        ## Guard the CALL SITE, not just the helper: the helper could stay
        ## crc32 while the per-mode seeding reverted to builtins.hash(mode).
        ## The seeding calls mode_rng_salt(mode) exactly once; a revert removes
        ## that call, so its presence pins the stable salt at the call site.
        with open(fuzzer.__file__, encoding="ascii") as fh:
            source = fh.read()
        self.assertIn(
            "mode_rng_salt(mode)",
            source,
            "per-mode seeding no longer uses the stable mode_rng_salt helper",
        )


if __name__ == "__main__":
    unittest.main()
