#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Per-function unit tests for bindp (usr/src/bindp/bindp.c).

Compiles bindp_unit.c, which #includes the REAL bindp.c (resolved via BINDP_REPO)
and calls its parsers/helpers DIRECTLY, then drives one category per subtest so
each function gets exhaustive input coverage the end-to-end behaviour suite and
the CBMC proofs do not drill into: parse_int_flag, get_address_family, and
_init's BIND_PORT / BIND_ADDR / REUSE_* / IP_TRANSPARENT parsing (boundaries,
invalid, empty).

The shipped libindp.so is linked -Wl,-z,nodlopen (LD_PRELOAD only), so ctypes
cannot load it; the harness reaches the functions (including the static ones) by
including the source. gcc is a REQUIRED build tool (FATAL if absent). Only a
missing subject (no bindp.c under BINDP_REPO) skips.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
HARNESS_SRC = os.path.join(HERE, "bindp_unit.c")

CATEGORIES = ("parse_flag", "family", "init_port", "init_addr", "init_flags")


def _bindp_src_dir():
    repo = os.environ.get("BINDP_REPO", "").strip()
    base = repo if repo else "/"
    src_dir = os.path.join(base, "usr/src/bindp")
    return src_dir if os.path.isfile(os.path.join(src_dir, "bindp.c")) else ""


class BindpUnitTest(unittest.TestCase):
    _tmp: str
    _bin: str

    @classmethod
    def setUpClass(cls):
        src_dir = _bindp_src_dir()
        if not src_dir:
            ## style-ok: allow-skip: bindp source absent (not a --component run);
            ## the orchestrator fails an unauthorized skip under --component.
            raise unittest.SkipTest(
                "bindp.c not found (set BINDP_REPO to the bindp checkout)")
        cls._tmp = tempfile.mkdtemp(prefix="bindp-unit.")
        cls.addClassCleanup(shutil.rmtree, cls._tmp, ignore_errors=True)
        ## gcc is a required build tool; a missing one is an environment bug that
        ## must fail loud, so do not guard it with a skip. -I points at the real
        ## bindp.c the harness includes.
        cls._bin = os.path.join(cls._tmp, "bindp_unit")
        subprocess.run(
            ["gcc", "-O2", "-Wall", "-I", src_dir, HARNESS_SRC, "-o", cls._bin],
            check=True, capture_output=True, text=True)

    def test_unit_categories(self):
        for category in CATEGORIES:
            with self.subTest(category=category):
                proc = subprocess.run(
                    [self._bin, category], capture_output=True, text=True)
                self.assertEqual(
                    proc.returncode, 0,
                    msg=(f"{category}: harness reported failures\n"
                         f"--- stdout ---\n{proc.stdout}\n"
                         f"--- stderr ---\n{proc.stderr}"))
                ## Guard against a vacuous pass: the category must have run cases.
                self.assertIn("failures=0", proc.stdout)
                self.assertNotIn("cases=0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
