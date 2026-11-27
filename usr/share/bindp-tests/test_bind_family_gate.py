#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression guard for bindp's setsockopt option gate (usr/src/bindp/bindp.c).

bindp is an LD_PRELOAD shim that rewrites bind()/connect() to a configured
source address. It also applies SO_REUSEADDR / SO_REUSEPORT / IP_TRANSPARENT
when asked (REUSE_ADDR / REUSE_PORT / IP_TRANSPARENT env). Those options must be
gated to IP sockets, but on the socket's REAL address family -- read from the
descriptor -- not on the caller's sockaddr sa_family.

Linux accepts an AF_UNSPEC sockaddr with INADDR_ANY as a valid IPv4 wildcard
bind. If bindp gates on sa_family, such a bind skips the options, and two IPv4
UDP sockets sharing one wildcard port then fail EADDRINUSE (neither got
SO_REUSEPORT) -- a regression this test pins.

This builds the REAL bindp.c with its shipped Makefile (resolved via BINDP_REPO),
LD_PRELOADs the resulting libindp.so, and drives bind_family_harness.c (a test
fixture, not a subject copy) which performs the two AF_UNSPEC wildcard binds and
reports whether the second succeeds.

gcc and make are REQUIRED build tools; their absence is an environment bug
(FATAL), not a skip. Only a missing subject (no bindp.c under BINDP_REPO) skips.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
HARNESS_SRC = os.path.join(HERE, "bind_family_harness.c")


def _bindp_src_dir():
    repo = os.environ.get("BINDP_REPO", "").strip()
    base = repo if repo else "/"
    src_dir = os.path.join(base, "usr/src/bindp")
    return src_dir if os.path.isfile(os.path.join(src_dir, "bindp.c")) else ""


class BindFamilyGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="bindp-tests.")
        src_dir = _bindp_src_dir()
        if not src_dir:
            raise unittest.SkipTest(
                "bindp.c not found (set BINDP_REPO to the bindp checkout)")
        ## gcc / make are required build tools, not optional: a missing one is an
        ## environment bug that must fail loud, so do not guard them with a skip.
        cls._lib = os.path.join(cls._tmp, "libindp.so")
        ## Build the REAL source with the shipped Makefile and its hardening
        ## flags; direct the output into the tmp dir so the checkout is untouched.
        subprocess.run(
            ["make", "-C", src_dir, f"TARGET={cls._lib}"],
            check=True, capture_output=True, text=True)
        cls._harness = os.path.join(cls._tmp, "harness")
        subprocess.run(
            ["gcc", "-O2", "-Wall", HARNESS_SRC, "-o", cls._harness],
            check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _run_harness(self):
        env = dict(os.environ)
        env["LD_PRELOAD"] = self._lib
        env["REUSE_ADDR"] = "1"
        env["REUSE_PORT"] = "1"
        return subprocess.run(
            [self._harness], env=env, capture_output=True, text=True)

    def test_af_unspec_wildcard_bind_gets_reuse_options(self):
        proc = self._run_harness()
        ## Exit 2 is a setup failure in the harness (socket/first bind), not the
        ## assertion -- surface it as an error rather than a misleading failure.
        self.assertNotEqual(
            proc.returncode, 2,
            msg=f"harness setup failed: {proc.stderr}")
        ## Exit 1 is the regression: the second AF_UNSPEC wildcard bind was
        ## rejected because bindp skipped SO_REUSEPORT for the AF_UNSPEC family.
        self.assertEqual(
            proc.returncode, 0,
            msg=("second AF_UNSPEC wildcard bind rejected -- bindp gated the "
                 f"reuse options on sa_family, not the socket family: {proc.stderr}"))


if __name__ == "__main__":
    sys.exit(unittest.main())
