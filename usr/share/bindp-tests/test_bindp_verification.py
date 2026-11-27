#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
CBMC formal-verification proofs for bindp (usr/src/bindp/bindp.c).

Drives bindp_cbmc.c (which #includes the REAL bindp.c, resolved via BINDP_REPO)
through CBMC, one proof per `--function`. bindp is loop-free interposer
arithmetic, so every proof is EXHAUSTIVE -- no --unwind, no bound. The proofs
cover memory safety of bind()/connect() and the env parsing, the strtol ->
in_port_t BIND_PORT conversion, and the SO_DOMAIN family gate -- including the
regression property that an AF_UNSPEC-family caller on a real AF_INET socket
still gets the reuse options.

cbmc is a REQUIRED tool: its absence is an environment bug (FATAL exit 1,
declare it in dm-consumer.yml apt-packages), never a skip. Only a missing
subject (no bindp.c under BINDP_REPO) skips.
"""

import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
HARNESS = os.path.join(HERE, "bindp_cbmc.c")

## Every verify_* entry in bindp_cbmc.c. A proof added to the harness must be
## listed here or it never runs.
CBMC_FUNCTIONS = (
    "verify_parse_int_flag",
    "verify_init_env_parsing",
    "verify_get_address_family",
    "verify_bind_inet_memory_safety",
    "verify_bind_ip_applies_options",
    "verify_bind_af_unspec_caller_still_applies_options",
    "verify_bind_non_ip_skips_options",
    "verify_connect_memory_safety",
)

## The standard CBMC check set, explicit (version-independent rather than
## relying on CBMC 6.x defaults).
CBMC_CHECKS = (
    "--signed-overflow-check",
    "--unsigned-overflow-check",
    "--conversion-check",
    "--div-by-zero-check",
    "--pointer-check",
    "--bounds-check",
)


def _bindp_src_dir():
    repo = os.environ.get("BINDP_REPO", "").strip()
    base = repo if repo else "/"
    src_dir = os.path.join(base, "usr/src/bindp")
    return src_dir if os.path.isfile(os.path.join(src_dir, "bindp.c")) else ""


def _require(tool):
    path = shutil.which(tool)
    if path is None:
        print(
            f"FATAL: {tool!r} not found -- declare it in dm-consumer.yml "
            "apt-packages", file=sys.stderr)
        sys.exit(1)
    return path


class BindpVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src_dir = _bindp_src_dir()
        if not cls.src_dir:
            ## style-ok: allow-skip: bindp source absent (not a --component run);
            ## the orchestrator fails an unauthorized skip under --component.
            raise unittest.SkipTest(
                "bindp.c not found (set BINDP_REPO to the bindp checkout)")
        cls.cbmc = _require("cbmc")

    def test_cbmc_proofs_verify(self):
        for function in CBMC_FUNCTIONS:
            with self.subTest(function=function):
                proc = subprocess.run(
                    [self.cbmc, HARNESS, "-I", self.src_dir,
                     "--function", function, *CBMC_CHECKS],
                    capture_output=True, text=True)
                self.assertIn(
                    "VERIFICATION SUCCESSFUL", proc.stdout,
                    msg=(f"{function}: proof did not verify\n"
                         f"--- stdout ---\n{proc.stdout}\n"
                         f"--- stderr ---\n{proc.stderr}"))


if __name__ == "__main__":
    sys.exit(unittest.main())
