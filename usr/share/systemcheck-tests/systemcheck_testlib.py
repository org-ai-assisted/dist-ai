#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the systemcheck test suite.

Resolves the systemcheck sources under test:
  * SYSTEMCHECK_REPO=/path/to/systemcheck -> <repo>/usr/libexec/systemcheck
  * unset                                 -> /usr/libexec/systemcheck (installed)

Also provides a helper to extract a single top-level bash function from a .bsh
fragment and run it in isolation (the fragments cannot be sourced wholesale
because they source sibling files by absolute path).
"""

import os
import re
import subprocess
import sys
import unittest


def systemcheck_dir() -> str:
    """Return the directory holding the systemcheck .bsh fragments."""
    repo = os.environ.get("SYSTEMCHECK_REPO", "").strip()
    if repo:
        cand = os.path.join(repo, "usr", "libexec", "systemcheck")
        if os.path.isdir(cand):
            return cand
        ## SKIP (exit 77) rather than FAIL when the checkout does not have the
        ## expected layout -- mirrors the dist-ai suite convention.
        print(
            f"SYSTEMCHECK_REPO={repo!r} has no usr/libexec/systemcheck; skipping.",
            file=sys.stderr,
        )
        sys.exit(77)
    installed = "/usr/libexec/systemcheck"
    if os.path.isdir(installed):
        return installed
    print("systemcheck sources not found (set SYSTEMCHECK_REPO); skipping.",
          file=sys.stderr)
    sys.exit(77)


def bsh_files() -> list[str]:
    """Absolute paths of every *.bsh fragment plus the log-checker script."""
    directory = systemcheck_dir()
    out = []
    for name in sorted(os.listdir(directory)):
        if name.endswith(".bsh") or name == "log-checker":
            out.append(os.path.join(directory, name))
    return out


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


_FUNC_RE_TMPL = r"^%s\(\) \{\n(.*?)^\}"


def extract_bash_function(path: str, name: str) -> str:
    """
    Return the full definition of a top-level bash function `name` from `path`.
    Assumes the closing brace is at column 0 (the fragment style). Raises
    LookupError if not found.
    """
    text = read(path)
    match = re.search(_FUNC_RE_TMPL % re.escape(name), text, re.DOTALL | re.MULTILINE)
    if not match:
        raise LookupError(f"function {name!r} not found in {path}")
    return f"{name}() {{\n{match.group(1)}}}\n"


def run_bash_function(func_def: str, call: str, env_setup: str = "") -> str:
    """
    Source `func_def`, run `env_setup`, then `call`; return stdout (stripped).
    Runs under a strict-ish bash but WITHOUT nounset (the fragments rely on
    optional globals).
    """
    script = f"set -o errexit\nset -o pipefail\n{env_setup}\n{func_def}\n{call}\n"
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


class SystemcheckTestBase(unittest.TestCase):
    """Base class exposing the resolved source directory + file list."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = systemcheck_dir()
        cls.files = bsh_files()
        cls.preparation = os.path.join(cls.dir, "preparation.bsh")
