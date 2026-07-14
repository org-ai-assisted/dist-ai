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


def _has_bash_shebang(path: str) -> bool:
    """True if the file's first line is a bash shebang."""
    try:
        with open(path, "rb") as handle:
            first_line = handle.readline(256)
    except OSError:
        return False
    return first_line.startswith(b"#!") and b"bash" in first_line


def bash_scripts() -> list[str]:
    """Absolute paths of EVERY bash script shipped by systemcheck, not just the
    *.bsh fragments: the fragments, the log-checker, the main `systemcheck`
    entrypoint, and every other file carrying a bash shebang (canary,
    canary-daemon, check-env, check_tor_running, crypt-check, pkexec-test,
    updatecheck-daemon, user-sysmaint-split-check, ...).

    Source tree (SYSTEMCHECK_REPO set): walk the checkout, skipping VCS and
    Debian packaging directories. Installed: use the package file list from
    `dpkg -L systemcheck` so no prefix has to be guessed.
    """
    repo = os.environ.get("SYSTEMCHECK_REPO", "").strip()
    if repo and os.path.isdir(repo):
        candidates = []
        skip_dirs = {".git", ".github", "debian"}
        for dirpath, dirs, names in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for name in names:
                candidates.append(os.path.join(dirpath, name))
    else:
        ## Trigger the standard SKIP if the sources are not present at all.
        systemcheck_dir()
        proc = subprocess.run(
            ["dpkg", "-L", "systemcheck"],
            capture_output=True, text=True, check=False,
        )
        candidates = proc.stdout.splitlines()

    scripts = []
    for path in sorted(set(candidates)):
        if not os.path.isfile(path):
            continue
        if path.endswith(".bsh") or os.path.basename(path) == "log-checker" \
                or _has_bash_shebang(path):
            scripts.append(path)
    return scripts


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
