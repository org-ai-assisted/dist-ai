#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the tb-updater test suite.

Resolves the tb-updater scripts under test:
  * TB_UPDATER_REPO=/path/to/tb-updater -> <repo>/usr/bin/update-torbrowser etc.
  * unset                               -> the installed copies under /usr

The core tests are pure-source structural checks (the GUI-mode wiring contract
and input routing), so a checkout is enough; nothing is installed or executed.
Each resolver exits 77 (SKIP) when its script is absent, mirroring the
msgcollector suite.
"""

import os
import re
import sys


def _repo() -> str:
    return os.environ.get("TB_UPDATER_REPO", "").strip()


def _resolve(rel_from_repo: str, installed: str, label: str) -> str:
    repo = _repo()
    if repo:
        cand = os.path.join(repo, rel_from_repo)
        if os.path.isfile(cand):
            return cand
        print(f"TB_UPDATER_REPO={repo!r} has no {rel_from_repo}; skipping.",
              file=sys.stderr)
        sys.exit(77)
    if os.path.isfile(installed):
        return installed
    print(f"{label} not found (set TB_UPDATER_REPO); skipping.", file=sys.stderr)
    sys.exit(77)


def update_torbrowser_script() -> str:
    """Absolute path of the update-torbrowser script under test."""
    return _resolve("usr/bin/update-torbrowser",
                    "/usr/bin/update-torbrowser", "update-torbrowser")


def desktop_starter_wrapper() -> str:
    """Absolute path of the desktop-shortcut launcher under test."""
    return _resolve("usr/libexec/tb-updater/desktop-starter-wrapper",
                    "/usr/libexec/tb-updater/desktop-starter-wrapper",
                    "desktop-starter-wrapper")


def version_validator_script() -> str:
    """Absolute path of the version-validator helper under test."""
    return _resolve("usr/libexec/tb-updater/version-validator",
                    "/usr/libexec/tb-updater/version-validator",
                    "version-validator")


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


_FUNC_RE_TMPL = r"^%s\(\) \{\n(.*?)^\}"


def extract_bash_function(path: str, name: str) -> str:
    """Return the full definition of a top-level bash function `name` from
    `path`. Assumes the closing brace is at column 0. Raises LookupError if not
    found (an older tb-updater may predate the function)."""
    match = re.search(_FUNC_RE_TMPL % re.escape(name), read(path),
                      re.DOTALL | re.MULTILINE)
    if not match:
        raise LookupError(f"function {name!r} not found in {path}")
    return f"{name}() {{\n{match.group(1)}}}\n"
