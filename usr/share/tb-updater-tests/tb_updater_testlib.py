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
import subprocess
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


def postinst_script() -> str:
    """Absolute path of the debian postinst maintainer script under test."""
    return _resolve("debian/tb-updater.postinst",
                    "/var/lib/dpkg/info/tb-updater.postinst",
                    "tb-updater.postinst")


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


def sanitize_string_bindir() -> str:
    """Directory of the sanitize-string binary the driven functions call by bare
    name, resolved from the wired binary / a helper-scripts checkout, so a
    checkout run behaves like an installed one. Empty if not resolvable."""
    for var in ("SANITIZE_STRING_BIN",):
        value = os.environ.get(var, "").strip()
        if value:
            return os.path.dirname(value)
    hs = os.environ.get("HELPER_SCRIPTS_PATH", "").strip()
    if hs and os.path.isfile(os.path.join(hs, "usr/bin/sanitize-string")):
        return os.path.join(hs, "usr/bin")
    if os.path.isfile("/usr/bin/sanitize-string"):
        return "/usr/bin"
    return ""


def drive_bash_function(path: str, name: str, *, preamble: str = "",
                        replace=None, args: str = "", env=None,
                        stdin: "str | None" = None
                        ) -> subprocess.CompletedProcess:
    """Source the REAL shipped bash function `name` from `path` and run it,
    returning the completed process.

    This executes the actual function body (not a copy of it): `replace` rewrites
    absolute helper/dialog paths in the extracted source to stubs so no real
    dialog or privileged tool runs, `preamble` provides stub functions and
    fixture variables, and `args`/`env`/`stdin` drive the call. Errexit/nounset
    are left off so a fixture that leaves an unrelated variable unset does not
    abort before the branch under test."""
    src = extract_bash_function(path, name)
    if replace:
        for old, new in replace.items():
            src = src.replace(old, new)
    driver = "set +e +u\n" + preamble + src + f"{name} {args}\n"
    child_env = dict(os.environ)
    bindir = sanitize_string_bindir()
    if bindir:
        child_env["PATH"] = bindir + os.pathsep + child_env.get("PATH", "")
    if env:
        child_env.update(env)
    return subprocess.run(
        ["bash", "-c", driver],
        input=stdin,
        capture_output=True,
        text=True,
        env=child_env,
        check=False,
    )
