#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the tb-updater test suite.

Resolves the tb-updater scripts under test:
  * TB_UPDATER_REPO=/path/to/tb-updater -> <repo>/usr/bin/update-torbrowser etc.
  * unset                               -> the installed copies under /usr

The core tests source the real scripts and drive their functions with only
root/Qubes/GUI externals stubbed, so a checkout is enough; nothing is
installed.
Each resolver exits 77 (SKIP) when its script is absent, mirroring the
msgcollector suite.
"""

import os
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


def sandbox_update_torbrowser_script() -> str:
    """Absolute path of the sandbox-update-torbrowser entry point under test."""
    return _resolve("usr/libexec/tb-updater/sandbox-update-torbrowser",
                    "/usr/libexec/tb-updater/sandbox-update-torbrowser",
                    "sandbox-update-torbrowser")


def dispvm_script() -> str:
    """Absolute path of the Qubes DispVM mount-point helper under test."""
    return _resolve("usr/libexec/tb-updater/dispvm",
                    "/usr/libexec/tb-updater/dispvm", "dispvm")


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


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


## Hang guard for one driven call (a GUI dialog that escaped its stub would
## otherwise block until a human closes it).
DRIVE_TIMEOUT = 60.0

## Exit status of the driver when the subject could not be loaded or lacks a
## hook the test relies on -- never a status the driven functions use.
DRIVE_UNUSABLE = 3


def drive_sourced_function(path: str, name: str, *, setup: str = "",
                           require: str = "", env=None,
                           stdin: "str | None" = None
                           ) -> subprocess.CompletedProcess:
    """Source the REAL script at `path` and call its function `name`,
    returning the completed process.

    The subject is source-able (its was_executed guard keeps main from
    auto-running and keeps strict mode out of the sourcing shell), so the
    whole file is loaded as shipped. A failing source exits DRIVE_UNUSABLE.
    `require` runs right after the source and must exit DRIVE_UNUSABLE when
    the subject lacks a hook the test depends on (an older script would
    otherwise act on the REAL paths/dialogs). `setup` runs next: stub
    functions defined there override the real root/Qubes/GUI externals, and
    fixture globals assigned there override the script's own. Inherited
    strict options (SHELLOPTS) are cleared first: fixtures leave unrelated
    variables unset on purpose. `env`/`stdin` drive the call."""
    driver = (
        'set +o errexit +o nounset +o pipefail\n'
        f'source "$1" || exit {DRIVE_UNUSABLE}\n'
        + require + '\n'
        + setup + '\n"$2"\n'
    )
    child_env = dict(os.environ)
    bindir = sanitize_string_bindir()
    if bindir:
        child_env["PATH"] = bindir + os.pathsep + child_env.get("PATH", "")
    if env:
        child_env.update(env)
    return subprocess.run(
        ["bash", "-c", driver, "bash", path, name],
        input=stdin,
        capture_output=True,
        text=True,
        env=child_env,
        check=False,
        timeout=DRIVE_TIMEOUT,
    )
