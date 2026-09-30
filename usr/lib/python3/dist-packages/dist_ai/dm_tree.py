## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shared derivative-maker tree primitives for the root-surface tooling.

Both dm-root-scripts-enum (the root-surface inventory) and dm-root-lpe-audit
(the LPE detector layered on it) walk the SAME source tree and must agree, to
the byte, on three judgements:

  - the installed name of a source file (genmkfile's 'name#pkg' -> 'name'),
  - whether a file is shell (so it is parsed, not skipped),
  - which submodule/component a path belongs to.

A second copy of these in the audit tool would drift from the enum silently --
an installed-name rule that disagreed would map an Exec* target to the wrong
file, or miss it -- so they live here once and both tools import them.
"""

import os
import re


SHELL_EXT = (".sh", ".bash", ".bsh")
SHELL_SHEBANG_RE = re.compile(r"\b(bash|sh|dash)\b")


def install_name(rel_path):
    """The installed basename. genmkfile keeps the install destination in the
    SOURCE filename: 'name#pkg' installs as 'name', and a package-rename tag can
    follow the real extension ('foo.policy.security-misc#pkg'). Drop the '#pkg'
    fragment so a suffix/ext test sees the real name."""
    return os.path.basename(rel_path).split("#", 1)[0]


def name_has_ext(rel_path, ext):
    """True if the installed name carries EXT, at the end or before a rename tag
    ('proc-hidepid.service#pkg', 'org...Flatpak.policy.security-misc#pkg')."""
    name = install_name(rel_path)
    return name.endswith(ext) or (ext + ".") in name


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def shebang(path):
    try:
        with open(path, "rb") as handle:
            first = handle.readline(256)
    except OSError:
        return None
    if first.startswith(b"#!"):
        return first[2:].decode("utf-8", "replace").strip()
    return None


def is_shell(abs_path, rel_path):
    ## dm's build-step dirs hold only shell, some extensionless and without a
    ## shebang (sourced, not executed) -- scan them regardless.
    if rel_path.startswith(("help-steps/", "build-steps.d/")):
        return True
    if any(name_has_ext(rel_path, ext) for ext in SHELL_EXT):
        return True
    line = shebang(abs_path)
    return bool(line) and bool(SHELL_SHEBANG_RE.search(line))


def submodule_paths(dm_root):
    gitmodules = os.path.join(dm_root, ".gitmodules")
    paths = []
    if os.path.isfile(gitmodules):
        for line in read_text(gitmodules).splitlines():
            line = line.strip()
            if line.startswith("path"):
                _, _, value = line.partition("=")
                value = value.strip()
                if value:
                    paths.append(value.rstrip("/"))
    return sorted(set(paths), key=len, reverse=True)


def component_for(rel_path, submodules):
    for sub in submodules:
        if rel_path == sub or rel_path.startswith(sub + "/"):
            return os.path.basename(sub), sub
    return "derivative-maker", ""


def walk_tree(dm_root, walk_errors):
    """Yield (abs_path, rel_path) for every non-symlink regular file under
    DM_ROOT, skipping VCS/cache dirs. An unreadable directory is appended to
    WALK_ERRORS, never silently dropped -- a security inventory that quietly
    omits a subtree reads as clean while blind to it."""
    skip_dirs = {".git", ".pytest_cache", "__pycache__"}
    for dirpath, dirnames, filenames in os.walk(
            dm_root, onerror=lambda exc: walk_errors.append(str(exc))):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            abs_path = os.path.join(dirpath, name)
            if os.path.islink(abs_path):
                continue
            yield abs_path, os.path.relpath(abs_path, dm_root)
