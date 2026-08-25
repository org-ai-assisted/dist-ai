## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""The pre-commit-hooks batch external -- run the pre-commit/pre-commit-hooks
binaries over the changed file set. Unlike an AST rule (one file, the parsed
tree), these are file-LIST tools: check-added-large-files needs the base ref,
forbid-new-submodules needs the range, the content fixers run over typed
sublists. So this is a batch pass keyed on (paths, base_ref, staged_mode), not a
per-file Rule.

Findings are model.Finding (FAIL / NOTE), rendered by the gate exactly like a
rule's. Fail-open when the hooks are absent (a bare git-hook run without them
installed must still commit). Every hook call puts untrusted filenames AFTER a
'--' so a path named like an option ('--fix=lf') is a positional arg, never a
flag that flips a fixer into rewrite mode (R-062)."""

import os
import re
import shutil
import subprocess
import tempfile

from dist_ai import model

## Anchored per-file waiver: a sourced fragment legitimately carries a shebang
## (dialect detection, highlighting) yet is not executable.
_SOURCED_FRAGMENT = re.compile(
    r"^[ \t]*##[ \t]*style-ok:[ \t]*sourced-fragment([ \t]|$)", re.MULTILINE)

## An imported package module keeps its shebang and stays non-executable (Debian
## ships these 0644). Anchored to a real Python library path so a plain script
## in a directory merely named 'dist-packages' is not exempted.
_INSTALLED_MODULE = re.compile(
    r"/lib/python3[^/]*/(?:dist|site)-packages/.*\.py$")

## check-json / pretty-format-json: an app-MANAGED settings file is rewritten by
## the app itself (unsorted, human-grouped) on every change, so formatting it
## here is futile and destructive. 'claude'/'.claude' as a FULL path component.
_APP_MANAGED_JSON = re.compile(
    r"(?:^|/)\.?claude/settings(?:\.local)?\.json$")

## is_text_file: cheap extension allowlist; a 'file --mime' fallback covers an
## extensionless script.
_TEXT_EXT = {
    ".md", ".sh", ".bsh", ".bash", ".py", ".yml", ".yaml", ".json", ".toml",
    ".xml", ".txt", ".csv", ".cfg", ".conf", ".ini", ".rst", ".html", ".css",
    ".js", ".ts", ".c", ".h", ".cpp", ".hpp", ".go", ".rs", ".tex",
    ".dockerfile"}
_TEXT_NAME = {"Dockerfile", "Makefile", "COPYING", "README", "LICENSE"}
_TEXT_MIME = ("text/", "x-shellscript", "x-python", "json", "xml", "yaml",
              "toml", "charset=us-ascii", "charset=utf-8")


def _abs(base_cwd, path):
    return path if os.path.isabs(path) else os.path.join(base_cwd, path)


def _is_binary_attr(base_cwd, path):
    """True if the repo declares PATH binary in .gitattributes -- then it is
    data, never text, whatever its extension."""
    try:
        out = subprocess.run(
            ["git", "check-attr", "--cached", "binary", "--", path],
            capture_output=True, cwd=base_cwd)
    except OSError:
        return False
    ## Decode with replace: git echoes the PATH back, which may hold non-UTF-8
    ## bytes -- a strict decode (text=True) would crash the whole scan.
    return out.stdout.decode("utf-8", "replace").rstrip("\n").endswith(
        ": binary: set")


def _is_text_file(base_cwd, path):
    if _is_binary_attr(base_cwd, path):
        return False
    base = os.path.basename(path)
    _, ext = os.path.splitext(base)
    if ext.lower() in _TEXT_EXT or base in _TEXT_NAME:
        return True
    if shutil.which("file") is None:
        return False
    try:
        mime = subprocess.run(
            ["file", "--brief", "--mime", "--dereference", "--",
             _abs(base_cwd, path)],
            capture_output=True, text=True).stdout
    except OSError:
        return False
    return any(token in mime for token in _TEXT_MIME)


def _read_text(base_cwd, path):
    try:
        with open(_abs(base_cwd, path), "rb") as handle:
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _run_hook(hook, flags, files, base_cwd):
    """Run a git-aware / checker hook on the REAL repo. Untrusted FILES go after
    '--'. A non-zero exit is a gate FAIL carrying the hook's output."""
    if not files:
        return
    try:
        proc = subprocess.run(
            [hook] + list(flags) + ["--"] + list(files),
            capture_output=True, cwd=base_cwd)
    except OSError as exc:
        ## Could NOT run the hook (E2BIG on a huge file list, the binary
        ## vanished mid-scan): a FAIL, never a silent return -- a check that did
        ## not run must not read as a pass (a private-key / AWS-credential scan
        ## bypassed this way would be a false green).
        yield model.fail(hook, "%s: could not run: %s" % (hook, exc), files[0])
        return
    if proc.returncode != 0:
        out = (proc.stdout + proc.stderr).decode("utf-8", "replace").rstrip("\n")
        message = "%s: exited non-zero" % hook
        if out.strip():
            message += "\n" + out
        yield model.fail(hook, message, files[0])


def _run_fixer(hook, files, base_cwd):
    """Run a content FIXER (end-of-file-fixer, ...) against throwaway copies so
    the working tree / a detached checkout is never mutated. The non-zero exit
    (the hook's 'would modify' signal) still fails the gate."""
    if not files:
        return
    mirror = tempfile.mkdtemp()
    try:
        for path in files:
            ## Force the copy INSIDE the mirror: os.path.join drops the mirror
            ## entirely for an absolute 'path', and a '..' would climb out --
            ## either way the fixer would run against (and the copy could clobber)
            ## a real tree, breaking the throwaway-copy guarantee. normpath+strip
            ## anchors every path under the mirror.
            rel = os.path.normpath(os.sep + path).lstrip(os.sep)
            dest = os.path.join(mirror, rel)
            try:
                os.makedirs(os.path.dirname(dest) or mirror, exist_ok=True)
                shutil.copy2(_abs(base_cwd, path), dest, follow_symlinks=False)
            except OSError:
                ## Unreadable / gone / same-file: skip this one rather than crash
                ## the whole batch. The gate's own detect pass still sees it.
                continue
        try:
            proc = subprocess.run(
                [hook, "--"] + list(files),
                capture_output=True, cwd=mirror)
        except OSError as exc:
            yield model.fail(hook, "%s: could not run: %s" % (hook, exc),
                             files[0])
            return
        if proc.returncode != 0:
            yield model.fail(
                hook,
                "%s: would modify file(s) -- run '%s' locally and commit the "
                "result" % (hook, hook), files[0])
    finally:
        shutil.rmtree(mirror, ignore_errors=True)


def _added(paths, base_ref, base_cwd):
    """The subset of PATHS this changeset ADDS (absent from BASE_REF). A path
    both added and deleted in the range is skipped (nothing on disk to stat)."""
    out = []
    for path in paths:
        if not os.path.exists(_abs(base_cwd, path)):
            continue
        if base_ref and subprocess.run(
                ["git", "cat-file", "-e", "%s:%s" % (base_ref, path)],
                capture_output=True, cwd=base_cwd).returncode == 0:
            continue
        out.append(path)
    return out


def _classify(paths, base_cwd):
    """Partition PATHS into the typed lists the hooks consume. Skips a symlink
    (its own list), a submodule gitlink (a directory here -- no content), and a
    vanished path."""
    lists = {name: [] for name in (
        "text", "exec_text", "symlink", "yaml", "json", "toml", "xml",
        "python", "req")}
    for path in paths:
        real = _abs(base_cwd, path)
        if not os.path.lexists(real):
            continue
        if os.path.islink(real):
            lists["symlink"].append(path)
            continue
        if not os.path.isfile(real):
            continue
        if _is_text_file(base_cwd, path):
            lists["text"].append(path)
            if os.access(real, os.X_OK):
                lists["exec_text"].append(path)
        base = os.path.basename(path)
        _, ext = os.path.splitext(base)
        ext = ext.lower()
        if ext in (".yml", ".yaml"):
            lists["yaml"].append(path)
        elif ext == ".json":
            lists["json"].append(path)
        elif ext == ".toml":
            lists["toml"].append(path)
        elif ext == ".xml":
            lists["xml"].append(path)
        elif ext == ".py":
            lists["python"].append(path)
        if re.match(r"(?:.*/)?(?:requirements|constraints).*\.txt$", path):
            lists["req"].append(path)
    return lists


def run(paths, base_ref, staged_mode, base_cwd=None):
    """Yield Findings from the pre-commit-hooks batch over PATHS (the changed
    file set, in the gate's own path spelling). BASE_CWD is the repo root for a
    git mode (paths are repo-relative there), else None (paths are as-given).
    Fail-open with a NOTE when the hooks are not installed."""
    if base_cwd is None:
        base_cwd = os.getcwd()
    if shutil.which("check-yaml") is None:
        yield model.note(
            "pre-commit-hooks",
            "pre-commit-hooks not on PATH; skipping "
            "(apt-get install pre-commit-hooks)")
        return

    lists = _classify(paths, base_cwd)
    text = lists["text"]

    ## filename-blind, over the whole changed set:
    ## '--enforce-all' inspects the passed files (git diff --staged is empty at
    ## push time); restricted to ADDED files so a long-tracked large file does
    ## not fail every commit that appends to it.
    added = _added(paths, base_ref, base_cwd)
    yield from _run_hook("check-added-large-files", ["--enforce-all"], added,
                         base_cwd)
    yield from _run_hook("check-case-conflict", [], paths, base_cwd)
    yield from _run_hook("destroyed-symlinks", [], paths, base_cwd)

    ## forbid-new-submodules diffs '--staged' unless the range is exported; in
    ## push mode nothing is staged, so without the range it inspects nothing.
    env_saved = None
    if base_ref and not staged_mode:
        env_saved = (os.environ.get("PRE_COMMIT_FROM_REF"),
                     os.environ.get("PRE_COMMIT_TO_REF"))
        os.environ["PRE_COMMIT_FROM_REF"] = base_ref
        os.environ["PRE_COMMIT_TO_REF"] = "HEAD"
    try:
        yield from _run_hook("forbid-new-submodules", [], paths, base_cwd)
    finally:
        if env_saved is not None:
            for key, value in zip(
                    ("PRE_COMMIT_FROM_REF", "PRE_COMMIT_TO_REF"), env_saved,
                    strict=True):
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    ## text-only:
    yield from _run_hook("check-merge-conflict", [], text, base_cwd)
    yield from _run_hook("check-vcs-permalinks", [], text, base_cwd)
    yield from _run_hook("detect-aws-credentials",
                         ["--allow-missing-credentials"], text, base_cwd)
    yield from _run_hook("detect-private-key", [], text, base_cwd)
    yield from _run_fixer("fix-byte-order-marker", text, base_cwd)
    yield from _run_fixer("end-of-file-fixer", text, base_cwd)
    yield from _run_fixer("trailing-whitespace-fixer", text, base_cwd)
    yield from _run_hook("mixed-line-ending", ["--fix=no"], text, base_cwd)

    ## check-shebang-scripts-are-executable: exempt a sourced fragment (waiver)
    ## and an imported package module (R-180).
    shebang_files = []
    for path in text:
        content = _read_text(base_cwd, path)
        if _SOURCED_FRAGMENT.search(content):
            yield model.note(
                "check-shebang-scripts-are-executable",
                "skipped: 'style-ok: sourced-fragment' waiver in '%s'" % path)
            continue
        if _INSTALLED_MODULE.search(path):
            yield model.note(
                "check-shebang-scripts-are-executable",
                "skipped: '%s' is an imported package module" % path)
            continue
        shebang_files.append(path)
    yield from _run_hook("check-shebang-scripts-are-executable", [],
                         shebang_files, base_cwd)

    yield from _run_hook("check-executables-have-shebangs", [],
                         lists["exec_text"], base_cwd)
    yield from _run_hook("check-symlinks", [], lists["symlink"], base_cwd)

    ## type by extension:
    yield from _run_hook("check-yaml", [], lists["yaml"], base_cwd)
    yield from _run_hook("check-json", [], lists["json"], base_cwd)
    yield from _run_hook("check-toml", [], lists["toml"], base_cwd)
    yield from _run_hook("check-xml", [], lists["xml"], base_cwd)
    yield from _run_hook("check-ast", [], lists["python"], base_cwd)
    yield from _run_hook("check-builtin-literals", [], lists["python"],
                         base_cwd)
    yield from _run_hook("debug-statement-hook", [], lists["python"], base_cwd)

    ## pretty-format-json REWRITES (and key-sorts) -- skip an app-managed
    ## settings file (check-json already validated its SYNTAX).
    json_fmt = []
    for path in lists["json"]:
        if _APP_MANAGED_JSON.search(path):
            yield model.note(
                "pretty-format-json",
                "skipped: '%s' is an app-managed settings file "
                "(syntax still checked by check-json; the app owns its format)"
                % path)
            continue
        json_fmt.append(path)
    yield from _run_fixer("pretty-format-json", json_fmt, base_cwd)
    yield from _run_fixer("requirements-txt-fixer", lists["req"], base_cwd)
