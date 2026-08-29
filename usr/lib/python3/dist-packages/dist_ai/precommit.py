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


def _materialize_blobs(paths, source_rev, base_cwd):
    """Copy each PATH's git blob at SOURCE_REV ('' = the index, a commit-ish =
    that tree) into a temp MIRROR preserving the repo-relative layout, with the
    tree's executable bit -- so a content/size/exec hook reads the object that
    ships, not the working tree that may have diverged (the 'staged secret hidden
    by a clean working copy' bypass). Fetched BY SHA from a whole-tree listing
    keyed on the exact path, so an adversarial filename cannot evade it. Returns
    (mirror_dir, failed) -- the caller removes the dir; FAILED is the blobs that
    could NOT be materialized (cat-file or write error), which the caller must
    FAIL on rather than silently skip: an unmaterialized blob is absent from the
    mirror, so the content scans (detect-private-key) never see it -- a scan that
    did not run must not read as a pass (fail closed)."""
    from dist_ai import gitdiff
    entries = gitdiff._tree_entries(
        None if source_rev == "" else source_rev, base_cwd)
    mirror = tempfile.mkdtemp(prefix="dist-ai-precommit-")
    failed = []
    for path in paths:
        mode, sha = entries.get(path, (None, None))
        ## Skip a symlink (120000) -- the broken-symlink check is git-native (see
        ## _broken_staged_symlinks), NOT a filesystem check over a mirror -- and a
        ## gitlink (160000), a submodule pointer with no file content.
        if sha is None or mode in ("120000", "160000"):
            continue
        try:
            blob = subprocess.run(
                ["git", "cat-file", "blob", sha],
                capture_output=True, cwd=base_cwd, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            failed.append(path)
            continue
        dest = os.path.join(mirror, os.path.normpath(os.sep + path).lstrip(os.sep))
        try:
            os.makedirs(os.path.dirname(dest) or mirror, exist_ok=True)
            with open(dest, "wb") as handle:
                handle.write(blob)
            ## Owner-only: this mirror holds the scanned blob content, incl. a
            ## staged PRIVATE KEY / credential (detect-private-key runs over it),
            ## so it must not be group/world readable. Exec bit kept (0o700 vs
            ## 0o600) for the mode-sensitive exec-shebang checks.
            os.chmod(dest, 0o700 if mode == "100755" else 0o600)
        except OSError:
            failed.append(path)
            continue
    return mirror, failed


def _broken_staged_symlinks(paths, source_rev, base_cwd):
    """Yield a FAIL for each staged SYMLINK whose target is UNAMBIGUOUSLY absent
    from the staged TREE. Purely GIT-NATIVE (no /tmp mirror, no working tree): the
    target is resolved relative to the link's directory WITHIN the tree, so a
    relative ESCAPE above the root and the staged-vs-working-tree split are judged
    on the staged blob alone.

    CONSERVATIVE by design (a broken symlink is hygiene, not a security hole, and
    full in-tree path resolution is a mini filesystem): it flags ONLY a target
    that is plainly not a tree path, and ERRS TOWARD NOT flagging a valid commit.
    Documented best-effort gaps, like an absolute target (host/deploy-time):
      - a target whose path traverses an intermediate DIR-SYMLINK is not resolved
        (not flagged) -- the checkout-time check-symlinks resolves it;
      - a relative target that lexically collapses a '..' through an ABSENT dir
        (e.g. 'missing/../tracked.txt') normpaths to a present path and passes,
        though the link dangles -- again caught by check-symlinks on checkout.
    An ABSOLUTE target is not judged (it resolves against the host at deploy)."""
    from dist_ai import gitdiff
    entries = gitdiff._tree_entries(
        None if source_rev == "" else source_rev, base_cwd)
    ## Every tree path AND every directory prefix, incl. '.' (the tree root): a
    ## target resolving to any of these is present, so the link is not broken.
    tree_paths = {"."}
    for name in entries:
        tree_paths.add(name)
        parts = name.split("/")
        for i in range(1, len(parts)):
            tree_paths.add("/".join(parts[:i]))

    def _target(sha):
        try:
            return os.fsdecode(subprocess.run(
                ["git", "cat-file", "blob", sha], capture_output=True,
                cwd=base_cwd, check=True).stdout)
        except (OSError, subprocess.CalledProcessError):
            return None

    def _via_dir_symlink(resolved):
        ## True if any parent component of RESOLVED is itself a tree symlink --
        ## then we cannot cheaply follow it, so we do not flag (best-effort).
        parts = resolved.split("/")
        for i in range(1, len(parts)):
            mode, _sha = entries.get("/".join(parts[:i]), (None, None))
            if mode == "120000":
                return True
        return False

    for path in paths:
        mode, sha = entries.get(path, (None, None))
        if mode != "120000":
            continue
        target = _target(sha)
        if target is None or os.path.isabs(target):
            continue  ## unreadable, or absolute (host/deploy-time): not judged
        resolved = os.path.normpath(
            os.path.join(os.path.dirname(path), target))
        if resolved in tree_paths:
            continue  ## resolves to a tree path (file, dir, or another symlink)
        if _via_dir_symlink(resolved):
            continue  ## traverses a dir-symlink: best-effort, do not flag
        ## Either escapes the tree ('../...') or names a path with no tree entry:
        ## unambiguously absent -> broken.
        yield model.fail(
            "check-symlinks",
            "check-symlinks: '%s' is a broken symlink (its target is not in "
            "the tree)" % path, path)


def _is_binary_attr(base_cwd, path, source_rev):
    """True if the repo declares PATH binary in .gitattributes -- then it is
    data, never text, whatever its extension. The attribute source MUST match the
    tree the scanned CONTENT came from (source_rev), or a stale .gitattributes
    mis-classifies a file and a content scan (detect-private-key) is skipped:
      - '' staged: the INDEX blob -> the INDEX .gitattributes (--cached).
      - a rev (range): the blob's OWN commit -> that rev (--attr-source).
      - None working tree: the WORKING-TREE file -> the WORKING-TREE
        .gitattributes (plain check-attr). Using --cached here reads the STALE
        committed/index attrs, so a worktree that drops a 'id_rsa binary' mark
        (leaving it unstaged) while staging a real PEM would classify the key
        binary and skip detect-private-key -- a private-key bypass.
    Always run in the REAL repo (base_cwd), never the non-git content mirror."""
    if source_rev:
        attr = ["--attr-source=%s" % source_rev, "check-attr"]
    elif source_rev == "":
        attr = ["check-attr", "--cached"]
    else:  ## None: working-tree scan -> the working tree's own .gitattributes
        attr = ["check-attr"]
    try:
        out = subprocess.run(
            ["git"] + attr + ["binary", "--", path],
            capture_output=True, cwd=base_cwd)
    except OSError:
        return False
    ## Decode with replace: git echoes the PATH back, which may hold non-UTF-8
    ## bytes -- a strict decode (text=True) would crash the whole scan.
    return out.stdout.decode("utf-8", "replace").rstrip("\n").endswith(
        ": binary: set")


def _is_text_file(base_cwd, content_cwd, path, source_rev):
    ## Attribute check in the real repo (base_cwd); the 'file' mime probe on the
    ## CONTENT (content_cwd = the blob mirror in a git mode), so a file present
    ## only in the index / a diverged working copy is typed from what ships.
    if _is_binary_attr(base_cwd, path, source_rev):
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
             _abs(content_cwd, path)],
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


def _staged_merge_conflicts(files, content_cwd):
    """Flag a merge-conflict marker in the shipped CONTENT (the blob, via
    content_cwd). The 'check-merge-conflict' hook cannot serve here: its
    'is_in_merge()' runs 'git rev-parse' BEFORE the '--assume-in-merge'
    short-circuit (a pre-commit-hooks 5.0.0 ordering bug), so it aborts in the
    non-git blob mirror -- and only the mirror holds the object we must judge, not
    the working tree. Reuse the hook's OWN marker constant (no drift: the markers
    are git's fixed conflict format, 7-char line prefixes, not a grammar) and scan
    the bytes ourselves. Same per-line, startswith semantics as the hook."""
    from pre_commit_hooks.check_merge_conflict import CONFLICT_PATTERNS
    for path in files:
        try:
            with open(_abs(content_cwd, path), "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        for number, line in enumerate(data.splitlines(keepends=True), start=1):
            for pattern in CONFLICT_PATTERNS:
                if line.startswith(pattern):
                    yield model.fail(
                        "check-merge-conflict",
                        "check-merge-conflict: merge conflict string %r found"
                        % pattern.strip().decode(), path, number)


def _run_hook(hook, flags, files, base_cwd):
    """Run a git-aware / checker hook on the REAL repo. Untrusted FILES go after
    '--'. A non-zero exit is a gate FAIL carrying the hook's output. A wedged git
    read (a FIFO .gitattributes) cannot reach here: gate.hostile_attributes
    refuses a non-regular .gitattributes before the batch runs."""
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
                ## Read the source through O_NOFOLLOW|O_NONBLOCK and write a plain
                ## REGULAR file into the mirror. copy2(follow_symlinks=False) would
                ## copy a symlink AS a symlink, and the fixer -- opening it in the
                ## mirror -- would FOLLOW it and rewrite the target OUTSIDE the
                ## repo (a TOCTOU: a regular file swapped for a symlink after
                ## _classify). O_NOFOLLOW refuses that swap (ELOOP -> skip), so the
                ## fixer only ever sees a real file it cannot escape -- the same
                ## O_NOFOLLOW guard the engine's in-place fixer already uses.
                def _nofollow(open_path, flags):
                    return os.open(
                        open_path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
                with open(_abs(base_cwd, path), "rb",
                          opener=_nofollow) as src_handle:
                    content = src_handle.read()
                with open(dest, "wb") as dst_handle:
                    dst_handle.write(content)
            except OSError:
                ## Unreadable / gone / a symlink swapped in / same-file: skip this
                ## one rather than crash the batch. The detect pass still sees it.
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


def _added(paths, base_ref, base_cwd, content_cwd):
    """The subset of PATHS this changeset ADDS (absent from BASE_REF). Existence
    is stated in CONTENT_CWD (the mirror in blob mode, so a size hook stats the
    blob), the 'already in base' test runs git in BASE_CWD (the real repo)."""
    out = []
    for path in paths:
        if not os.path.exists(_abs(content_cwd, path)):
            continue
        if base_ref and subprocess.run(
                ["git", "cat-file", "-e", "%s:%s" % (base_ref, path)],
                capture_output=True, cwd=base_cwd).returncode == 0:
            continue
        out.append(path)
    return out


def _large_blobs(paths, base_ref, source_rev, base_cwd):
    """FAIL each newly-ADDED blob larger than check-added-large-files' default
    (500 KiB). The blob-mode counterpart of that hook, which stats the working
    tree (so a large file hidden behind a small working copy passed) and cannot
    run in the non-git mirror (it shells out to 'git check-attr'). 'cat-file -s'
    is the blob's real size -- and naturally the tiny POINTER size for a git-lfs
    file, so lfs stays exempt with no extra logic. Existence keys on the tree,
    not disk, so a large file staged then removed from the working copy is caught."""
    from dist_ai import gitdiff
    entries = gitdiff._tree_entries(
        None if source_rev == "" else source_rev, base_cwd)
    for path in paths:
        mode, sha = entries.get(path, (None, None))
        if sha is None or mode in ("120000", "160000"):
            continue
        if base_ref and subprocess.run(
                ["git", "cat-file", "-e", "%s:%s" % (base_ref, path)],
                capture_output=True, cwd=base_cwd).returncode == 0:
            continue  ## already present in the base -> not newly added
        try:
            size = int(subprocess.run(
                ["git", "cat-file", "-s", sha],
                capture_output=True, cwd=base_cwd, check=True).stdout)
        except (OSError, subprocess.CalledProcessError, ValueError):
            continue
        if size > 500 * 1024:
            yield model.fail(
                "check-added-large-files",
                "check-added-large-files: '%s' blob is %d KiB (> 500 KiB); "
                "reduce it or track it with git-lfs" % (path, size // 1024),
                path)


def _classify(paths, base_cwd, content_cwd, source_rev):
    """Partition PATHS into the typed lists the hooks consume. Existence, kind
    and exec bit are read from CONTENT_CWD (the blob mirror in a git mode), so a
    file present only in the index -- or whose working copy was overwritten with a
    decoy of a different type -- is still typed from the content that ships; the
    .gitattributes check keys on BASE_CWD (see _is_text_file). Skips a symlink, a
    submodule gitlink, and a vanished path."""
    lists = {name: [] for name in (
        "text", "scan", "exec_text", "symlink", "yaml", "json", "toml", "xml",
        "python", "req")}
    for path in paths:
        real = _abs(content_cwd, path)
        if not os.path.lexists(real):
            continue
        if os.path.islink(real):
            lists["symlink"].append(path)
            continue
        if not os.path.isfile(real):
            continue
        ## SECRET scanners run over 'scan' -- EVERY regular file, binary or not.
        ## Gating them on the binary classification let a '.gitattributes ...
        ## binary' mark (even an UNTRACKED one, honoured only in a working-tree
        ## scan) suppress detect-private-key/detect-aws for a real key. A key in a
        ## file marked binary is exactly what must still be caught, so the attr
        ## must never decide whether a secret scan runs.
        lists["scan"].append(path)
        if _is_text_file(base_cwd, content_cwd, path, source_rev):
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


def run(paths, base_ref, staged_mode, base_cwd=None, source_rev=None):
    """Yield Findings from the pre-commit-hooks batch over PATHS (the changed
    file set, in the gate's own path spelling). BASE_CWD is the repo root for a
    git mode (paths are repo-relative there), else None (paths are as-given).
    SOURCE_REV (None = working tree; '' = index; a commit-ish = that tree) makes
    every CONTENT/size/exec hook read the git OBJECT that ships, via a temp
    mirror, instead of the working tree -- else a staged private key / large file
    overwritten clean in the working copy would pass the batch (the same bypass
    the per-file blob gating closes). Fail-open with a NOTE when the hooks are not
    installed."""
    if base_cwd is None:
        base_cwd = os.getcwd()
    if shutil.which("check-yaml") is None:
        yield model.note(
            "pre-commit-hooks",
            "pre-commit-hooks not on PATH; skipping "
            "(apt-get install pre-commit-hooks)")
        return

    mirror = None
    ## content_cwd feeds hooks that read a file's BYTES or exec bit; base_cwd the
    ## ones that read git STRUCTURE (submodules, case, symlinks) -- those need the
    ## real repo, not a mirror.
    content_cwd = base_cwd
    if source_rev is not None:
        mirror, failed = _materialize_blobs(paths, source_rev, base_cwd)
        content_cwd = mirror
        ## Fail CLOSED on a blob that could not be materialized: it is absent from
        ## the mirror, so the content scans (detect-private-key) would never run
        ## over it -- a skipped secret scan must not read as a pass.
        for path in failed:
            yield model.fail(
                "detect-private-key",
                "could not materialize the staged blob for '%s'; its content "
                "scans did not run (failing closed)" % path, path)
    try:
        yield from _run_batch(paths, base_ref, staged_mode, base_cwd,
                              content_cwd, source_rev)
    finally:
        if mirror is not None:
            shutil.rmtree(mirror, ignore_errors=True)


def _run_batch(paths, base_ref, staged_mode, base_cwd, content_cwd, source_rev):
    ## content_cwd (the mirror in a git mode) feeds only the PURE-CONTENT hooks --
    ## those that read a file's bytes and call no git themselves. The many
    ## git-aware hooks (they run 'git ls-files' / 'git rev-parse' internally and
    ## would abort in a non-git mirror) stay on base_cwd. So the secret scanners
    ## (detect-private-key / detect-aws) and the parsers judge the blob, while the
    ## structure/mode hooks judge the real repo. classification reads the blob so
    ## a file present only in the index (worktree deleted) is still typed+scanned.
    lists = _classify(paths, base_cwd, content_cwd, source_rev)
    text = lists["text"]
    scan = lists["scan"]

    ## filename-blind, over the whole changed set:
    ## '--enforce-all' inspects the passed files (git diff --staged is empty at
    ## push time); restricted to ADDED files so a long-tracked large file does
    ## not fail every commit that appends to it.
    if source_rev is None:
        ## working-tree mode: the real hook stats the tree (which IS the content).
        added = _added(paths, base_ref, base_cwd, base_cwd)
        yield from _run_hook("check-added-large-files", ["--enforce-all"],
                             added, base_cwd)
    else:
        ## blob mode: the hook cannot run in the non-git mirror; check blob sizes.
        yield from _large_blobs(paths, base_ref, source_rev, base_cwd)
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

    ## Scan the SHIPPED content (blob) for merge-conflict markers -- the hook
    ## itself cannot run against the non-git blob mirror (see _staged_merge_conflicts).
    yield from _staged_merge_conflicts(text, content_cwd)
    yield from _run_hook("check-vcs-permalinks", [], text, content_cwd)
    ## Secret scanners over 'scan' (every regular file), NOT 'text': the binary
    ## attr must never suppress a secret scan (see _classify).
    yield from _run_hook("detect-aws-credentials",
                         ["--allow-missing-credentials"], scan, content_cwd)
    yield from _run_hook("detect-private-key", [], scan, content_cwd)
    yield from _run_fixer("fix-byte-order-marker", text, content_cwd)
    yield from _run_fixer("end-of-file-fixer", text, content_cwd)
    yield from _run_fixer("trailing-whitespace-fixer", text, content_cwd)
    yield from _run_hook("mixed-line-ending", ["--fix=no"], text, content_cwd)

    ## check-shebang-scripts-are-executable: exempt a sourced fragment (waiver)
    ## and an imported package module (R-180). Reads content + exec bit, both of
    ## which the mirror carries from the tree.
    shebang_files = []
    for path in text:
        content = _read_text(content_cwd, path)
        if _SOURCED_FRAGMENT.search(content):
            yield model.note(
                "check-shebang-scripts-are-executable",
                "check-shebang-scripts-are-executable skipped: "
                "'style-ok: sourced-fragment' waiver in '%s'" % path)
            continue
        if _INSTALLED_MODULE.search(path):
            yield model.note(
                "check-shebang-scripts-are-executable",
                "check-shebang-scripts-are-executable skipped: '%s' is an "
                "imported package module" % path)
            continue
        shebang_files.append(path)
    ## these two read the INDEX filemode via 'git ls-files --stage' AND open the
    ## file on disk, so they are git-aware and run in the real repo -- and only on
    ## paths that EXIST there: a file present only in the index (its working copy
    ## deleted) has no on-disk content for them to read, exactly as before the blob
    ## migration (the secret scanners above still judge its blob via the mirror).
    on_disk = [p for p in shebang_files if os.path.lexists(_abs(base_cwd, p))]
    yield from _run_hook("check-shebang-scripts-are-executable", [],
                         on_disk, base_cwd)
    exec_on_disk = [p for p in lists["exec_text"]
                    if os.path.lexists(_abs(base_cwd, p))]
    yield from _run_hook("check-executables-have-shebangs", [],
                         exec_on_disk, base_cwd)
    ## Broken-symlink check. Working-tree mode: the real hook over the tree. Blob
    ## mode: git-native tree resolution (no mirror), so the STAGED link is judged
    ## with no relative-escape / chain-depth / worktree-split edges.
    if source_rev is None:
        yield from _run_hook("check-symlinks", [], lists["symlink"], base_cwd)
    else:
        yield from _broken_staged_symlinks(paths, source_rev, base_cwd)

    ## type by extension, content-reading -> content_cwd:
    yield from _run_hook("check-yaml", [], lists["yaml"], content_cwd)
    yield from _run_hook("check-json", [], lists["json"], content_cwd)
    yield from _run_hook("check-toml", [], lists["toml"], content_cwd)
    yield from _run_hook("check-xml", [], lists["xml"], content_cwd)
    yield from _run_hook("check-ast", [], lists["python"], content_cwd)
    yield from _run_hook("check-builtin-literals", [], lists["python"],
                         content_cwd)
    yield from _run_hook("debug-statement-hook", [], lists["python"],
                         content_cwd)

    ## pretty-format-json REWRITES (and key-sorts) -- skip an app-managed
    ## settings file (check-json already validated its SYNTAX).
    json_fmt = []
    for path in lists["json"]:
        if _APP_MANAGED_JSON.search(path):
            yield model.note(
                "pretty-format-json",
                "pretty-format-json skipped: '%s' is an app-managed settings "
                "file (syntax still checked by check-json; the app owns its "
                "format)" % path)
            continue
        json_fmt.append(path)
    yield from _run_fixer("pretty-format-json", json_fmt, content_cwd)
    yield from _run_fixer("requirements-txt-fixer", lists["req"], content_cwd)
