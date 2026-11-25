## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Repo-level gate checks -- the ones that judge a git RANGE or the whole
changed set, not one file's parse tree: the commit-message non-ASCII floor, the
genmkfile-owned debian/changelog convention, and the advisory comment audit.
The per-file AST / text / external rules live in the engine; these need git.

Every check yields model.Finding, so the gate renders a range finding exactly
like a per-file one. base_cwd is the repo root (paths are repo-relative there)."""

import collections
import functools
import math
import os
import re
import shutil
import stat
import subprocess

from dist_ai import bash_ast
from dist_ai import engine
from dist_ai import gitdiff
from dist_ai import model

_AUTOBUMP_SUBJECT = "bumped changelog version"
_MANUAL_OK = re.compile(
    r"^[ \t]*changelog-manual-ok:[ \t]*[^ \t]", re.IGNORECASE | re.MULTILINE)

_GitResult = collections.namedtuple("_GitResult", ["returncode", "stdout"])


def _git(args, base_cwd, check=False):
    """Run git, decoding stdout with errors='replace' so a non-UTF-8 commit
    body / subject / path never crashes the gate (git echoes those bytes back).
    A rule that needs the exact bytes -- R-001 over a message -- reads them raw,
    not through this."""
    proc = subprocess.run(
        ["git"] + args, capture_output=True, cwd=base_cwd, check=check)
    return _GitResult(proc.returncode, proc.stdout.decode("utf-8", "replace"))


def hostile_attributes(names, base_cwd):
    """The path of the first NON-REGULAR attribute file among the repo root, the
    ancestor directories of the changed NAMES, and '.git/info/attributes', or
    None. A FIFO, socket, device, or symlink attribute file makes git BLOCK the
    instant it reads attributes -- diff, status, check-attr, inside the gate OR a
    git-aware hook -- an unbounded hang no per-subprocess timeout fully closes (a
    killed hook's git grandchild keeps the pipe open). os.lstat never blocks, so
    we detect it up front and refuse fast (fail closed) instead of wedging.
    Ancestor dirs only: that is exactly the set git consults for the scanned files.

    Best-effort residuals (non-PR-reachable, so left for the caller's own repo):
    a NESTED '.gitattributes' in --staged --all is read during ENUMERATION (a
    working-tree scan) before the caller's pre-flight, so only the root is caught
    up front there; a non-standard git dir (submodule/worktree '.git' file) is not
    resolved. Neither can be planted by untrusted PR content on the authoritative
    --staged/--range path."""
    base = base_cwd or os.getcwd()
    dirs = {""}
    for name in names:
        parts = os.path.normpath(name).split(os.sep)[:-1]
        for i in range(len(parts) + 1):
            dirs.add(os.sep.join(parts[:i]))
    candidates = [os.path.join(base, rel, ".gitattributes") for rel in sorted(dirs)]
    ## $GIT_DIR/info/attributes is a SEPARATE attribute source git reads on every
    ## attribute lookup; a FIFO there hangs even --staged. Standard layout only.
    candidates.append(os.path.join(base, ".git", "info", "attributes"))
    for candidate in candidates:
        try:
            mode = os.lstat(candidate).st_mode
        except OSError:
            continue
        if not stat.S_ISREG(mode):
            return os.path.relpath(candidate, base)
    return None


def warn_worktree_skew(names, ref, base_cwd):
    """Advisory NOTE (never a FAIL) when a checked path's working tree diverges
    from the git OBJECT this mode judged. REF is the diff target: '' for the
    staged index (the object about to be committed), a commit-ish (HEAD) for a
    range (the pushed blob). The note is purely informational -- the working tree
    carries edits not in that object; without it the divergence is silent."""
    if ref is None:
        return
    for name in names:
        args = ["diff", "--quiet"]
        if ref:
            args.append(ref)
        args += ["--", name]
        if _git(args, base_cwd).returncode != 0:
            hint = ("has unstaged working-tree edits; the gate judged the staged "
                    "blob (the exact staged/index content)" if not ref
                    else "differs from %s; the gate judged the %s blob (the "
                    "exact pushed content)" % (ref, ref))
            yield model.note("worktree-skew", "'%s' %s" % (name, hint), name)


def _is_changelog(path):
    return path == "debian/changelog" or path.endswith("/debian/changelog")


def _is_changelog_family(path):
    return _is_changelog(path) or path == "changelog.upstream" \
        or path.endswith("/changelog.upstream")


def _changelog_verdict(touches, only_family, subject, body):
    """True if a commit that TOUCHES debian/changelog is permitted: a genmkfile
    auto-bump (exact subject + family-only diff) or a 'Changelog-manual-ok:'
    override. False -> the manual-edit finding must fire."""
    if not touches:
        return True
    if subject == _AUTOBUMP_SUBJECT and only_family:
        return True
    return bool(_MANUAL_OK.search(body))


def check_changelog_range(base_ref, base_cwd):
    """FAIL for each commit in BASE_REF..HEAD that hand-edits the
    genmkfile-owned debian/changelog without an override. Each commit is judged
    on its own (an auto-bump and a feature commit in one range do not taint each
    other). '-c' takes the combined diff so an evil-merge edit is seen."""
    revs = _git(["rev-list", "--reverse", "%s..HEAD" % base_ref], base_cwd)
    if revs.returncode != 0:
        ## A failed enumeration is NOT "no changelog edits" -- the check did not
        ## run. Report it, so a git error cannot read as a clean changelog pass.
        yield model.fail(
            "changelog manual-edit",
            "could not enumerate %s..HEAD; the changelog check did not run"
            % base_ref, "debian/changelog")
        return
    for sha in revs.stdout.split():
        names = _git(
            ["-c", "core.quotePath=false", "diff-tree", "--no-commit-id",
             "--name-only", "-z", "-c", "-r", sha], base_cwd).stdout
        changed = [name for name in names.split("\0") if name]
        touches = any(_is_changelog(name) for name in changed)
        if not touches:
            continue
        only_family = all(_is_changelog_family(name) for name in changed)
        subject = _git(["log", "-1", "--format=%s", sha], base_cwd).stdout \
            .rstrip("\n")
        body = _git(["log", "-1", "--format=%B", sha], base_cwd).stdout
        if not _changelog_verdict(True, only_family, subject, body):
            yield model.fail(
                "changelog manual-edit",
                "commit %s edits debian/changelog (genmkfile-owned); bump via "
                "'genmkfile deb-chl-bumpup-major', or add a "
                "'Changelog-manual-ok: <reason>' trailer to the commit message"
                % sha, "debian/changelog")


def check_changelog_staged(paths, message_file, base_cwd):
    """Staged counterpart: no commit yet, so judge the staged set as one pending
    commit. Without a --message-file the pending subject/trailer is unreadable,
    so defer to push/CI (a NOTE) rather than fail blindly."""
    touches = any(_is_changelog(path) for path in paths)
    if not touches:
        return
    only_family = all(_is_changelog_family(path) for path in paths)
    if not message_file:
        yield model.note(
            "changelog manual-edit",
            "staged mode: debian/changelog staged but no --message-file; "
            "deferring changelog-trailer check to push/CI")
        return
    try:
        with open(message_file, encoding="utf-8", errors="replace") as handle:
            body = handle.read()
    except OSError:
        body = ""
    subject = body.split("\n", 1)[0]
    if not _changelog_verdict(True, only_family, subject, body):
        yield model.fail(
            "changelog manual-edit",
            "staged debian/changelog edit (genmkfile-owned); bump via "
            "'genmkfile deb-chl-bumpup-major', or add a "
            "'Changelog-manual-ok: <reason>' trailer to the commit message",
            "debian/changelog")


def check_message(base_ref, staged_mode, message_file, base_cwd):
    """The commit-message non-ASCII (R-001) floor. Staged: the pending message
    is the --message-file (a NOTE if absent -- there is no message to read).
    Range: the base..HEAD commit-range message. Same engine rule the tree files
    use, over the raw bytes."""
    if staged_mode:
        if not message_file:
            yield model.note(
                "commit-message R-001",
                "staged mode: no --message-file; skipping commit-message "
                "R-001 check")
            return
        try:
            with open(message_file, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            yield model.fail("commit-message R-001",
                             "cannot read --message-file: %s" % exc,
                             message_file)
            return
        yield from engine.detect_message(raw)
        return
    ## RAW bytes, not _git's replace-decoded string: R-001 must see the actual
    ## non-ASCII byte a message carries, not a U+FFFD substitution of it.
    proc = subprocess.run(
        ["git", "log", "%s..HEAD" % base_ref, "--format=%B%n"],
        capture_output=True, cwd=base_cwd)
    if proc.stdout:
        yield from engine.detect_message(proc.stdout)


_SHELL_EXT = (".sh", ".bsh", ".bash")
_SHELL_SHEBANG = re.compile(r"^#!.*\b(?:ba|da)?sh\b")


def _is_shell_file(abspath, name):
    if name.endswith(_SHELL_EXT):
        return True
    ## Read the shebang WITHOUT hanging: O_NOFOLLOW refuses a symlink (a link to
    ## /dev/zero would never yield a newline), O_NONBLOCK makes a fifo/device
    ## read return at once instead of blocking. Only a plain readable head is
    ## inspected; anything else is simply not a shell file we can name.
    try:
        fd = os.open(abspath, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        head = os.read(fd, 256)
    except OSError:
        return False
    finally:
        os.close(fd)
    return bool(_SHELL_SHEBANG.match(head.decode("utf-8", "replace")))


def check_untracked(base_cwd):
    """Advisory NOTE for each UNTRACKED shell file -- a new script not yet 'git
    add'ed is invisible to the staged/range set, so the gate would silently not
    check it. Naming it turns a forgotten 'git add' from a silent gap into a
    visible note. Never a FAIL (an untracked file is not part of this change)."""
    ## '-z' + quotePath=false: a name with a space / byte >= 0x80 is emitted RAW
    ## (NUL-delimited), not C-quoted. Decode the RAW bytes with surrogateescape
    ## (os.fsdecode), NOT _git's errors='replace': a non-UTF-8 filename byte must
    ## round-trip back to the real path for the open()/shebang check, else the
    ## U+FFFD-mangled path does not exist, _is_shell_file's open fails, and the
    ## advisory silently never fires for exactly the file it exists to surface.
    try:
        proc = subprocess.run(
            ["git", "-c", "core.quotePath=false", "ls-files", "--others",
             "--exclude-standard", "-z"], capture_output=True, cwd=base_cwd)
    except OSError:
        return
    if proc.returncode != 0:
        return
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        name = os.fsdecode(raw)
        if not _is_shell_file(os.path.join(base_cwd, name), name):
            continue
        ## backslashreplace so a lone-surrogate byte prints safely to stderr;
        ## then escape any CONTROL char (ESC, CR/LF, ...) so a crafted untracked
        ## filename cannot inject terminal control sequences or forge log lines
        ## when this note is printed (CWE-150).
        display = os.fsencode(name).decode("utf-8", "backslashreplace")
        display = "".join(
            ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
            for ch in display)
        yield model.note(
            "untracked",
            "untracked shell file NOT checked -- 'git add' it to gate it: "
            "'%s'" % display, display)


_INDENT_RULE = "R-003"


def _added_shell_names(names, base_ref, staged_mode, base_cwd):
    """The subset of NAMES this change ADDS as a brand-new path (git status 'A'),
    with rename detection on (-M) so a renamed LEGACY file is an R, not an A, and
    is never forced to reindent -- a pure relocation is not new code (R-152). Copy
    detection is OFF on purpose: a copy is a second new file and IS gated like any
    new file. Keyed on git's own diff, not a 'cat-file -e base:path' existence
    test, exactly so a rename is excluded.
    Staged mode diffs the index with '--cached' alone (no explicit HEAD): with a
    HEAD it compares index vs HEAD; on an UNBORN branch (initial commit, no HEAD)
    it compares index vs the empty tree, so a new file is status A and IS gated --
    '--cached HEAD' would instead exit 128 there and silently gate nothing."""
    if staged_mode:
        spec = ["--cached"]
    else:
        spec = ["%s...HEAD" % base_ref]
    try:
        out = subprocess.run(
            ["git", "-c", "core.quotePath=false", "diff", "-M",
             "--diff-filter=A", "--name-only", "-z"] + spec,
            capture_output=True, cwd=base_cwd)
    except OSError:
        return []
    if out.returncode != 0:
        return []
    added = {os.fsdecode(raw) for raw in out.stdout.split(b"\0") if raw}
    return [name for name in names if name in added]


def _indent_unit(tree):
    """The file's block-indent step from the shfmt AST, or None when
    indeterminate. The indent is the leading column of each line that opens a
    STRUCTURAL unit -- read straight off the existing parse, NOT by scanning raw
    lines (never reinvent a bash parser). Two kinds of structural line, together
    covering every indented line that is NOT a statement body:
      - statement starts (bash_ast.iter_stmts);
      - case-arm patterns (CaseClause Items), which are indented but are NOT Stmt
        nodes -- under switch-case-indent (shfmt -ci) they hold the ONLY line at
        their level (bodies sit one level deeper), so missing them reads a
        top-level case as indent 4 and false-FAILs a clean 2-space file.
    Keying on structural starts is what makes it correct: a line-continuation or
    aligned argument is mid-statement, never a structural start, so it never
    contributes a spurious width. GCD over the per-line starts gives the step;
    several starts sharing a line (a ';' chain, 'a|b)' patterns) count once at the
    line's first. Unit < 2 (tabs, mixed) -> None (pass). Failure mode is always a
    MISS, never a false FAIL."""
    if tree is None:
        return None
    first_col = {}

    def record(pos):
        line = (pos or {}).get("Line")
        col = (pos or {}).get("Col")
        if not line or not col:
            return
        if line not in first_col or col < first_col[line]:
            first_col[line] = col

    for stmt in bash_ast.iter_stmts(tree):
        record(stmt.get("Pos"))
    for case in bash_ast.nodes_of_type(tree, "CaseClause"):
        for item in case.get("Items") or []:
            for pattern in item.get("Patterns") or []:
                record(pattern.get("Pos"))
    indents = [col - 1 for col in first_col.values() if col > 1]
    if not indents:
        return None
    unit = functools.reduce(math.gcd, indents, 0)
    return unit if unit >= 2 else None


def check_added_file_indent(names, base_ref, staged_mode, base_cwd, source_rev):
    """FAIL a NEWLY-ADDED shell file whose indentation step is not 2 (R-003).
    New-file-only BY DESIGN: existing 2- and 3-space scripts are left untouched
    (R-152), so this only ever judges a file this change introduces -- it never
    reindents, and a direct-file run (no base_ref) is skipped. Waive a new file
    that must match 3-space siblings with '## style-ok: R-003' (or '## style-ok:
    indent-unit'). Python indentation is black's job (4-space), not this check."""
    if not base_ref or not base_cwd:
        return
    added = _added_shell_names(names, base_ref, staged_mode, base_cwd)
    if not added:
        return
    pairs = [(os.path.join(base_cwd, name), name) for name in added]
    if source_rev is None:
        contexts = gitdiff.contexts(pairs)
    else:
        contexts = gitdiff.blob_contexts(
            pairs, None if source_rev == "" else source_rev)
    for ctx in contexts:
        if ctx is None or not ctx.is_shell or not ctx.source:
            continue
        if ctx.has_rule_override(_INDENT_RULE) or ctx.has_waiver("indent-unit"):
            continue
        unit = _indent_unit(ctx.tree)
        if unit is None or unit == 2:
            continue
        yield model.fail(
            _INDENT_RULE,
            "%s: new shell file indents with %d spaces; new files use 2-space "
            "indentation (existing 2-/3-space files are left as-is). Reindent to "
            "2, or waive with '## style-ok: %s' if it must match 3-space "
            "siblings." % (_INDENT_RULE, unit, _INDENT_RULE), ctx.path)


def _find_comments_audit(tool_dir):
    if tool_dir:
        cand = os.path.join(tool_dir, "comments-audit")
        if os.access(cand, os.X_OK):
            return cand
    return shutil.which("comments-audit")


def comments_audit(paths, base_cwd, tool_dir):
    """R-151 comment auditor -- ADVISORY only, never a FAIL. Surfaces
    comment-paraphrases-code candidates for human review (the heuristic has
    false positives, so it cannot gate)."""
    auditor = _find_comments_audit(tool_dir)
    if auditor is None:
        yield model.note(
            "R-151 comment-audit",
            "comments-audit not found; skipping the R-151 comment advisory")
        return
    if not paths:
        return
    try:
        out = subprocess.run(
            [auditor, "--files"] + list(paths),
            capture_output=True, text=True, cwd=base_cwd).stdout
    except OSError:
        return
    if out.strip() and "0 candidate findings" not in out:
        yield model.note(
            "R-151 comment-audit",
            "candidates (ADVISORY -- review, not a gate failure):\n"
            + out.rstrip("\n"))
