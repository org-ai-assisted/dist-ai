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
import os
import re
import shutil
import subprocess

from dist_ai import engine
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


def warn_worktree_skew(names, ref, base_cwd):
    """Advisory NOTE (never a FAIL) when a checked path's working tree diverges
    from what this mode judged. REF is the diff target: '' for the staged index,
    a commit-ish for a range. Index mode judged the STAGED BLOB, so the note is
    purely informational (the working tree carries edits not yet staged); a range
    read the working tree off disk against REF's commits, so its divergence means
    the check did not see REF's exact bytes -- without the note that is silent."""
    if ref is None:
        return
    for name in names:
        args = ["diff", "--quiet"]
        if ref:
            args.append(ref)
        args += ["--", name]
        if _git(args, base_cwd).returncode != 0:
            hint = ("has unstaged working-tree edits; the gate judged the staged "
                    "blob (the exact committed content)" if not ref
                    else "differs from %s; the check ran against the working "
                    "tree" % ref)
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
    ## (NUL-delimited), not C-quoted -- a quoted '"caf\303\251.sh"' would fail
    ## the extension test and the open (same care the changelog enumeration takes).
    out = _git(["-c", "core.quotePath=false", "ls-files", "--others",
                "--exclude-standard", "-z"], base_cwd)
    if out.returncode != 0:
        return
    for name in out.stdout.split("\0"):
        if name and _is_shell_file(os.path.join(base_cwd, name), name):
            yield model.note(
                "untracked",
                "untracked shell file NOT checked -- 'git add' it to gate it: "
                "'%s'" % name, name)


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
