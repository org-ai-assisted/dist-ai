## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Repo-level gate checks -- the ones that judge a git RANGE or the whole
changed set, not one file's parse tree: the commit-message non-ASCII floor, the
genmkfile-owned debian/changelog convention, and the advisory comment audit.
The per-file AST / text / external rules live in the engine; these need git.

Every check yields model.Finding, so the gate renders a range finding exactly
like a per-file one. base_cwd is the repo root (paths are repo-relative there)."""

import os
import re
import shutil
import subprocess

from dist_ai import engine
from dist_ai import model

_AUTOBUMP_SUBJECT = "bumped changelog version"
_MANUAL_OK = re.compile(
    r"^[ \t]*changelog-manual-ok:[ \t]*[^ \t]", re.IGNORECASE | re.MULTILINE)


def _git(args, base_cwd, check=False):
    return subprocess.run(
        ["git"] + args, capture_output=True, text=True, cwd=base_cwd,
        check=check)


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
    msg = _git(["log", "%s..HEAD" % base_ref, "--format=%B%n"], base_cwd).stdout
    if msg:
        yield from engine.detect_message(msg.encode("utf-8"))


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
