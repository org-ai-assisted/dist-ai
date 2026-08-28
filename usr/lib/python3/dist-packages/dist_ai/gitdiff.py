## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Enumerate the files the engine should examine, and build a FileContext for
each with the RIGHT path spelling.

A rule's self-exemption and its .gitattributes lookup key on the path, so a file
enumerated from the index is named repo-RELATIVE (the same spelling the gate
passes), while its bytes are read from the absolute path. A file named directly
on the command line keeps the spelling the caller gave (relative stays relative,
so a 'usr/bin/dist-ai-style' argument keeps its exact repo-relative spelling)."""

import os
import subprocess

from dist_ai import bash_ast
from dist_ai import context as ctxmod


class StagedDiscoveryError(Exception):
    """git could not enumerate the changed set -- distinct from 'nothing changed'
    (a false green if mistaken for it)."""


class BaseRefError(Exception):
    """A base ref the caller named does not resolve. Exit 2, never a silent skip
    (an unresolvable base would otherwise diff an empty range and pass)."""


def _repo_root():
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, check=True)
    return os.fsdecode(out.stdout.strip())


def _head_exists():
    """True if HEAD resolves -- false in a repo with no commit yet, where a
    diff against HEAD would error."""
    return subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "HEAD"],
        capture_output=True).returncode == 0


def resolve_base(base_ref):
    """Verify BASE_REF resolves to a commit; raise BaseRefError if not. The
    caller turns that into exit 2 with the 'pass a base' hint, exactly as the
    bash gate did -- an unresolvable base must never quietly gate nothing."""
    ok = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", base_ref],
        capture_output=True).returncode == 0
    if not ok:
        raise BaseRefError(base_ref)


def merge_base(base_ref):
    """The merge base of BASE_REF and HEAD -- the fork point a range is measured
    from. range_pairs diffs BASE_REF...HEAD (triple-dot = merge-base..HEAD), so
    the 'is this file new in the range' test (added-large-files) must key on the
    merge base too, NOT base_ref's current tip: a path the base branch added
    after the fork is not present at the fork, so it is genuinely new here.
    Falls back to BASE_REF when there is no common ancestor (unrelated
    histories), the same ref a two-dot range would then use."""
    out = subprocess.run(
        ["git", "merge-base", base_ref, "HEAD"], capture_output=True)
    if out.returncode != 0:
        return base_ref
    return os.fsdecode(out.stdout.strip()) or base_ref


def _diff_names(args):
    """Run 'git -c core.quotePath=false diff -z --name-only --diff-filter=ACMRT
    ARGS' and return the repo-relative names. quotePath=false + -z keep a path
    with a tab / newline / byte >= 0x80 one intact record (a C-quoted name
    matches no disk path and would be silently skipped). Raises
    StagedDiscoveryError on a git failure."""
    try:
        out = subprocess.run(
            ["git", "-c", "core.quotePath=false", "diff", "-z",
             "--name-only", "--diff-filter=ACMRT"] + args,
            capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StagedDiscoveryError(str(exc)) from exc
    return [os.fsdecode(name) for name in out.split(b"\0") if name]


def _pairs(names, root):
    return [(os.path.join(root, name), name) for name in names]


def staged_pairs(all_tracked=False, pathspecs=None):
    """(abspath, relpath) for the staged (ACMRT) files. ALL_TRACKED diffs the
    working tree against HEAD (what 'git commit --all' records) instead of the
    index -- but only when HEAD exists, else the initial commit has nothing to
    diff against and the index is the whole change. PATHSPECS (a list) restricts
    the set with git's own pathspec matching, so a directory / glob behaves
    exactly as in the commit being gated. Raises StagedDiscoveryError on a git
    failure."""
    if all_tracked and _head_exists():
        args = ["HEAD"]
    else:
        args = ["--cached"]
    if pathspecs:
        args += ["--"] + list(pathspecs)
    names = _diff_names(args)
    return _pairs(names, _repo_root())


def range_pairs(base_ref):
    """(abspath, relpath) for the files changed in BASE_REF...HEAD (the push /
    union mode: everything the range introduces relative to the merge base).
    Raises StagedDiscoveryError on a git failure."""
    names = _diff_names(["%s...HEAD" % base_ref])
    return _pairs(names, _repo_root())


def given_pairs(paths):
    """(abspath, relpath) for each command-line path (a directory is walked).
    relpath keeps the caller's spelling so a path-keyed exemption still matches;
    abspath is where the bytes are read. Raises FileNotFoundError on a missing
    path (a loud error, never a silent skip)."""
    return [(os.path.abspath(path), path) for path in bash_ast.walk_files(paths)]


def contexts(pairs):
    """FileContexts for (abspath, relpath) PAIRS, skipping symlinks / non-regular
    / undecodable files (from_disk returns None)."""
    out = []
    for abspath, relpath in pairs:
        ctx = ctxmod.FileContext.from_disk(abspath, relpath=relpath)
        if ctx is not None:
            out.append(ctx)
    return out


def _index_entry(relpath, root):
    """(mode, sha) for RELPATH's stage-0 index entry, or (None, None) if it has
    none (dropped from the index, or unmerged). '-z' keeps a path with an odd
    byte one record."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "--stage", "-z", "--", relpath],
            cwd=root, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None, None
    record = out.split(b"\0", 1)[0]
    if not record:
        return None, None
    meta = record.split(b"\t", 1)[0].split()
    if len(meta) < 2:
        return None, None
    return os.fsdecode(meta[0]), os.fsdecode(meta[1])


def staged_blob_contexts(pairs):
    """FileContexts whose bytes are the STAGED BLOB (index, stage 0) content --
    so --staged gates exactly what a commit would record, NEVER the working tree,
    which may differ (a working copy overwritten after staging must not hide a
    violation staged in the index, nor a working-tree edit trip a check of the
    clean staged blob). A symlink (mode 120000) or gitlink (160000) index entry
    is skipped, mirroring contexts()' skip of a symlink on disk. abspath is kept
    (the index/attrs git queries need the in-repo path); undecodable bytes ->
    source None (the byte-level R-001 floor still reads raw)."""
    root = _repo_root()
    out = []
    for abspath, relpath in pairs:
        mode, sha = _index_entry(relpath, root)
        if sha is None or mode in ("120000", "160000"):
            continue
        try:
            raw = subprocess.run(
                ["git", "cat-file", "blob", sha],
                cwd=root, capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            continue
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            source = None
        out.append(ctxmod.FileContext(relpath, source, abspath=abspath, raw=raw))
    return out
