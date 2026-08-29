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


def _tree_entries(rev, root):
    """{relpath: (mode, sha)} for every blob at REV -- None -> the stage-0 INDEX,
    a commit-ish -> that tree. The WHOLE listing is taken in one call and keyed by
    exact path, so no per-file path ever reaches a git argument: a name that is
    pathspec MAGIC (':(exclude)x') or collides with the ':<stage>:<path>' /
    'REV:path' object grammar ('0:x') cannot make a lookup error out (swallowed ->
    unscanned) or resolve to the wrong object. quotePath=false + '-z' keep an odd
    -byte path one intact record. Raises StagedDiscoveryError on a git failure."""
    if rev is None:
        cmd = ["git", "-c", "core.quotePath=false", "ls-files", "--stage", "-z"]
        sha_field = 1  ## 'mode sha stage \t path'
    else:
        cmd = ["git", "-c", "core.quotePath=false", "ls-tree", "-r", "-z", rev]
        sha_field = 2  ## 'mode type sha \t path'
    try:
        out = subprocess.run(
            cmd, cwd=root, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StagedDiscoveryError(str(exc)) from exc
    entries = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _tab, path = record.partition(b"\t")
        fields = meta.split()
        if len(fields) <= sha_field:
            continue
        entries[os.fsdecode(path)] = (
            os.fsdecode(fields[0]), os.fsdecode(fields[sha_field]))
    return entries


def blob_contexts(pairs, rev=None):
    """FileContexts whose bytes are the git blob at REV -- None -> the stage-0
    INDEX (what a commit records), a commit-ish like 'HEAD' -> that tree (what a
    push carries) -- NEVER the working tree, which may have diverged (a working
    copy overwritten after commit/stage must not hide a violation in the object
    that ships, nor a working-tree edit trip a check of the clean object). A
    symlink (mode 120000) or gitlink (160000) entry is skipped, mirroring
    contexts()' skip of a symlink on disk. The blob is fetched BY SHA (never a
    ':path' object spec), so an adversarial filename cannot evade the scan. abspath
    is kept (the index/attrs git queries need the in-repo path); undecodable bytes
    -> source None (the byte-level R-001 floor still reads raw)."""
    root = _repo_root()
    entries = _tree_entries(rev, root)
    out = []
    for abspath, relpath in pairs:
        mode, sha = entries.get(relpath, (None, None))
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
        ## source_rev is the git tree the bytes came from: '' for the index,
        ## the commit-ish for a range -- so classification (.gitattributes) and
        ## any sibling lookup key on the SAME tree, not the working tree.
        out.append(ctxmod.FileContext(
            relpath, source, abspath=abspath, raw=raw,
            source_rev="" if rev is None else rev))
    return out
