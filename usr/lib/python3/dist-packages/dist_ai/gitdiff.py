## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Enumerate the files the engine should examine, and build a FileContext for
each with the RIGHT path spelling.

A rule's self-exemption and its .gitattributes lookup key on the path, so a file
enumerated from the index is named repo-RELATIVE (the same spelling the gate
passes), while its bytes are read from the absolute path. A file named directly
on the command line keeps the spelling the caller gave (relative stays relative,
so a 'usr/bin/pre-push-static' argument still matches its exemption)."""

import os
import subprocess

from dist_ai import bash_ast
from dist_ai import context as ctxmod


class StagedDiscoveryError(Exception):
    """git could not enumerate the staged set -- distinct from 'nothing staged'
    (a false green if mistaken for it)."""


def _repo_root():
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, check=True)
    return os.fsdecode(out.stdout.strip())


def staged_pairs():
    """(abspath, relpath) for every staged (ACMRT) file. relpath is git's
    repo-relative name; abspath is it joined onto the repo root. Raises
    StagedDiscoveryError on a git failure."""
    try:
        names = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRT",
             "-z"],
            capture_output=True, check=True).stdout
        root = _repo_root()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StagedDiscoveryError(str(exc)) from exc
    return [
        (os.path.join(root, os.fsdecode(name)), os.fsdecode(name))
        for name in names.split(b"\0") if name
    ]


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
