## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shared CLI helpers for the standalone webcheck lanes (extlinks, secrets, lighthouse, site)."""

import os
import sys
from typing import List


def require_existing_dirs(roots: List[str], lane: str) -> List[str]:
    """Return abspath(root) for every NAMED root, or EXIT 1 (loud) naming any that does not
    resolve to a directory.

    A mistyped / non-resolving root is a FAILURE, never silently dropped (which, if another root
    survived, would let the run exit 0 -- a typo'd root 'passing') and never a SKIP. That is the
    silent-green class "no unauthorized skips" forbids: the operator asked for a specific site, so
    not finding it is a failure, not something to quietly test-around. Callers handle the
    genuinely-no-roots-requested case (empty argv) themselves."""
    missing = [r for r in roots if not os.path.isdir(r)]
    if missing:
        sys.stderr.write("%s: FATAL: named site root(s) do not resolve to a directory: %s -- a "
                         "mistyped root is a failure, not a silent skip\n"
                         % (lane, ", ".join(missing)))
        raise SystemExit(1)
    return [os.path.abspath(r) for r in roots]


# Generator build-output dir names: their basename names the OUTPUT, not the site, so a per-site
# baseline keyed on it ("cspell-baseline-_site.txt") neither identifies the site nor stays unique
# across generators. A site gated at its build output (computer-security-research.github.io/_site)
# is named by its parent (the repo) instead. Deliberately UNDERSCORE-PREFIXED only: a plain name
# like "build"/"dist"/"site" can be a real repository name, so including it would misname that
# repo's baseline after its parent. Keep this set in sync with webcheck-cspell-sandbox.
_BUILD_DIR_NAMES = frozenset({"_site", "_build"})


def site_name(root: str) -> str:
    """Stable, human-identifiable site name for a root -- the basename that names its per-site
    baseline (cspell/secrets) and labels its gate output. Operates on the lexical absolute path so
    the Bash driver (realpath --canonicalize-missing --no-symlinks) and this agree byte-for-byte.

    Normally the root's basename (the repo dir). But when the root is a generator's build output
    (an underscore-prefixed dir like '_site'), fall back to the parent directory's name so the
    baseline is identifiable and cannot collide with another generator's '_site'."""
    norm = os.path.normpath(os.path.abspath(root))
    base = os.path.basename(norm)
    if base in _BUILD_DIR_NAMES:
        parent = os.path.basename(os.path.dirname(norm))
        if parent:
            return parent
    return base


def require_distinct_site_names(roots: List[str], lane: str) -> None:
    """For the baseline-keyed lanes (cspell, secrets): EXIT 1 (loud) if two roots resolve to the
    SAME site_name -- one site's accepted baseline would then mask the other's findings (a masked
    secret is the dangerous case) -- or if a name is itself a build-dir token, meaning no site
    could be identified. Never a silently shared or misdirected baseline."""
    seen: dict = {}
    for r in roots:
        name = site_name(r)
        if name in _BUILD_DIR_NAMES:
            sys.stderr.write("%s: FATAL: cannot derive a site name from %r (a build-output dir with "
                             "no identifying parent) -- pass the repository root\n" % (lane, r))
            raise SystemExit(1)
        if name in seen:
            sys.stderr.write("%s: FATAL: roots %r and %r both resolve to site name %r -- one site's "
                             "baseline would mask the other\n" % (lane, seen[name], r, name))
            raise SystemExit(1)
        seen[name] = r
