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
