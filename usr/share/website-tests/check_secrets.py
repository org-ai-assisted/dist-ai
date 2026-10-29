#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CLI shim: the secret-scan of the built site tree lives in the importable core
## `dist_ai.webcheck.secrets` (delegates to gitleaks, offline + read-only). The bytes
## of a static site are public, so a leaked key/token in them is irreversible -- this
## gate runs for EVERY policy (family, csr, wiki). gitleaks is a hard dependency
## (debian/control Depends); its absence is a loud FATAL in the core, never a skip.

import os
import sys

## Make `dist_ai.webcheck` importable from a CHECKOUT (CI sibling-checkout) as well as
## when INSTALLED; same inline idiom site-generate / check_svg_safety use, no env var to remember.
_dist_packages = os.path.normpath(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'lib', 'python3', 'dist-packages'))
if os.path.isdir(_dist_packages) and _dist_packages not in sys.path:
    sys.path.insert(0, _dist_packages)

from dist_ai.webcheck import secrets as _secrets

if __name__ == '__main__':
    sys.exit(_secrets.main(sys.argv[1:]))
