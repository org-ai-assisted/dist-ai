#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CLI shim: the tab-preview thumbnail CENTERING browser lane lives in the
## importable core `dist_ai.webcheck.tabthumb` (shared with mw-static-generator so
## neither side reinvents the measurement). This file is the stable entry point.

import os
import sys

## Make `dist_ai.webcheck` importable from a CHECKOUT (CI sibling-checkout) as well as
## when INSTALLED; same inline idiom site-generate uses, no env var to remember.
_dist_packages = os.path.normpath(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'lib', 'python3', 'dist-packages'))
if os.path.isdir(_dist_packages) and _dist_packages not in sys.path:
    sys.path.insert(0, _dist_packages)

from dist_ai.webcheck import tabthumb as _tabthumb

if __name__ == '__main__':
    sys.exit(_tabthumb.main())
