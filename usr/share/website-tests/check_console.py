#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CLI shim: the runtime console-error / pageerror / CSP-violation gate lives in the
## importable core `dist_ai.webcheck.console` (shared with mw-static-generator). This is
## the family-sites entry: it serves each site checkout from a localhost mount and loads
## every page in headless chromium. SKIPs (exit 77) when Playwright/chromium is absent,
## like the sibling browser lanes, so the launcher delegates it to the sandbox.

import os
import sys

## Make `dist_ai.webcheck` importable from a CHECKOUT (CI sibling-checkout) as well as
## when INSTALLED; same inline idiom site-generate uses, no env var to remember.
_dist_packages = os.path.normpath(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'lib', 'python3', 'dist-packages'))
if os.path.isdir(_dist_packages) and _dist_packages not in sys.path:
    sys.path.insert(0, _dist_packages)

from dist_ai.webcheck import console as _console

if __name__ == '__main__':
    sys.exit(_console.check_roots(sys.argv[1:]))
