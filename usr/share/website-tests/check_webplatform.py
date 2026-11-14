#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CLI shim: the FUNCTIONAL Speculation Rules + View Transitions gate lives in the importable
## core `dist_ai.webcheck.webplatform`. This is the family/CSR entry: it serves each site
## checkout from a localhost mount and, in real chromium over CDP, proves the inline
## speculationrules block is accepted (not CSP-blocked) + prefetches, and the @view-transition
## rule is applied + a same-origin nav runs clean. SKIPs (exit 77) when Playwright/chromium is
## absent, like the sibling browser lanes, so the launcher delegates it to the sandbox.

import os
import sys

## Make `dist_ai.webcheck` importable from a CHECKOUT (CI sibling-checkout) as well as
## when INSTALLED; same inline idiom the sibling shims use, no env var to remember.
_dist_packages = os.path.normpath(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'lib', 'python3', 'dist-packages'))
if os.path.isdir(_dist_packages) and _dist_packages not in sys.path:
    sys.path.insert(0, _dist_packages)

from dist_ai.webcheck import webplatform as _webplatform

if __name__ == '__main__':
    sys.exit(_webplatform.check_roots(sys.argv[1:]))
