#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CLI shim: the SVG active-content safety scan lives in the importable core
## `dist_ai.webcheck.svg_safety` (shared with mw-static-generator). For the family
## Pages sites the SVGs are first-party favicons, so this runs in-process in the static
## lane (defusedxml already guards XXE/entity-bomb); mw-static runs the same logic
## CONFINED against untrusted wiki SVG.

import os
import sys

## Make `dist_ai.webcheck` importable from a CHECKOUT (CI sibling-checkout) as well as
## when INSTALLED; same inline idiom site-generate uses, no env var to remember.
_dist_packages = os.path.normpath(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'lib', 'python3', 'dist-packages'))
if os.path.isdir(_dist_packages) and _dist_packages not in sys.path:
    sys.path.insert(0, _dist_packages)

from dist_ai.webcheck import svg_safety as _svg_safety

if __name__ == '__main__':
    sys.exit(_svg_safety.main(sys.argv[1:]))
