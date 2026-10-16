#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CLI shim: the static consistency checks live in the importable core
## `dist_ai.webcheck.site` (shared with mw-static-generator so neither side
## reinvents the other's checks). This file stays the stable entry point that
## `website-tests`, `site-generate` (import check_site), and `check_seo_test.py`
## (loads it by path) resolve. It mirrors the core module's FULL namespace -- incl.
## underscore-prefixed helpers the SEO regression reads -- so a by-path load behaves
## exactly as the former in-file module did.

import os
import sys

## Make `dist_ai.webcheck` importable whether this tree is INSTALLED (dist-ai .deb;
## already on sys.path) or run from a CHECKOUT (CI sibling-checkout, co-located
## generator), where usr/lib/python3/dist-packages is not on the default path. Same
## inline idiom site-generate uses; no env var, nothing to remember.
_dist_packages = os.path.normpath(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'lib', 'python3', 'dist-packages'))
if os.path.isdir(_dist_packages) and _dist_packages not in sys.path:
    sys.path.insert(0, _dist_packages)

from dist_ai.webcheck import site as _site

globals().update({
    _name: _value for _name, _value in vars(_site).items()
    if _name not in (
        '__name__', '__file__', '__loader__', '__spec__',
        '__package__', '__builtins__', '__doc__', '__cached__')
})

if __name__ == '__main__':
    sys.exit(_site.main())
