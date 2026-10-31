#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Dep preflight for the static website-consistency lane. Verifies the Python modules its checkers
## (check_site.py / check_svg_safety.py) import are present, and names the apt package for any that
## are MISSING -- so a clean CI runner lacking one fails with a CLEAR, actionable message instead of
## a bare ImportError deep inside a checker (which reads only as a generic "exit code 1" and silently
## blocks the Pages deploy). This file is the SINGLE enumeration of the lane's runtime deps: the
## consumer workflow apt install step MUST install exactly these packages. find_spec checks
## importability WITHOUT importing (no side effects, and it reports every missing dep in one run).
##
## Exit: 0 all present | 1 one or more missing (named on stderr).

import importlib.util
import sys

## module import name -> Debian apt package that provides it
DEPS = {
    'bs4': 'python3-bs4',                 # BeautifulSoup: CSP-meta html5lib parse (check_site)
    'html5lib': 'python3-html5lib',       # the WHATWG parser bs4 drives (check_site)
    'PIL': 'python3-pil',                 # image dimension / format checks (check_site)
    'defusedxml': 'python3-defusedxml',   # SVG active-content guard (check_svg_safety)
    'yaml': 'python3-yaml',               # config parse
}


def main():
    missing = [pkg for mod, pkg in DEPS.items() if importlib.util.find_spec(mod) is None]
    if missing:
        sys.stderr.write(
            'FAIL: static website-consistency lane missing Python dep(s); '
            'CI install step must add: ' + ' '.join(sorted(missing)) + '\n')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
