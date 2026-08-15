#!/usr/bin/python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Measurement helper for the truecolor-art regression tests. Given a rendered art payload
## file, print "<rows> <distinct-widths...> <SAFE|UNSAFE>":
##   rows    -- number of lines
##   widths  -- the SET of per-line glyph widths (SGR stripped), sorted; a ragged scene
##              (width drift) shows as more than one width token
##   SAFE    -- the bytes are cat-safe: ONLY SGR colour (ESC[..m), the U+2580 half-block,
##              and newlines. the U+2580 escape keeps this source ASCII; re resolves it to the glyph.

import re
import sys


def strip_sgr(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def main():
    with open(sys.argv[1], encoding='utf-8') as handle:
        data = handle.read()
    lines = data.rstrip('\n').split('\n')
    widths = sorted({len(strip_sgr(line)) for line in lines})
    residue = re.sub(r'\x1b\[[0-9;]*m|\u2580|\n', '', data)
    print(len(lines), *widths, 'SAFE' if residue == '' else 'UNSAFE')


if __name__ == '__main__':
    main()
