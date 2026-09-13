#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
## AI-Assisted

"""Unit test for paste_probe_lib.verdict() -- the correctness core of the
bracketed-paste-bypass probe. The X-driving parts (paste-driver.py) are exercised
by running secure-terminal-paste-fingerprint under Xvfb; this pins the pure
classification so a wrong edit fails loudly (canary: each case fails on the old
count-based logic if the region-strip is broken)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paste_probe_lib as lib

B, E, SB, SA = lib.BEG, lib.END, lib.SENTINEL_BEFORE, lib.SENTINEL_AFTER

CASES = [
    # (name, captured bytes, expected verdict)
    ('guard-held: forged marker stripped, AFTER inside wrapper',
     B + SB + SA + E, 'guard-held'),
    ('bypass: forged 201~ survived, AFTER escaped the wrapper',
     B + SB + E + SA + E, 'bypass'),
    ('no-bracketed-paste: delivered raw, no 200~ wrapper',
     SB + E + SA, 'no-bracketed-paste'),
    ('inconclusive: nothing captured',
     b'', 'inconclusive'),
    ('inconclusive: startup noise only, no sentinels',
     b'\x1b[?1;2c', 'inconclusive'),
    ('guard-held survives an accidental double paste',
     (B + SB + SA + E) * 2, 'guard-held'),
    ('bypass survives an accidental double paste',
     (B + SB + E + SA + E) * 2, 'bypass'),
    ('guard-held with surrounding shell/prompt noise',
     b'$ ' + B + SB + SA + E + b'\r\n', 'guard-held'),
    # not a bypass: AFTER precedes an intact, unforged wrapper (no escape happened)
    ('AFTER before an intact wrapper is not a bypass',
     SA + B + SB + E, 'guard-held'),
    # not a bypass: a safe terminal's paste captured before its closing 201~ arrived
    ('truncated safe capture (unclosed 200~) is inconclusive, not bypass',
     B + SB + SA, 'inconclusive'),
]


def main():
    failures = 0
    for name, raw, expected in CASES:
        got = lib.verdict(raw)
        ok = got == expected
        failures += not ok
        print('%s %s (got %r)' % ('pass' if ok else 'FAIL', name, got))
    print('test-paste-verdict: %d pass, %d fail, 0 skip'
          % (len(CASES) - failures, failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
