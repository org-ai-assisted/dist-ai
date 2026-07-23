#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
## AI-Assisted

"""Terminal fingerprint probe. Run INSIDE a terminal: send each standard
identification/query escape sequence to the controlling tty, read whatever the
terminal answers within a timeout, and write a JSON report of query -> raw
response to --out. A terminal that ANSWERS a query leaks that datum to any
program (local or a remote host over ssh); one that stays silent leaks nothing.

Reproducible: `probe.py --out FILE` in any terminal (xterm, st, secure-terminal
via `-- probe.py`, ...). The runner drives several under Xvfb and diffs them."""

import os
import sys
import json
import time
import select
import termios
import tty
import argparse

# (key, human label, query bytes, what answering it leaks)
QUERIES = [
    ('da1', 'Primary Device Attributes (DA1)', b'\x1b[c',
     'the feature set -> identifies the emulator family'),
    ('da2', 'Secondary Device Attributes (DA2)', b'\x1b[>c',
     'terminal type + firmware VERSION number'),
    ('da3', 'Tertiary Device Attributes (DA3)', b'\x1b[=c',
     'a unit ID string'),
    ('xtversion', 'Name + version (XTVERSION)', b'\x1b[>0q',
     'the exact emulator NAME and version string'),
    ('cursor', 'Cursor position report (DSR 6)', b'\x1b[6n',
     'the cursor row/column'),
    ('status', 'Terminal status (DSR 5)', b'\x1b[5n',
     'that the terminal is present/OK'),
    ('fg', 'Foreground colour (OSC 10)', b'\x1b]10;?\x07',
     'your exact text colour (theme fingerprint)'),
    ('bg', 'Background colour (OSC 11)', b'\x1b]11;?\x07',
     'your exact background colour (theme fingerprint)'),
    ('palette', 'Palette colour 1 (OSC 4)', b'\x1b]4;1;?\x07',
     'your exact palette (theme fingerprint)'),
    ('textarea_px', 'Text-area size in pixels (CSI 14 t)', b'\x1b[14t',
     'the window pixel size'),
    ('cell_px', 'Cell size in pixels (CSI 16 t)', b'\x1b[16t',
     'the font cell pixel size'),
    ('title', 'Report window title (CSI 21 t)', b'\x1b[21t',
     'the current window TITLE text'),
    ('decrqm_sync', 'Synchronised-output mode (DECRQM 2026)', b'\x1b[?2026$p',
     'whether a specific private mode is supported'),
]


def probe_tty(timeout):
    """Send each query to /dev/tty in raw mode, collect any response."""
    fd = os.open('/dev/tty', os.O_RDWR)
    old = termios.tcgetattr(fd)
    tty.setraw(fd)
    results = {}
    try:
        for key, _label, seq, _leak in QUERIES:
            os.write(fd, seq)
            time.sleep(0.05)
            out = b''
            end = time.time() + timeout
            while time.time() < end:
                ready, _, _ = select.select([fd], [], [], 0.05)
                if ready:
                    out += os.read(fd, 512)
                    end = time.time() + timeout
            results[key] = out
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old)
        os.close(fd)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--label', default=os.environ.get('TERM', '?'))
    parser.add_argument('--timeout', type=float, default=0.4)
    ns = parser.parse_args()
    raw = probe_tty(ns.timeout)
    report = {
        'label': ns.label,
        'term': os.environ.get('TERM', ''),
        'answers': {k: v.decode('latin-1') for k, v in raw.items()},
    }
    with open(ns.out, 'w', encoding='utf-8') as handle:
        json.dump(report, handle)
    # A short human echo (harmless if the terminal shows it).
    answered = sum(1 for v in raw.values() if v)
    sys.stderr.write('probed %s: %d/%d queries answered\n'
                     % (ns.label, answered, len(QUERIES)))


if __name__ == '__main__':
    main()
