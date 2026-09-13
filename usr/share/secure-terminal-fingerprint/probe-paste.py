#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
## AI-Assisted

"""Bracketed-paste-bypass probe. Run INSIDE a terminal (the driver launches it as
`<emulator> -e python3 probe-paste.py ...`).

It enables bracketed paste (CSI ?2004h) so the terminal is asked to wrap any paste
as data, signals readiness, then captures the raw bytes the terminal delivers when
the driver pastes a PRIMARY selection that hides a FORGED end marker (see
paste_probe_lib.PAYLOAD): BEFORE  CSI 201~  AFTER.

A terminal that passes the forged `CSI 201~` through lets it close the paste early,
so `AFTER` arrives as ordinary (unbracketed) keystrokes -- the pasted-command
smuggling / bracketed-paste-bypass class (e.g. CVE-2021-31701). A terminal that
sanitises the pasted bytes keeps `AFTER` inside its own single 200~..201~ wrapper.
Verdict (paste_probe_lib.verdict) is written as JSON to --out."""

import os
import sys
import json
import time
import select
import termios
import tty
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paste_probe_lib as lib


def _drain(fd):
    """Discard any startup bytes already waiting on the tty."""
    while True:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if not ready:
            return
        try:
            os.read(fd, 4096)
        except OSError:
            return


def capture(ready_path, timeout, settle):
    """Enable bracketed paste, signal ready, and collect the pasted byte stream."""
    fd = os.open('/dev/tty', os.O_RDWR)
    old = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        os.write(fd, b'\x1b[?2004h')     # ask the terminal to bracket pastes
        time.sleep(0.15)
        _drain(fd)
        with open(ready_path, 'w', encoding='utf-8') as handle:
            handle.write('ready')        # tell the driver to paste now
        out = b''
        end = time.time() + timeout      # overall wait for the paste to arrive
        while time.time() < end:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                out += chunk
                end = time.time() + settle   # short settle once bytes flow
        return out
    finally:
        try:
            os.write(fd, b'\x1b[?2004l')
        except OSError:
            pass
        termios.tcsetattr(fd, termios.TCSANOW, old)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--ready', required=True,
                        help='touch this path once bracketed paste is enabled')
    parser.add_argument('--label', default=os.environ.get('TERM', '?'))
    parser.add_argument('--timeout', type=float, default=4.0)
    parser.add_argument('--settle', type=float, default=0.4)
    ns = parser.parse_args()
    raw = capture(ns.ready, ns.timeout, ns.settle)
    report = {
        'label': ns.label,
        'term': os.environ.get('TERM', ''),
        'verdict': lib.verdict(raw),
        'markers': {'begin': raw.count(lib.BEG), 'end': raw.count(lib.END),
                    'after_present': lib.SENTINEL_AFTER in raw},
        'captured': raw.decode('latin-1'),
    }
    with open(ns.out, 'w', encoding='utf-8') as handle:
        json.dump(report, handle)
    sys.stderr.write('paste-probe %s: %s\n' % (ns.label, report['verdict']))


if __name__ == '__main__':
    main()
