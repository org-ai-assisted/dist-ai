#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
## AI-Assisted

"""In-Xvfb orchestrator for one terminal's bracketed-paste-bypass measurement.

Runs INSIDE a nested X server (the runner invokes it under `xvfb-run`). It:
  1. puts the forged-marker payload (from probe-paste.PAYLOAD) on the PRIMARY
     selection and keeps owning it,
  2. launches the terminal running probe-paste.py,
  3. waits for the probe to enable bracketed paste and signal ready,
  4. middle-clicks the terminal window to paste PRIMARY (the classic X paste),
  5. waits for the probe's verdict JSON at --out.

Needs xdotool + (xclip or xsel) on PATH, inside the same X server as the terminal.
Emits nothing itself; the probe writes --out. Exit 0 iff a verdict was produced."""

import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
import argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import paste_probe_lib as lib


def own_selections(payload, workdir):
    """Own the PRIMARY and CLIPBOARD selections with `payload`.

    Both, so a terminal whose paste binding reads either one gets the payload.
    Returns the list of holder Popens (empty if no clipboard tool is available)."""
    path = os.path.join(workdir, 'payload.bin')
    with open(path, 'wb') as handle:
        handle.write(payload)
    holders = []
    if shutil.which('xclip'):
        for sel in ('primary', 'clipboard'):
            holders.append(subprocess.Popen(
                ['xclip', '-selection', sel, '-i', path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    elif shutil.which('xsel'):
        for flag in ('--primary', '--clipboard'):
            with open(path, 'rb') as handle:
                holders.append(subprocess.Popen(
                    ['xsel', flag, '--input'], stdin=handle,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    return holders


def _xdotool(*args, timeout=10):
    return subprocess.run(['xdotool', *args], timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)


def find_window(cls, deadline):
    """Return the first window id matching WM class `cls`, or None before deadline."""
    while time.time() < deadline:
        res = _xdotool('search', '--onlyvisible', '--class', cls)
        ids = res.stdout.decode().split()
        if ids:
            return ids[-1]
        time.sleep(0.2)
    return None


def paste_primary(wid, attempts=4, spacing=0.5):
    """Middle-click inside the window to paste the PRIMARY selection.

    Under the bare nested Xvfb there is no window manager, so keyboard focus is not
    assigned and XTEST key events (Shift+Insert) go nowhere; a pointer Button2 event
    lands on the window under the pointer regardless. Button2 pastes PRIMARY on
    xterm, st and urxvt by default. Clicked a few times spaced out because a slow
    emulator may not accept a paste until it has finished mapping -- harmless, since
    verdict() strips whole bracketed regions and so tolerates more than one paste."""
    _xdotool('mousemove', '--window', wid, '80', '80')
    for _ in range(attempts):
        time.sleep(spacing)
        _xdotool('click', '2')


def wait_for(path, deadline):
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.1)
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--launch', required=True,
                        help='JSON list: terminal argv up to (not incl.) the -e command')
    parser.add_argument('--exec-flag', default='-e',
                        help='the terminal flag that runs a command (-e for xterm/st/urxvt)')
    parser.add_argument('--class', dest='wclass', required=True,
                        help='WM class to find the terminal window (xdotool --class)')
    parser.add_argument('--probe', required=True, help='path to probe-paste.py')
    parser.add_argument('--out', required=True, help='the probe writes its verdict here')
    parser.add_argument('--label', required=True)
    parser.add_argument('--ready-timeout', type=float, default=15.0)
    parser.add_argument('--result-timeout', type=float, default=10.0)
    ns = parser.parse_args()

    if shutil.which('xdotool') is None:
        sys.stderr.write('paste-driver: xdotool missing\n')
        return 2
    launch = json.loads(ns.launch)
    work = tempfile.mkdtemp(prefix='paste-')
    ready = os.path.join(work, 'ready')

    holders = own_selections(lib.PAYLOAD, work)
    if not holders:
        sys.stderr.write('paste-driver: no xclip/xsel to own the selection\n')
        return 2
    time.sleep(0.3)                             # let the selections settle

    argv = launch + [ns.exec_flag, 'python3', ns.probe,
                     '--out', ns.out, '--ready', ready, '--label', ns.label,
                     '--timeout', '8', '--settle', '0.6']
    term = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_for(ready, time.time() + ns.ready_timeout):
            sys.stderr.write('paste-driver %s: probe never signalled ready\n' % ns.label)
            return 1
        wid = find_window(ns.wclass, time.time() + 5)
        if wid is None:
            sys.stderr.write('paste-driver %s: window (class %s) not found\n'
                             % (ns.label, ns.wclass))
            return 1
        paste_primary(wid)
        if not wait_for(ns.out, time.time() + ns.result_timeout):
            sys.stderr.write('paste-driver %s: no verdict written\n' % ns.label)
            return 1
        return 0
    finally:
        for proc in [term, *holders]:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except (OSError, subprocess.SubprocessError):
                try:
                    proc.kill()
                except OSError:
                    pass


if __name__ == '__main__':
    sys.exit(main())
