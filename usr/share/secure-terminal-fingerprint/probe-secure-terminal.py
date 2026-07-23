#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
## AI-Assisted

"""Probe secure-terminal (the app) for fingerprint responses, headlessly and
deterministically. Instead of running the GUI under Xvfb, drive a SecureTerminal
widget: have a real child shell EMIT each query as output, and capture whatever
the app writes BACK to the pty (its answer). secure-terminal strips every query,
so it answers nothing -- verified here for both CLI and TUI mode. Same JSON report
shape as probe.py, so the runner diffs it against the real emulators uniformly.

Usage: probe-secure-terminal.py --out FILE [--tui] --st-repo DIR"""

import os
import sys
import json
import time
import argparse


def probe(st_repo, tui, queries):
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    sys.path.insert(0, os.path.join(st_repo, 'usr/lib/python3/dist-packages'))
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import QCoreApplication
    app = QApplication.instance() or QApplication([])   # held so it is not GC'd
    assert app is not None
    from secure_terminal.terminal import SecureTerminal
    answers = {}
    for key, seq in queries:
        # a child shell that prints exactly this query's bytes, then idles, so the
        # app processes it as ordinary program output and would answer over the pty.
        octal = ''.join('\\%03o' % b for b in seq)
        term = SecureTerminal(
            command=['/bin/sh', '-c', 'printf "%s"; sleep 2' % octal], tui=tui)
        sent = []
        term._write = lambda d, _s=sent: _s.append(bytes(d))
        end = time.time() + 2.5
        while time.time() < end:
            QCoreApplication.processEvents()
            time.sleep(0.01)
        answers[key] = b''.join(sent).decode('latin-1')
        try:
            term.shutdown()
        except Exception:                       # noqa: BLE001 - best-effort teardown
            pass
    return answers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--tui', action='store_true')
    parser.add_argument('--st-repo',
                        default=os.path.expanduser('~/private-sources/secure-terminal'))
    ns = parser.parse_args()
    # keep the query list in lock-step with probe.py by importing it
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import probe as probe_mod
    queries = [(k, seq) for k, _label, seq, _leak in probe_mod.QUERIES]
    answers = probe(ns.st_repo, ns.tui, queries)
    report = {
        'label': 'secure-terminal-' + ('tui' if ns.tui else 'cli'),
        'term': 'secure-terminal' if not ns.tui else 'xterm-256color',
        'answers': answers,
    }
    with open(ns.out, 'w', encoding='utf-8') as handle:
        json.dump(report, handle)
    answered = sum(1 for v in answers.values() if v)
    sys.stderr.write('probed %s: %d/%d queries answered\n'
                     % (report['label'], answered, len(queries)))


if __name__ == '__main__':
    main()
