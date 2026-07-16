#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Randomized in-process fuzzer for secure-terminal's untrusted-input parsers.

Every function targeted here consumes attacker-influenceable input: a program's
raw output rendered to the widget, text pasted from the clipboard, a window/tab
title set by the running program (OSC), the SGR colour parameters of an escape
sequence, a config drop-in that round-trips through disk, the persisted session
file, IPC frames from the single-instance socket, and the hook rules/gate files.
A crash, a hang, or a wrong-typed return on adversarial input is a terminal that
dies (or worse, lets a dangerous escape reach the real terminal) on hostile data.

Unlike the hypothesis property tests (test_fuzz.py, which gate every PR), this
runs a large randomized campaign with an ESCAPE-BIASED generator whose whole job
is to keep trying to smuggle a dangerous code point (C0/C1 controls, ESC, bidi
overrides, zero-width joiners, BOM, line/paragraph separators) past the
sanitizer. Every generated string is checked against an independent terminal-
safety oracle (DANGEROUS_CPS below, mirroring stdisplay's) at every display mode,
plus per-function invariants (idempotence, cursor stays in-line, correct type).

Run: fuzz_secure_terminal.py [--iterations N] [--seed N]. On a failure it prints
the seed and the offending input so the case replays deterministically.
"""

import argparse
import importlib.util
import os
import random
import struct
import sys
import tempfile

from secure_terminal import sanitize as S
from secure_terminal import settings as SET
from secure_terminal import session as SESS
from secure_terminal import ipc


## ---- independent terminal-safety oracle (mirrors test_corpus.py) ------------

_HONORED = {0x08, 0x09, 0x0A, 0x0D}
SAFE = frozenset(_HONORED | set(range(0x20, 0x7F)))
DANGEROUS_CPS = frozenset(
    [c for c in range(0x00, 0x20) if c not in _HONORED]      # C0 controls incl ESC
    + [0x7F]                                                  # DEL
    + list(range(0x80, 0xA0))                                # C1 controls
    + [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF]  # zero-width / BOM
    + list(range(0x202A, 0x202F))                            # bidi embed/override
    + list(range(0x2066, 0x206A))                            # bidi isolates
    + [0x2028, 0x2029])                                      # line / paragraph sep


## hooklib lives in the hooks dir, not on the package path: load it directly, the
## same way test_fuzz.py does (five dirnames up from the sanitize module -> usr).
_usr = os.path.abspath(S.__file__)
for _ in range(5):
    _usr = os.path.dirname(_usr)
_hlpath = os.path.join(_usr, 'share', 'secure-terminal', 'hooks', 'hooklib.py')
HL = None
if os.path.exists(_hlpath):
    _spec = importlib.util.spec_from_file_location('hooklib', _hlpath)
    HL = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(HL)


## ---- input generators -------------------------------------------------------

## The smuggling alphabet: dangerous primitives the sanitizer must neutralize,
## interleaved with the printable text and escape scaffolding that makes a parser
## take its interesting branches.
_DANGER = [
    '\x1b', '\x1b[2J', '\x1b[H', '\x1b[10A', '\x1b[5;9H', '\x1b[2K', '\x1b[1G',
    '\x1b[3D', '\x1b[6C', '\x1b]0;title\x07', '\x1b]0;title\x1b\\', '\x1b(B',
    '\x9b', '\x9d', '\x90', '\x00', '\x07', '\x7f', '\r', '\b', '\t', '\n',
    '\u200b', '\u200e', '\u202e', '\u2066', '\u2069', '\ufeff', '\u2060',
    ' ', ' ', '\x1b[31m', '\x1b[38;5;200m', '\x1b[48;2;1;2;3m',
    '\u2028', '\u2029', '\x1b[31m', '\x1b[38;5;200m', '\x1b[48;2;1;2;3m',
]
_TEXT = list('abcXYZ 0189.:;=/#|<>"\'\\') + [
    '\u20ac', '\u00e9', '\U0001f600', 'echo', 'ls', 'sudo', 'curl']


def _rand_token(rnd):
    kind = rnd.random()
    if kind < 0.45:
        return rnd.choice(_DANGER)
    if kind < 0.8:
        return rnd.choice(_TEXT)
    ## Occasionally a long run of one primitive, to probe pathological input.
    return rnd.choice(_DANGER + _TEXT) * rnd.randint(0, 500)


def _rand_text(rnd, max_tokens=24):
    return ''.join(_rand_token(rnd) for _ in range(rnd.randint(0, max_tokens)))


def _rand_bytes(rnd, max_len=512):
    return bytes(rnd.randrange(256) for _ in range(rnd.randint(0, max_len)))


def _assert(condition, message, seed):
    if not condition:
        raise AssertionError('{0} (replay --seed {1})'.format(message, seed))


## ---- fuzz phases ------------------------------------------------------------

def phase_output(rnd, iterations, seed):
    ## The output renderer and the raw-byte decoder: a dangerous code point must
    ## NEVER survive in any mode; strip/reveal render only the safe alphabet; and
    ## strip is idempotent.
    for _ in range(iterations):
        text = _rand_text(rnd)
        for mode in S.DISPLAY_MODES:
            out = S.render_output(text, mode)
            _assert(not any(ord(ch) in DANGEROUS_CPS for ch in out),
                    'render_output({0!r}, {1}) leaked a dangerous cp: {2!r}'
                    .format(text, mode, out), seed)
            if mode in ('strip', 'reveal'):
                _assert(all(ord(ch) in SAFE for ch in out),
                        'render_output({0!r}, {1}) left non-SAFE: {2!r}'
                        .format(text, mode, out), seed)
        strip = S.render_output(text, 'strip')
        _assert(S.render_output(strip, 'strip') == strip,
                'render_output strip not idempotent on {0!r}'.format(text), seed)
        raw = text.encode('utf-8', 'surrogatepass') if not any(
            0xD800 <= ord(c) <= 0xDFFF for c in text) else b''
        sb = S.sanitize_bytes(raw, 'strip')
        _assert(all(ord(ch) in SAFE for ch in sb),
                'sanitize_bytes left non-SAFE for {0!r}'.format(raw), seed)


def phase_lines(rnd, iterations, seed):
    ## The line-mode logical-cell editor and its renderers: no ESC ever reaches a
    ## cell, the cursor stays within the current line, strip runs are all-safe,
    ## and the legacy bulk editor keeps its cursor in bounds. Also the per-cell
    ## TUI sanitizer and the SGR colour parser.
    for _ in range(iterations):
        text = _rand_text(rnd)
        comp, cells, col, sgr = S.feed_line_edits([], 0, {}, text)
        _assert(0 <= col <= len(cells),
                'feed_line_edits cursor {0} out of [0,{1}] on {2!r}'
                .format(col, len(cells), text), seed)
        for ch, _key in cells:
            _assert(ch != '\x1b', 'ESC smuggled into a cell on {0!r}'
                    .format(text), seed)
        runs, prefix = S.cells_to_runs(comp, cells, 'strip', rnd.choice((True,
                                                                         False)))
        _assert(isinstance(prefix, int) and prefix >= 0,
                'cells_to_runs bad prefix on {0!r}'.format(text), seed)
        for run_text, _key in runs:
            _assert(all(ord(ch) in SAFE or ch == '\n' for ch in run_text),
                    'cells_to_runs strip run not safe on {0!r}'.format(text),
                    seed)
        disp = S.cells_display_col(cells, col, 'strip')
        _assert(disp >= 0, 'cells_display_col negative on {0!r}'.format(text),
                seed)
        ## feeding the resulting state again must not raise
        S.feed_line_edits(cells, col, sgr, text)
        ## legacy bulk editor
        line = _rand_text(rnd, max_tokens=8)
        completed, cur, newcol = S.apply_line_edits(
            line, rnd.randint(0, len(line)), text, rnd.randint(0, 200))
        _assert(0 <= newcol <= len(cur),
                'apply_line_edits cursor out of bounds on {0!r}'.format(text),
                seed)
        ## per-cell TUI sanitizer: any control in the cell -> neutralized to '_'
        cell = ''.join(rnd.choice(_DANGER + _TEXT) for _ in range(rnd.randint(0,
                                                                              4)))
        tc = S.tui_cell(cell, rnd.choice(S.DISPLAY_MODES))
        if any(ord(c) < 0x20 for c in cell):
            _assert(tc == '_', 'tui_cell did not neutralize control {0!r}'
                    .format(cell), seed)
        ## SGR parser: fg/bg stay in the 16-colour range, bold stays bool
        state = {'fg': None, 'bg': None, 'bold': False}
        S.parse_sgr(''.join(rnd.choice('0123456789;:') for _ in range(
            rnd.randint(0, 24))), state)
        _assert(state['fg'] is None or 0 <= state['fg'] <= 15,
                'parse_sgr fg out of range', seed)
        _assert(state['bg'] is None or 0 <= state['bg'] <= 15,
                'parse_sgr bg out of range', seed)


def phase_paste(rnd, iterations, seed):
    ## Clipboard/title parsers: the ASCII paste keeps only printable ASCII + the
    ## two submit controls; the unicode paste keeps no invisible/deceptive cp; the
    ## title is bounded plain ASCII; the classifiers return their documented shape.
    for _ in range(iterations):
        text = _rand_text(rnd)
        pa = S.sanitize_paste(text)
        _assert(all(ch in ('\t', '\r') or 0x20 <= ord(ch) <= 0x7E for ch in pa),
                'sanitize_paste leaked on {0!r}'.format(text), seed)
        pu = S.sanitize_paste_unicode(text)
        _assert(all(ch in ('\r', '\t') or ch.isprintable() for ch in pu),
                'sanitize_paste_unicode leaked on {0!r}'.format(text), seed)
        ti = S.sanitize_title(text)
        _assert(len(ti) <= 80 and all(0x20 <= ord(ch) <= 0x7E for ch in ti)
                and '\n' not in ti,
                'sanitize_title leaked on {0!r}'.format(text), seed)
        _assert(S.sanitize_title(ti) == ti,
                'sanitize_title not idempotent on {0!r}'.format(text), seed)
        flags = S.paste_findings(text)
        _assert(isinstance(flags, tuple) and len(flags) == 2
                and all(isinstance(f, bool) for f in flags),
                'paste_findings bad shape on {0!r}'.format(text), seed)
        cls = S.classify_paste(text)
        _assert(isinstance(cls, list) and all(
            isinstance(label, str) and isinstance(count, int) and count > 0
            for label, count in cls),
                'classify_paste bad shape on {0!r}'.format(text), seed)
        desc = S.describe_codepoint(rnd.randint(-4096, 0x120000))
        _assert(isinstance(desc, str) and desc, 'describe_codepoint empty', seed)


def phase_config(rnd, iterations, seed):
    ## The config drop-in parser and the session loader read semi-trusted files;
    ## a malformed/hostile one must parse to the documented type and never raise.
    with tempfile.TemporaryDirectory() as tmp:
        conf = os.path.join(tmp, 'x.conf')
        state = os.path.join(tmp, 'state')
        os.makedirs(state, exist_ok=True)
        SESS._state_dir = lambda: state
        for _ in range(iterations):
            with open(conf, 'w', encoding='utf-8') as handle:
                handle.write(_rand_text(rnd, max_tokens=12))
            out = {}
            SET._parse_into(conf, out)
            _assert(all(isinstance(k, str) and isinstance(v, str)
                        for k, v in out.items()),
                    'settings._parse_into returned non-str entry', seed)
            with open(os.path.join(state, 'session.json'), 'wb') as handle:
                handle.write(_rand_bytes(rnd, max_len=1024))
            _assert(isinstance(SESS.load(), list),
                    'session.load did not return a list', seed)


def phase_ipc(rnd, iterations, seed):
    ## The IPC length-frame reassembler: arbitrary byte chunks must never raise
    ## except the documented over-long ValueError, and a completed payload's
    ## length equals its 4-byte prefix.
    for _ in range(iterations):
        chunks = [_rand_bytes(rnd, max_len=64) for _ in range(rnd.randint(0, 8))]
        joined = b''.join(chunks)
        framer = ipc.Framer()
        result = None
        try:
            for chunk in chunks:
                got = framer.feed(chunk)
                if got is not None:
                    result = got
                    break
        except ValueError:
            continue                    # documented rejection of a huge frame
        if result is not None:
            length = struct.unpack('<I', joined[:4])[0]
            _assert(len(result) == length,
                    'ipc.Framer payload length mismatch', seed)


def phase_hooks(rnd, iterations, seed):
    ## The hook rules parser and the privileged config gate: arbitrary contents
    ## must yield the documented type and never raise (a bad file cannot crash a
    ## hook or flip the gate).
    if HL is None:
        return
    with tempfile.TemporaryDirectory() as tmp:
        priv = os.path.join(tmp, 'secure-terminal.d')
        os.makedirs(priv, exist_ok=True)
        HL._PRIVILEGED = (tmp,)
        for _ in range(iterations):
            HL.read_file = lambda name, _t=_rand_text(rnd): _t
            rules = HL.read_rules('example-hook-rules.conf')
            _assert(rules is None or isinstance(rules, list),
                    'read_rules bad type', seed)
            for rule in (rules or []):
                _assert(len(rule) == 4 and rule[0] in ('allow', 'block', 'ask')
                        and all(isinstance(f, str) for f in rule),
                        'read_rules bad rule {0!r}'.format(rule), seed)
            with open(os.path.join(priv, 'hooks.conf'), 'w',
                      encoding='utf-8') as handle:
                handle.write(_rand_text(rnd, max_tokens=8))
            value = HL._privileged_conf_value('hook_config_allow_user')
            _assert(value is None or isinstance(value, str),
                    'privileged_conf_value bad type', seed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=40000)
    parser.add_argument('--seed', type=int, default=None)
    opts = parser.parse_args()

    seed = opts.seed if opts.seed is not None else random.randrange(2 ** 32)
    rnd = random.Random(seed)
    phases = (
        ('output', phase_output),
        ('lines', phase_lines),
        ('paste', phase_paste),
        ('config', phase_config),
        ('ipc', phase_ipc),
        ('hooks', phase_hooks),
    )
    per_phase = max(1, opts.iterations // len(phases))
    print('fuzz_secure_terminal: seed={0} iterations={1}'.format(
        seed, opts.iterations))
    for name, func in phases:
        try:
            func(rnd, per_phase, seed)
        except Exception:
            sys.stderr.write(
                "fuzz_secure_terminal: FAILURE in phase '{0}' -- replay with "
                "--seed {1}\n".format(name, seed))
            raise
        print("fuzz_secure_terminal: phase '{0}' ok ({1} iterations)".format(
            name, per_phase))

    print('fuzz_secure_terminal: PASS')


if __name__ == '__main__':
    main()
