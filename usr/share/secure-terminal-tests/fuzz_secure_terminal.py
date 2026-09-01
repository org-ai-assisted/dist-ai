#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Randomized in-process fuzzer for secure-terminal's untrusted-input parsers.

Every function targeted here consumes attacker-influenceable input: a program's
raw output rendered to the widget, text pasted from the clipboard, a window/tab
title set by the running program (OSC), the SGR colour parameters of an escape
sequence, a config drop-in that round-trips through disk, the persisted session
file, and IPC frames from the single-instance socket.
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
import os
import random
import re
import struct
import sys
import tempfile
import unicodedata

from secure_terminal import sanitize as S
from secure_terminal import settings as SET
from secure_terminal import session as SESS
from secure_terminal import ipc
from secure_terminal import cli as CLI


## ---- independent terminal-safety oracle (mirrors test_corpus.py) ------------

_HONORED = {0x08, 0x09, 0x0A, 0x0D}
SAFE = frozenset(_HONORED | set(range(0x20, 0x7F)))
# DERIVED from the Unicode general categories, never enumerated -- see the same
# derivation in test_corpus.py. An enumerated ORACLE fails silently: a member
# nobody listed weakens every assertion below instead of failing one, so this copy
# went on missing U+061C, U+2061..2064 and U+180E for as long as it was a list.
#   Cc control (C0, DEL, C1); Cf format (bidi controls, zero-widths, invisible
#   math operators, BOM, soft hyphen); Zl/Zp line and paragraph separators.
# Plus the default-ignorables, the one class no category exposes: printable to
# str.isprintable(), yet they render as nothing.
_DANGEROUS_CATEGORIES = frozenset(('Cc', 'Cf', 'Zl', 'Zp'))
DANGEROUS_CPS = frozenset(
    cp for cp in range(0x110000)
    if cp not in _HONORED
    and (unicodedata.category(chr(cp)) in _DANGEROUS_CATEGORIES
         or S.is_default_ignorable(chr(cp))))
# Canary: the default-ignorable arm borrows a PRODUCT predicate, so a gutted
# is_default_ignorable would shrink this oracle without failing anything. Naming
# the members makes that a hard failure at import, before a single fuzz iteration.
for _cp in (0x00, 0x1B, 0x7F, 0x9B, 0x061C, 0x180E, 0x200B, 0x200D, 0x200E,
            0x202E, 0x2066, 0x2028, 0x2029, 0xFEFF, 0x2061, 0x2062, 0x2063,
            0x2064, 0xFE0F, 0x3164, 0x115F, 0x034F):
    assert _cp in DANGEROUS_CPS, 'DANGEROUS_CPS lost U+%04X' % _cp
assert not (DANGEROUS_CPS & SAFE), 'SAFE and DANGEROUS_CPS must be disjoint'


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
    ## NEVER survive in any mode; box/reveal render only the safe alphabet; and
    ## box is idempotent.
    for _ in range(iterations):
        text = _rand_text(rnd)
        for mode in S.DISPLAY_MODES:
            out = S.render_output(text, mode)
            _assert(not any(ord(ch) in DANGEROUS_CPS for ch in out),
                    'render_output({0!r}, {1}) leaked a dangerous cp: {2!r}'
                    .format(text, mode, out), seed)
            if mode in ('box', 'reveal'):
                _assert(all(ord(ch) in SAFE for ch in out),
                        'render_output({0!r}, {1}) left non-SAFE: {2!r}'
                        .format(text, mode, out), seed)
        strip = S.render_output(text, 'box')
        _assert(S.render_output(strip, 'box') == strip,
                'render_output box not idempotent on {0!r}'.format(text), seed)
        raw = text.encode('utf-8', 'surrogatepass') if not any(
            0xD800 <= ord(c) <= 0xDFFF for c in text) else b''
        sb = S.sanitize_bytes(raw, 'box')
        _assert(all(ord(ch) in SAFE for ch in sb),
                'sanitize_bytes left non-SAFE for {0!r}'.format(raw), seed)


def phase_lines(rnd, iterations, seed):
    ## The line-mode logical-cell editor and its renderers: no ESC ever reaches a
    ## cell, the cursor stays within the current line, box runs are all-safe,
    ## and the legacy bulk editor keeps its cursor in bounds. Also the per-cell
    ## TUI sanitizer and the SGR colour parser.
    for _ in range(iterations):
        text = _rand_text(rnd)
        max_line = rnd.choice((0, 0, rnd.randint(2, 120)))   # exercise the width bound
        comp, cells, col, sgr, _w = S.feed_line_edits([], 0, {}, text, max_line)
        _assert(0 <= col <= len(cells),
                'feed_line_edits cursor {0} out of [0,{1}] on {2!r}'
                .format(col, len(cells), text), seed)
        _assert(not max_line or (col <= max_line and len(cells) <= max_line),
                'feed_line_edits exceeded width {0} on {1!r}'.format(max_line, text),
                seed)
        for ch, _key in cells:
            _assert(ch != '\x1b', 'ESC smuggled into a cell on {0!r}'
                    .format(text), seed)
        runs, prefix = S.cells_to_runs(comp, cells, 'box', rnd.choice((True,
                                                                         False)))
        _assert(isinstance(prefix, int) and prefix >= 0,
                'cells_to_runs bad prefix on {0!r}'.format(text), seed)
        for run_text, _key in runs:
            # BOX (U+25A1) is cells_to_runs' intentional box-mode
            # placeholder for a neutralized cell (the widget maps it back to '_'
            # on export) -- safe by design, so allow it alongside the ASCII set.
            _assert(all(ord(ch) in SAFE or ch in ('\n', S.BOX)
                        for ch in run_text),
                    'cells_to_runs box run not safe on {0!r}'.format(text),
                    seed)
        disp = S.cells_display_col(cells, col, 'box')
        _assert(disp >= 0, 'cells_display_col negative on {0!r}'.format(text),
                seed)
        ## feeding the resulting state again must not raise
        S.feed_line_edits(cells, col, sgr, text, max_line)
        ## per-cell TUI sanitizer: any control in the cell -> neutralized to the
        ## single-column BOX placeholder (matches CLI box/show rendering)
        cell = ''.join(rnd.choice(_DANGER + _TEXT) for _ in range(rnd.randint(0,
                                                                              4)))
        tc = S.tui_cell(cell, rnd.choice(S.DISPLAY_MODES))
        if any(ord(c) < 0x20 for c in cell):
            _assert(tc == S.BOX, 'tui_cell did not neutralize control {0!r}'
                    .format(cell), seed)
        ## SGR parser: fg/bg stay in the 16-colour range, bold stays bool
        state = {'fg': None, 'bg': None, 'bold': False}
        S.parse_sgr(''.join(rnd.choice('0123456789;:') for _ in range(
            rnd.randint(0, 24))), state)
        for _chan in (state['fg'], state['bg']):
            _assert(_chan is None
                    or (isinstance(_chan, int) and 0 <= _chan <= 15)
                    or (isinstance(_chan, str) and re.fullmatch(r'#[0-9a-f]{6}', _chan)),
                    'parse_sgr colour not None / 0..15 / #rrggbb', seed)


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
            out: dict[str, str] = {}
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


def phase_cli(rnd, iterations, seed):
    ## The secure-terminal-cli entry (cli.main): random argv must never crash the
    ## parser beyond argparse's own SystemExit. _run is mocked, so nothing is
    ## actually spawned; this exercises the arg grammar + the REMAINDER '--' handling.
    orig_run = CLI._run
    CLI._run = lambda cmd_argv, mode: 0
    try:
        _atoms = ['--mode', '--bogus', 'detail', 'box', 'show', 'reveal', '-x', '--',
                  'ls', '-la', '']
        for _ in range(iterations):
            argv = [rnd.choice(_atoms) if rnd.random() < 0.7 else _rand_text(rnd, 3)
                    for _ in range(rnd.randint(0, 6))]
            try:
                CLI.main(argv)
            except SystemExit:
                pass                        # argparse rejects bad args / --help -- expected
    finally:
        CLI._run = orig_run


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
        ('cli', phase_cli),
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
