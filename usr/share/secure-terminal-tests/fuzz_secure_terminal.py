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
import json
import os
import random
import re
import struct
import sys
import tempfile

from secure_terminal import sanitize as S
from secure_terminal import settings as SET
from secure_terminal import session as SESS
from secure_terminal import ipc
from secure_terminal import hook as HOOK
from secure_terminal import cli as CLI


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


def phase_hook_protocol(rnd, iterations, seed):
    ## The command-hook SUBPROCESS protocol (hook.py, distinct from the rules parser
    ## above): a handler's advisory message and its suggestion (which may be SENT to
    ## the shell) must be sanitized whatever the handler returns, and evaluate() must
    ## never raise -- it must always yield a valid verdict, however garbage the reply.
    ## _invoke is mocked so no subprocess is spawned.
    orig_invoke = HOOK._invoke
    try:
        for _ in range(iterations):
            raw = _rand_text(rnd)
            msg = HOOK._sanitize_message(raw)
            _assert(len(msg) <= 2000
                    and all(ord(c) in SAFE for c in msg),
                    'hook _sanitize_message leaked/over-long on {0!r}'.format(raw), seed)
            sug = HOOK._sanitize_suggestion(raw)
            _assert(len(sug) <= 1000 and '\n' not in sug and '\r' not in sug
                    and all(0x20 <= ord(c) <= 0x7E for c in sug),
                    'hook _sanitize_suggestion leaked on {0!r}'.format(raw), seed)
            reply = rnd.choice([
                None, [], 'x', 42, {},
                {'verdict': rnd.choice(['allow', 'block', 'ask', 'need_transcript',
                                        'bogus', '', 123]),
                 'message': _rand_text(rnd), 'suggestion': _rand_text(rnd)},
                {'message': _rand_text(rnd)},
                {'verdict': 'need_transcript'}])
            HOOK._invoke = lambda *a, _r=reply, **k: _r
            dec = HOOK.evaluate(['/nonexistent'], _rand_text(rnd),
                                on_error=rnd.choice(['allow', 'block']),
                                transcript_provider=lambda: _rand_text(rnd))
            _assert(isinstance(dec, dict)
                    and dec.get('verdict') in ('allow', 'block', 'ask')
                    and isinstance(dec.get('message'), str)
                    and isinstance(dec.get('suggestion'), str)
                    and '\n' not in dec['suggestion'] and '\r' not in dec['suggestion'],
                    'hook evaluate returned an invalid decision for reply {0!r}'
                    .format(reply), seed)
    finally:
        HOOK._invoke = orig_invoke


def phase_hook_subprocess(rnd, iterations, seed):
    ## The REAL hook round-trip -- a subprocess + json.loads of the child's stdout,
    ## beyond phase_hook_protocol's mocked reply. A hook child echoes a
    ## fuzzer-controlled reply file, run through evaluate() with the real _invoke, so
    ## arbitrary (incl. invalid) child output must still yield a valid decision and
    ## never raise. A subprocess per iteration is slow, so probe a small curated set.
    hook_fd, hook_py = tempfile.mkstemp(suffix='.py')
    os.write(hook_fd, b"import sys\n"
                      b"sys.stdin.buffer.read()\n"
                      b"sys.stdout.buffer.write(open(sys.argv[1], 'rb').read())\n")
    os.close(hook_fd)
    reply_fd, reply_file = tempfile.mkstemp()
    os.close(reply_fd)
    argv = [sys.executable, hook_py, reply_file]
    try:
        for _ in range(min(iterations, 60)):
            reply = rnd.choice([
                b'', b'not json', b'{', b'[]', b'42', b'null', b'true',
                json.dumps({'verdict': rnd.choice(['allow', 'block', 'ask',
                                                   'need_transcript', 'x']),
                            'message': _rand_text(rnd),
                            'suggestion': _rand_text(rnd)}).encode('utf-8'),
                _rand_bytes(rnd, 128)])
            with open(reply_file, 'wb') as handle:
                handle.write(reply)
            dec = HOOK.evaluate(argv, _rand_text(rnd), timeout=5,
                                on_error=rnd.choice(['allow', 'block']),
                                transcript_provider=lambda: _rand_text(rnd))
            _assert(isinstance(dec, dict)
                    and dec.get('verdict') in ('allow', 'block', 'ask')
                    and isinstance(dec.get('suggestion'), str)
                    and '\n' not in dec['suggestion'] and '\r' not in dec['suggestion'],
                    'hook real round-trip: invalid decision for reply {0!r}'
                    .format(reply), seed)
    finally:
        os.unlink(hook_py)
        os.unlink(reply_file)


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
        ('hooks', phase_hooks),
        ('hook_protocol', phase_hook_protocol),
        ('hook_subprocess', phase_hook_subprocess),
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
