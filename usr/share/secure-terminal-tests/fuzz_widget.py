#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""GUI fuzzer: drive the LIVE SecureTerminal widget (offscreen Qt) with adversarial
input, not just the pure sanitizer functions (fuzz_secure_terminal.py covers those).

Feeds random escape/C1/unicode/combining-mark byte streams through the real
_on_readable render pipeline in every display mode and in both CLI and TUI mode,
flips modes and OSC opt-ins mid-stream, fires random pastes and key events. The
invariants a sanitizing terminal must never break:
  - no unhandled exception / crash on any input;
  - a single feed never freezes the render (a per-feed wall-clock bound catches a
    quadratic-reshape DoS such as a Zalgo combining-mark flood);
  - the visible document never contains a raw ESC or C0 control (only newline/tab);
  - the logical/grid model stays bounded, so no input builds an unbounded cluster;
  - nothing dangerous reaches the pty on a paste.

A crash, a hang, or a leaked control byte is a terminal that failed to sanitize.
The phases here are the reusable fuzz core; the deterministic test_fuzz_widget.py
drives them under coverage, this file's CLI runs them heavily. Override with
--iterations N / --seed N / --phase NAME; a failure prints the seed to replay.
Needs PyQt6 + pyte and QT_QPA_PLATFORM=offscreen (the entrypoint sets it)."""

import argparse
import os
import random
import sys
import time

try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtCore import Qt, QEvent, QMimeData
    from secure_terminal.terminal import SecureTerminal
    from secure_terminal import sanitize as S
except Exception as exc:                                 # pragma: no cover - deps present in CI
    sys.stderr.write('secure-terminal-tests-fuzz-gui: SKIP (cannot import '
                     'PyQt6/pyte/secure_terminal: {0})\n'.format(exc))
    sys.exit(77)


## Adversarial alphabet: the dangerous primitives a terminal must neutralize, plus
## the text/escape scaffolding that drives a parser into its interesting branches.
## Combining marks are over-represented -- the Zalgo grapheme-cluster DoS class.
_COMBINING = [chr(0x0300 + i) for i in range(0, 0x30)] + [
    chr(0x093E), chr(0x0EB1), chr(0x0E31), chr(0x07A6), chr(0xFE0F), chr(0x1F3FB)]
_DANGER = [
    '\x1b', '\x1b[2J', '\x1b[H', '\x1b[10A', '\x1b[5;9H', '\x1b[2K', '\x1b[1G',
    '\x1b[3D', '\x1b[6C', '\x1b[22G', '\x1b]0;title\x07', '\x1b]0;t\x1b\\',
    '\x1b]52;c;cGFy\x07', '\x1b]8;;http://x\x07', '\x1b(B', '\x1b[200~',
    '\x1b[201~', '\x1b[?2004h', '\x1b[?1049h', '\x1b[?1049l', '\x1b[?2026h',
    '\x9b', '\x9d', '\x90', '\x00', '\x07', '\x7f', '\r', '\b', '\t', '\n',
    '\u200b', '\u200e', '\u202e', '\u2066', '\u2069', '\ufeff', '\u2060',
    '\u2028', '\u2029', '\x1b[31m', '\x1b[38;5;200m', '\x1b[48;2;1;2;3m']
_TEXT = list('abcXYZ 0189.:;=/#|<>"\'\\') + [
    '\u20ac', '\u00e9', '\U0001f600', 'echo ', 'ls -la', 'prompt$ ']
_OSC_FEATURES = ('osc_title', 'osc_clipboard', 'osc_clipboard_read',
                 'osc_hyperlink', 'osc_notify', 'osc_palette', 'osc_cwd')
_PASTE_WARN = ('never', 'unicode', 'always')

## A feed must never take longer than this: real bounded input renders in
## milliseconds, so a multi-second feed is a reshape DoS, not machine load.
_FEED_BUDGET_S = 8.0
## No visible cell may hold more than a bounded grapheme; generous headroom over the
## stream-safe cap so a legitimately long (but bounded) cluster never trips it.
_CELL_MAX = 256


def _rand_token(rnd):
    kind = rnd.random()
    if kind < 0.30:
        return rnd.choice(_DANGER)
    if kind < 0.55:
        ## a run of one primitive: the pathological / DoS-probing shape
        return rnd.choice(_COMBINING + _DANGER + _TEXT) * rnd.randint(0, 600)
    if kind < 0.75:
        return rnd.choice(_COMBINING)
    return rnd.choice(_TEXT)


def _rand_bytes_chunk(rnd, max_tokens=20):
    text = ''.join(_rand_token(rnd) for _ in range(rnd.randint(0, max_tokens)))
    ## bounded well under a pipe buffer so a synthetic feed never blocks
    return text.encode('utf-8', 'surrogatepass')[:40000]


def _assert(condition, message, seed):
    if not condition:
        raise AssertionError('{0} (replay --seed {1})'.format(message, seed))


def _feed(term, raw):
    """Drive the real _on_readable with `raw` via a pipe, as the child would. Returns
    the wall-clock seconds the feed took (the DoS signal)."""
    r, w = os.pipe()
    old = term._fd
    term._fd = r
    start = time.monotonic()
    try:
        os.write(w, raw)
        os.close(w)
        term._on_readable()
    finally:
        term._fd = old
        os.close(r)
    return time.monotonic() - start


def _check_document(term, seed, ctx):
    ## The visible transcript is the sanitization guarantee: no control code point
    ## reaches the document except the structural newline/tab. A bare `ord >= 0x20`
    ## would ADMIT DEL (0x7F) and the C1 controls (0x80-0x9F) -- both non-printable,
    ## both outside the sanitizer's proven display alphabet (0x20-0x7E) -- so name the
    ## ranges: printable ASCII, or printable unicode (>= 0xA0), never a C0/DEL/C1.
    for ch in term.toPlainText():
        _assert(ch in ('\n', '\t') or 0x20 <= ord(ch) <= 0x7e or ord(ch) >= 0xa0,
                'raw control {0!r} reached the document ({1})'.format(ch, ctx), seed)


def _check_cells_bounded(term, seed, ctx):
    screen = term._screen
    if screen is None:
        return
    for y in list(screen.buffer.keys()):
        row = screen.buffer[y]
        for x in list(row.keys()):
            _assert(len(row[x].data) <= _CELL_MAX,
                    'a TUI cell grew unbounded ({0})'.format(ctx), seed)


## ---- fuzz phases ------------------------------------------------------------

def phase_feed(rnd, iterations, seed):
    ## Feed adversarial output into a persistent CLI-mode terminal in every display
    ## mode; the render pipeline must not crash, freeze, or leak a control byte.
    modes = list(S.DISPLAY_MODES)
    pool = {m: SecureTerminal(command='/bin/cat') for m in modes}
    for m, term in pool.items():
        term.apply_mode(m)
    for _ in range(iterations):
        m = rnd.choice(modes)
        term = pool[m]
        raw = _rand_bytes_chunk(rnd)
        dt = _feed(term, raw)
        _assert(dt < _FEED_BUDGET_S,
                'CLI {0} feed took {1:.1f}s (DoS) on {2} bytes'
                .format(m, dt, len(raw)), seed)
        _check_document(term, seed, 'cli-feed:' + m)


def phase_tui(rnd, iterations, seed):
    ## The pyte/TUI path: the interpreter runs, so the grid must stay bounded and no
    ## cell may accumulate an unbounded combining cluster.
    term = SecureTerminal(command='/bin/cat', tui=True)
    modes = list(S.DISPLAY_MODES)
    for _ in range(iterations):
        term.apply_mode(rnd.choice(modes))
        raw = _rand_bytes_chunk(rnd)
        dt = _feed(term, raw)
        _assert(dt < _FEED_BUDGET_S,
                'TUI feed took {0:.1f}s (DoS) on {1} bytes'.format(dt, len(raw)), seed)
        _check_document(term, seed, 'tui-feed')
        _check_cells_bounded(term, seed, 'tui-feed')


def phase_switch(rnd, iterations, seed):
    ## Flip CLI<->TUI and toggle OSC opt-ins mid-stream: a mode switch re-renders
    ## from retained raw output and must not crash or leak.
    term = SecureTerminal(command='/bin/cat')
    for _ in range(iterations):
        _feed(term, _rand_bytes_chunk(rnd))
        term.apply_tui(not term.tui_active())            # exercise both directions
        term.apply_osc(rnd.choice(_OSC_FEATURES), rnd.random() < 0.5)
        term.apply_mode(rnd.choice(list(S.DISPLAY_MODES)))
        _check_document(term, seed, 'switch')
        _check_cells_bounded(term, seed, 'switch')


def phase_paste(rnd, iterations, seed):
    ## Random clipboard content pasted into the widget: nothing dangerous may reach
    ## the pty. Spy on _write and assert the payload carries no raw control (a
    ## bracketed-paste wrapper's own ESC brackets are the only allowed escape).
    term = SecureTerminal(command='/bin/cat')
    sent: list[bytes] = []
    term._write = lambda data, _s=sent: _s.append(data)   # capture pty writes
    for _ in range(iterations):
        term.apply_paste_warn(rnd.choice(_PASTE_WARN))
        text = ''.join(_rand_token(rnd) for _ in range(rnd.randint(0, 12)))
        sent.clear()
        mime = QMimeData()
        mime.setText(text)
        term.insertFromMimeData(mime)
        if term.review_pending():
            term.dispatch_pending_paste(rnd.choice(('stripped', 'unicode', 'reject')))
        for data in sent:
            ## strip a bracketed-paste wrapper, then no ESC/C0/DEL (bar the submit
            ## CR/tab). At the BYTE level 0x80-0xFF are legitimate UTF-8 lead/
            ## continuation bytes of printable unicode a keep-printable paste delivers,
            ## so they pass; DEL (0x7F) is never part of a UTF-8 sequence, so a bare
            ## `byte >= 0x20` wrongly admitting it is a real gap -- exclude it.
            payload = data.replace(b'\x1b[200~', b'').replace(b'\x1b[201~', b'')
            for byte in payload:
                _assert(byte in (0x09, 0x0d) or 0x20 <= byte <= 0x7e or byte >= 0x80,
                        'paste leaked control byte {0:#x} to the pty on {1!r}'
                        .format(byte, text), seed)


def phase_keys(rnd, iterations, seed):
    ## Random key events (printable + control chords) plus mode churn: input
    ## handling must never crash the widget.
    term = SecureTerminal(command='/bin/cat')
    term._write = lambda data: None                      # swallow keystrokes
    keys = [Qt.Key.Key_A, Qt.Key.Key_C, Qt.Key.Key_D, Qt.Key.Key_U,
            Qt.Key.Key_L, Qt.Key.Key_Return, Qt.Key.Key_Backspace,
            Qt.Key.Key_Up, Qt.Key.Key_Tab, Qt.Key.Key_Escape, Qt.Key.Key_1]
    mods = [Qt.KeyboardModifier.NoModifier, Qt.KeyboardModifier.ControlModifier,
            Qt.KeyboardModifier.ShiftModifier,
            Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier]
    for _ in range(iterations):
        ev = QKeyEvent(QEvent.Type.KeyPress, rnd.choice(keys), rnd.choice(mods),
                       rnd.choice(('', 'a', '1', ' ')))
        term.keyPressEvent(ev)
        term.apply_mode(rnd.choice(list(S.DISPLAY_MODES)))


def phase_review(rnd, iterations, seed):
    ## The review bar (review.py) reviews untrusted text in BOTH directions, in the ONE
    ## editable, revealed box (revealed_editor.py). Fuzz show_review with random text +
    ## kind, then the three in-place transforms (Strip / ASCII-fold / Restore) and a
    ## live rerender_mirror (a mode flip while the review is open): none may crash, the
    ## box must never surface a raw ESC (escape sequences are rendered, not shown), and
    ## the box source must stay display-clean (no control/invisible slips through the
    ## keep-printable + transform pipeline). The DELIVER path itself (the box PLUS the
    ## un-shown beyond-cap tail, composed and handed to the dispatch) is fuzzed
    ## separately in _fuzz_review_delivery below -- this loop's inputs are all shorter
    ## than the box cap, so they never populate the tail.
    from secure_terminal.review import ReviewBar
    from secure_terminal.sanitize import sanitize_clipboard, reveal_display
    from PyQt6.QtWidgets import QWidget, QMessageBox
    win = QWidget()
    term = SecureTerminal(command='/bin/cat')
    bar = ReviewBar(win)
    _saved_q = QMessageBox.question
    QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
    try:
        for _ in range(iterations):
            raw = ''.join(_rand_token(rnd) for _ in range(rnd.randint(0, 15)))
            bar.show_review(term, raw, rnd.randint(0, 3),
                            rnd.choice(('paste', 'copy', 'clipboard', 'bogus')))
            _assert(bar.reviewed_term() is term,
                    'review bar did not take the term for {0!r}'.format(raw), seed)
            # Each transform leaves the box source at a fixed point of ITS tier: Strip and
            # ASCII-fold reduce to pure ASCII (sanitize_clipboard-clean); Restore RE-REVEALS
            # -- the invisibles/bidi/control return as EVIDENCE, rendered as marked cells, so
            # the reveal box is reveal_display-clean (idempotent), NOT sanitize-clean. The
            # DELIVERED text's control-byte safety is a separate sanitize property (Deliver is
            # blocked while a revealed box still holds hidden chars); it is covered elsewhere.
            for action, clean, tier in ((bar._do_strip, sanitize_clipboard, 'ASCII'),
                                        (bar._do_fold, sanitize_clipboard, 'ASCII'),
                                        (bar._do_restore, reveal_display, 'reveal')):
                action()
                box = bar._editor.source()
                _assert('\x1b' not in bar._editor.toPlainText(),
                        'review box surfaced a raw ESC on {0!r}'.format(raw), seed)
                _assert(box == clean(box),
                        'review box holds a non-{0}-clean char on {1!r}'.format(tier, raw),
                        seed)
            # flip the tab's mode while the review is open: the box must re-render
            # (the live-follow path) without raising
            term.apply_mode(rnd.choice(list(S.DISPLAY_MODES)))
            bar.rerender_mirror()
            bar.hide_review()
            # drive the REAL Deliver path with a populated un-shown tail
            _fuzz_review_delivery(rnd, bar, term, seed)
    finally:
        QMessageBox.question = _saved_q


def _fuzz_review_delivery(rnd, bar, term, seed):
    ## The beyond-cap tail is the review bar's subtlest surface: raw[_BOX_MAX:] is held
    ## OUT of the editable box (never shown, never editable) yet STILL delivered,
    ## neutralized to the tier the visible box got (review._TIER[_active_mode]). Two
    ## properties the box-only fuzz above cannot reach because its inputs never overflow
    ## the cap:
    ##   (A) a Deliver the box-gate allowed never hands ANY invisible/bidi/control byte
    ##       to the dispatch -- the un-shown tail cannot smuggle one in;
    ##   (B) the un-shown tail is never WEAKER than the transform the user pressed --
    ##       a [Strip unicode] / [ASCII-fold] leaves the tail pure ASCII (else a paste
    ##       longer than the cap would slip a homoglyph past a strip), and a
    ##       [Keep printable] tail is at least invisible-free.
    ## This is the crit1 tail-neutralization regression, now fuzzed across every tier
    ## and both trust directions instead of a single hand-built example.
    from secure_terminal import review as R
    ## Shrink the box cap so a short adversarial paste overflows it CHEAPLY: the real
    ## 20000-char cap would render 20k cells per iteration. The tier logic under test is
    ## identical at any cap -- only the split point moves.
    saved_cap = R._BOX_MAX
    R._BOX_MAX = 16
    ## Capture what the bar hands the dispatch (box + neutralized tail) without the real
    ## sanitize / pty / clipboard side effects. paste/copy dispatch live on the term
    ## CLASS and clipboard's on another class entirely, so a fresh term has none of them
    ## as instance attributes -- popping the instance shadow in the finally restores the
    ## class methods and drops the clipboard stand-in.
    captured = {}

    def _cap(action, text=None):
        captured['action'] = action
        captured['text'] = text

    names = ('dispatch_pending_paste', 'dispatch_pending_copy',
             'dispatch_pending_clipboard')
    for name in names:
        setattr(term, name, _cap)
    try:
        for kind in ('paste', 'copy', 'clipboard', 'bogus'):
            # box slice pure ASCII (so a strip/fold leaves the box ASCII); the tail
            # ALWAYS carries a look-alike + an invisible (U+0430 Cyrillic a, U+200B
            # ZWSP) so both invariants keep teeth, plus random adversarial tokens. The
            # fixed prefix also guarantees a non-empty tail -- a _rand_token run can be
            # '' (its repeat-count arm can pick 0), which would otherwise leave the box
            # exactly at the cap and populate no tail.
            tail = '\u0430\u200b' + ''.join(_rand_token(rnd)
                                            for _ in range(rnd.randint(0, 6)))
            raw = 'a' * R._BOX_MAX + tail
            for tform, mode in ((bar._do_keep, 'keep'), (bar._do_strip, 'strip'),
                                (bar._do_fold, 'fold')):
                bar.show_review(term, raw, 0, kind)
                _assert(bar._tail, 'the tail did not populate for {0!r}'.format(raw), seed)
                tform()
                _assert(bar._active_mode == mode,
                        'transform left _active_mode {0!r}, expected {1!r}'
                        .format(bar._active_mode, mode), seed)
                captured.clear()
                bar._remaining = 0            # bypass the anti-fat-finger countdown
                bar._deliver_clicked()        # the REAL gate re-check + _choose('deliver')
                _assert('text' in captured,
                        'Deliver did not dispatch (kind={0} mode={1})'.format(kind, mode),
                        seed)
                _assert(captured['action'] == 'unicode',
                        'Deliver dispatched {0!r}, not the re-sanitizing "unicode" action'
                        .format(captured['action']), seed)
                composite = captured['text']
                # (A) nothing hidden crosses -- the bar must not hand one over even before
                # the dispatch's own re-drop backstop.
                _assert(bar._blocked_count(composite) == 0,
                        'delivered composite carries {0} hidden char(s) (kind={1} mode={2})'
                        .format(bar._blocked_count(composite), kind, mode), seed)
                # (B) the un-shown tail is no weaker than the chosen tier.
                tail_out = bar._tail_delivered()
                if mode in ('strip', 'fold'):
                    _assert(all(ord(c) < 0x80 for c in tail_out),
                            'un-shown tail kept non-ASCII under {0} (kind={1} tail={2!r})'
                            .format(mode, kind, tail_out), seed)
                else:
                    _assert(bar._blocked_count(tail_out) == 0,
                            'un-shown tail kept a hidden char under keep (kind={0} '
                            'tail={1!r})'.format(kind, tail_out), seed)
            # a manual box edit AFTER a strip, then Deliver: the box is WYSIWYG (a
            # re-typed visible character -- incl. a look-alike -- legitimately survives
            # and shows), but the un-shown TAIL must still respect the active tier and
            # add no hidden char. The edit draws from _TEXT (visible: ASCII + look-
            # alikes/emoji), NOT _rand_token, so it never re-introduces a hidden char
            # that the Deliver gate would (correctly) block -- that block path is the
            # gate's own concern, covered in test_review.py, not this tail assertion.
            bar.show_review(term, raw, 0, kind)
            bar._do_strip()
            bar._editor.set_source(''.join(rnd.choice(_TEXT)
                                           for _ in range(rnd.randint(0, 8))))
            captured.clear()
            bar._remaining = 0
            bar._deliver_clicked()
            _assert('text' in captured,
                    'edited Deliver did not dispatch (kind={0})'.format(kind), seed)
            _assert(all(ord(c) < 0x80 for c in bar._tail_delivered()),
                    'un-shown tail kept non-ASCII under strip after a manual edit '
                    '(kind={0})'.format(kind), seed)
            _assert(bar._blocked_count(captured['text']) == 0,
                    'edited delivery carried a hidden char (kind={0})'.format(kind), seed)
            bar.hide_review()
    finally:
        for name in names:
            term.__dict__.pop(name, None)
        R._BOX_MAX = saved_cap


PHASES = (
    ('feed', phase_feed),
    ('tui', phase_tui),
    ('switch', phase_switch),
    ('paste', phase_paste),
    ('keys', phase_keys),
    ('review', phase_review),
)


def run(rnd, per_phase, seed, only=None):
    """Run the fuzz phases; a shared app is assumed live. Returns the phase names
    run. Raises AssertionError (with a replay seed) on any invariant breach."""
    ran = []
    for name, func in PHASES:
        if only and name != only:
            continue
        func(rnd, per_phase, seed)
        ran.append(name)
    return ran


def main():                                              # pragma: no cover - CLI entry
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=6000)
    parser.add_argument('--seed', type=int, default=None)
    parser.add_argument('--phase', default=None, help='run only this phase')
    opts = parser.parse_args()

    _app = QApplication.instance() or QApplication(sys.argv)
    seed = opts.seed if opts.seed is not None else random.randrange(2 ** 32)
    rnd = random.Random(seed)
    names = [opts.phase] if opts.phase else [n for n, _ in PHASES]
    per_phase = max(1, opts.iterations // len(names))
    print('fuzz_widget: seed={0} iterations={1}'.format(seed, opts.iterations),
          flush=True)
    for name in names:
        try:
            run(rnd, per_phase, seed, only=name)
        except Exception:
            sys.stderr.write("fuzz_widget: FAILURE in phase '{0}' -- replay with "
                             '--seed {1}\n'.format(name, seed))
            raise
        print("fuzz_widget: phase '{0}' ok ({1} iterations)".format(name, per_phase),
              flush=True)
    print('fuzz_widget: PASS', flush=True)
    sys.stdout.flush()
    os._exit(0)                                          # skip Qt's offscreen teardown


if __name__ == '__main__':                               # pragma: no cover - CLI entry
    main()
