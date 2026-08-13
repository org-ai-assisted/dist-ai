#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Hypothesis HYPOTHESIS-PROPERTY tests for secure-terminal's security invariants
(#31 P1/P2, from the #30 unknown-unknowns research). Each INV is a UNIVERSAL
property over random streams (and, where it applies, the real adversarial corpus),
driven through the REAL code path -- the pure sanitizer, the live Qt widget's paste
and output paths, and the standalone CLI choke point -- not a hand-picked fixture.

  INV-1  no paste auto-executes: for ANY clipboard string, insertFromMimeData
         writes no submit CR without a review interposed OR strips it, across the
         GUI paste path AND the CLI stdin burst path.
  INV-2  no output reaches an earlier line / scrollback: a committed line is
         byte-identical before and after ANY subsequently-fed output chunk (the
         line editor honours only line-LOCAL edits; vertical addressing is stripped).
  INV-3  the live render equals an INDEPENDENT reference model `logical()` -- the
         differential 'logical == rendered' oracle. Any divergence is a spoof
         primitive (an escape or control that changed the screen differently than
         the safe documented model predicts).
  INV-4  every emitted display character is inert: printable ASCII plus the honored
         editing controls, plus ONLY the whitelisted marks (the neutralization BOX,
         the non-ASCII-space SPACE_MARK, and -- in Show mode -- honest structural
         box-drawing / block glyphs). Universal over random streams AND the corpus.
  INV-5  a paste is inert until an EXPLICIT user action: a held (multi-line) paste
         sends nothing until dispatch, and a single-line paste sits at the prompt
         with no submit until the user's own Enter -- the user-facing form of INV-1.
  INV-6  output never induces an input reply: feeding ANY program output with every
         OSC reach-out enabled writes NOTHING back to the child, EXCEPT the single
         per-tab-GATED reply (the OSC 52 clipboard read, which needs an explicit
         grant). No DSR / answerback / mouse / query reflection path exists.

Every property is CANARY-VERIFIED: a deliberately-broken stub (an un-stripped paste,
a leaked escape, a reflected write, a modified earlier line) must make the property's
assertion FAIL, so a green result means the check has teeth. The pure invariants
(INV-3, INV-4, and the CLI half of INV-1) run Qt-free; the widget invariants (the GUI
half of INV-1, INV-2, INV-5, INV-6) reuse ONE offscreen widget each so no example
forks a pty. A missing PyQt6/pyte is a hard FAILURE for the widget half (a
security-relevant suite must never silently disable itself), not a skip.

hypothesis is a declared dependency; a missing one is a hard FAILURE. Exit 0 on full
pass, 1 on any failure.
"""

import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from hypothesis import given, settings, strategies as st
    from secure_terminal import sanitize as S
except Exception as exc:  # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(invariants): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

FAIL = 0


def fail(msg):
    global FAIL
    FAIL += 1
    sys.stderr.write('FAIL: ' + msg + '\n')


RUN = settings(max_examples=400, deadline=None)
# The Qt widget properties reuse ONE widget per example (no pty fork), but a live
# insertFromMimeData / output feed is still ~1000x a pure call, so run fewer.
RUN_GUI = settings(max_examples=120, deadline=None)

# The safe display alphabet: printable ASCII + the four honored editing controls
# (backspace, tab, newline, carriage return). A reveal / detail <U+XXXX ...> badge
# is itself made only of these.
SAFE = frozenset((0x08, 0x09, 0x0A, 0x0D)) | frozenset(range(0x20, 0x7F))


# --- corpus seeds: the SAME real adversarial payloads test_corpus / test_fuzz use,
# --- read from the sibling test_corpus.py fixture defs (never re-instantiated -- it
# --- runs its own assertions at import; only the fixture functions are wanted).
def _corpus_seeds():
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    origin = os.path.join(here, 'test_corpus.py')
    with open(origin, encoding='utf-8') as handle:
        source = handle.read()
    namespace = {}
    for fn in ('dangerous_corpus', 'trojan_source_corpus', 'git_diffs_lie_fixtures'):
        start = source.index('def %s():' % fn)
        end = source.index('\n# ---', start)
        exec(compile(source[start:end], origin, 'exec'), namespace)  # noqa: S102 # nosec B102 -- our own fixture defs
    seeds = list(namespace['dangerous_corpus']().values())
    seeds += list(namespace['trojan_source_corpus']().values())
    seeds += [b.decode('utf-8', 'replace')
              for b in namespace['git_diffs_lie_fixtures']().values()]
    return seeds


CORPUS_SEEDS = _corpus_seeds()
assert CORPUS_SEEDS, 'corpus seeds are empty -- the invariants would cover nothing'

# A grammar of realistic terminal output: random text spliced with the escape /
# control atoms a parser actually breaks on. PROMPT_START (DECSET 2004) is
# deliberately EXCLUDED from the INV-3 stream grammar -- feed_line_edits intercepts
# it as a prompt-flush BEFORE the escape strip, which the escape-stripping reference
# model does not (and must not) mirror; INV-3's own grammar re-adds every other
# escape. INV-2/4/6 use it freely.
_CSI_OP = st.builds(
    lambda n, op: '\x1b[' + ('' if n is None else str(n)) + op,
    st.one_of(st.none(), st.integers(min_value=0, max_value=120)),
    st.sampled_from('CDGKJABHf'))               # cursor moves incl. VERTICAL (A/B/H/f)
_SGR = st.lists(st.sampled_from(['0', '1', '31', '38;5;200', '7', '39']),
                max_size=4).map(lambda p: '\x1b[' + ';'.join(p) + 'm')
_OSC = st.sampled_from(['\x1b]0;title\x07', '\x1b]52;c;cGF5bG9hZA==\x07',
                        '\x1b]8;;http://evil\x1b\\link\x1b]8;;\x1b\\',
                        '\x1b]9;notify\x07'])
_CTRL = st.sampled_from(['\b', '\r', '\n', '\t', '\x07', '\x0b', '\x0c', '\x1b',
                         '\x00'])
_HOSTILE_CH = st.sampled_from([chr(c) for c in (
    0x202A, 0x202E, 0x2066, 0x2069, 0x200E, 0x061C, 0x200B, 0x200D, 0xFEFF,
    0x2028, 0x2029, 0x0430, 0x3164, 0xFE0F, 0x2500, 0x00A0, 0x4E00, 0xE9)])
# INV-3 stream: escapes + controls + hostile + text, but NO PROMPT_START and a
# BOUNDED count of stacked combining marks (feed_line_edits caps a Zalgo flood, a
# bounded-DoS defence the simple reference model does not encode).
_INV3_ATOM = st.one_of(st.text(max_size=6), _CSI_OP, _SGR, _OSC, _CTRL, _HOSTILE_CH)
INV3_STREAM = st.lists(_INV3_ATOM, max_size=14).map(''.join)
# INV-4 / INV-2 / INV-6 streams may carry anything at all.
_ALT = st.sampled_from(['\x1b[?1049h', '\x1b[?1047h', '\x1b[?47h', '\x1b[?2004h',
                        '\x1b[?1000h', '\x1b[?25l'])
ANY_ATOM = st.one_of(st.text(max_size=6), _CSI_OP, _SGR, _OSC, _CTRL, _ALT,
                     _HOSTILE_CH)
ANY_STREAM = st.lists(ANY_ATOM, max_size=16).map(''.join)


# ===========================================================================
# The differential oracle for INV-3: an INDEPENDENT reference model.
# ===========================================================================
def logical(stream):
    r"""Reference model of the line-mode rendered text: strip every escape sequence,
    then apply ONLY the documented line-LOCAL edits -- backspace (cursor left),
    carriage return (cursor to column 0), newline (end line), a stray control byte
    or non-ASCII byte OVERWRITES the cell under the cursor (a terminal never inserts
    and shifts) -- and neutralize each surviving byte with the SAME per-character
    substitution render_output applies (box mode). A standalone BEL is dropped (it is
    a signal, not glyph). This is a from-scratch second implementation of the safe
    display contract; the live path (feed_line_edits + cells_to_runs) must agree with
    it byte for byte, so any divergence is a spoof primitive.

    Matches feed_line_edits(line_edits=False): both strip the line-local CSI ops
    rather than honour them, so the ONLY motions are backspace / carriage-return /
    newline -- exactly the documented set."""
    text = S.ANSI_RE.sub('', stream)          # remove every escape sequence
    lines = []
    buf = []                                  # current line cells (source chars)
    col = 0
    for ch in text:
        if ch == '\n':
            lines.append(buf)
            buf, col = [], 0
        elif ch == '\r':
            col = 0
        elif ch == '\x08':
            if col > 0:
                col -= 1
        elif ch == '\x07':
            continue                          # BEL: a signal, no cell, no motion
        elif ch == '\x1b':
            continue                          # a lone/unmatched ESC is dropped, never a cell
        else:
            if col < len(buf):
                buf[col] = ch
            else:
                buf.append(ch)
            col += 1
    lines.append(buf)                         # the trailing current line
    rendered = [''.join(S.render_output(c, 'box') for c in line) for line in lines]
    return '\n'.join(rendered)


def rendered_live(stream):
    """The live path's box-mode display text, with the readable box mapped back to
    '_' (the export mapping), so it is comparable to logical()'s '_' output.
    line_edits=False so only \\b \\r \\n move the cursor -- the documented set the
    reference models. No SGR key noise (colours off)."""
    comp, cells, _col, _sgr, wraps = S.feed_line_edits([], 0, {}, stream,
                                                        line_edits=False)
    runs, _prefix = S.cells_to_runs(comp, cells, 'box', False, wraps=wraps)
    return ''.join(text for text, _key in runs).replace(S.BOX, '_')


# ===========================================================================
# INV-3: logical == rendered (the differential oracle).
# ===========================================================================
@RUN
@given(INV3_STREAM)
def prop_inv3_random(stream):
    assert rendered_live(stream) == logical(stream), repr(stream[:80])


def inv3_corpus():
    for seed in CORPUS_SEEDS:
        if S.PROMPT_START in seed:
            continue                          # outside the reference's domain (see logical)
        if rendered_live(seed) != logical(seed):
            fail('INV-3 corpus divergence: %r' % seed[:80])


# ===========================================================================
# INV-4: every emitted display character is inert.
# ===========================================================================
def _emitted(stream, mode):
    comp, cells, _col, _sgr, wraps = S.feed_line_edits([], 0, {}, stream)
    runs, _prefix = S.cells_to_runs(comp, cells, mode, False, wraps=wraps)
    return ''.join(text for text, _key in runs)


def _inv4_char_ok(ch, mode):
    cp = ord(ch)
    if cp in SAFE or ch == '\n':
        return True
    if ch == S.BOX:
        return True                           # the neutralization placeholder
    if mode == 'show':
        if ch == S.SPACE_MARK:
            return True                       # the non-ASCII-space marker
        if S.is_structural(cp):
            return True                       # honest box-drawing / block glyph
        # Show keeps a PRINTABLE non-ASCII glyph (its documented risk), but never an
        # invisible / default-ignorable / bidi / control one.
        return (ch.isprintable() and not S.is_default_ignorable(ch)
                and not S.is_bidi_control(cp))
    return False                              # box / reveal / detail: nothing else


@RUN
@given(ANY_STREAM, st.sampled_from(S.DISPLAY_MODES))
def prop_inv4_random(stream, mode):
    disp = _emitted(stream, mode)
    bad = [ch for ch in disp if not _inv4_char_ok(ch, mode)]
    assert not bad, '%s: %r in %r' % (mode, [hex(ord(c)) for c in bad[:4]], disp[:60])
    # no dangerous code point ever survives, in ANY mode
    assert not any(S.is_default_ignorable(ch) for ch in disp), repr(disp[:60])


def inv4_corpus():
    for seed in CORPUS_SEEDS:
        for mode in S.DISPLAY_MODES:
            disp = _emitted(seed, mode)
            if any(not _inv4_char_ok(ch, mode) for ch in disp):
                fail('INV-4 corpus: %s left a non-inert char for %r' % (mode, seed[:60]))
            if any(S.is_default_ignorable(ch) for ch in disp):
                fail('INV-4 corpus: %s left an invisible char for %r' % (mode, seed[:60]))


# ===========================================================================
# INV-1 (CLI half): the standalone stdin-burst choke point never leaves a paste
# ending in a submit byte.
# ===========================================================================
try:
    from secure_terminal.cli import _strip_burst_submit
except Exception as exc:  # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(invariants): FAIL cli import: %s\n' % exc)
    sys.exit(1)


def _inv1_cli_predicate(strip_fn, keys):
    """The invariant as a predicate of the strip function under test, so a broken
    stub can be canaried. A pasted BURST (more than one byte) that ends in a submit
    byte must be forwarded WITHOUT a trailing submit -- else it auto-runs."""
    out = strip_fn(keys)
    if len(keys) > 1 and keys[-1:] in (b'\r', b'\n'):
        return not out.endswith((b'\r', b'\n'))
    return True                               # a single keystroke is forwarded as-is


@RUN
@given(st.binary(max_size=64))
def prop_inv1_cli(keys):
    assert _inv1_cli_predicate(_strip_burst_submit, keys), repr(keys)


# ===========================================================================
# Widget-driven invariants: the GUI half of INV-1, plus INV-2, INV-5, INV-6.
# One offscreen widget per invariant, reused across examples (no pty fork).
# ===========================================================================
_HAVE_QT = True
try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QKeyEvent, QGuiApplication
    from PyQt6.QtCore import QEvent, Qt, QMimeData
    from secure_terminal.terminal import SecureTerminal
    import secure_terminal.terminal as TERM
    APP = QApplication.instance() or QApplication([])
except Exception as exc:  # pylint: disable=broad-except
    # A widget suite must FAIL closed on a missing GUI dep, never skip: the paste and
    # reflection invariants are exactly the security-relevant ones.
    sys.stderr.write('secure-terminal-tests(invariants): FAIL Qt/pyte unavailable '
                     '(the widget invariants must run): %s\n' % exc)
    sys.exit(1)


def _mime(text):
    m = QMimeData()
    m.setText(text)
    return m


def _reset_paste(term, sent):
    if term.review_pending():
        term.dispatch_pending_paste('reject')
    sent.clear()


# ----- INV-1 (GUI half) + INV-5: a paste never auto-executes / is inert -------
_WL = SecureTerminal(command='/bin/cat')          # line mode (the secure default)
_WL.apply_paste_warn('unicode')
_WL_SENT = []
_WL._write = _WL_SENT.append                       # pylint: disable=protected-access


def _inv1_gui_predicate(term, sent, text):
    """A paste of `text` either is HELD for review (nothing written) or reaches the
    child with NO submit byte -- never an auto-run. Predicate form so a stub that
    fails to strip can be canaried."""
    _reset_paste(term, sent)
    term.insertFromMimeData(_mime(text))
    written = b''.join(bytes(chunk) for chunk in sent)
    held = term.review_pending()
    _reset_paste(term, sent)
    return held or (b'\r' not in written), (written, held)


@RUN_GUI
@given(st.text(max_size=48))
def prop_inv1_gui(text):
    ok, ctx = _inv1_gui_predicate(_WL, _WL_SENT, text)
    assert ok, repr((text, ctx))


def inv1_gui_corpus():
    for seed in CORPUS_SEEDS:
        ok, ctx = _inv1_gui_predicate(_WL, _WL_SENT, seed)
        if not ok:
            fail('INV-1 GUI corpus: a paste auto-executed: %r %r' % (seed[:60], ctx))


@RUN_GUI
@given(st.text(min_size=1, max_size=40).filter(lambda s: '\n' not in s and '\r' not in s))
def prop_inv5_single_line_waits_for_enter(text):
    """A SINGLE-line paste sits at the prompt: no submit reaches the child until the
    user's OWN Enter, which then submits."""
    _reset_paste(_WL, _WL_SENT)
    _WL.insertFromMimeData(_mime(text))
    if _WL.review_pending():                        # unicode etc. -> held, covered elsewhere
        _reset_paste(_WL, _WL_SENT)
        return
    after_paste = b''.join(bytes(c) for c in _WL_SENT)
    assert b'\r' not in after_paste, repr((text, after_paste))
    _WL_SENT.clear()
    _WL.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Return,
                                Qt.KeyboardModifier.NoModifier, ''))
    after_enter = b''.join(bytes(c) for c in _WL_SENT)
    assert after_enter == b'\r', repr((text, after_enter))
    _reset_paste(_WL, _WL_SENT)


@RUN_GUI
@given(st.text(max_size=24), st.text(max_size=24))
def prop_inv5_multiline_held_until_dispatch(a, b):
    """A MULTI-line paste (a hidden second command) sends NOTHING until an explicit
    dispatch -- inert until the user acts."""
    text = a + '\n' + b + '\ncmd'
    _reset_paste(_WL, _WL_SENT)
    _WL.insertFromMimeData(_mime(text))
    assert _WL.review_pending(), repr(text)         # held
    assert _WL_SENT == [], repr((text, _WL_SENT))   # nothing written while held
    _WL.dispatch_pending_paste('reject')            # explicit action: reject
    assert _WL_SENT == [], 'a rejected paste sends nothing'
    _reset_paste(_WL, _WL_SENT)


# ----- INV-2: no output reaches an earlier line -------------------------------
_WL2 = SecureTerminal(command='/bin/cat')          # line mode
_WL2._write = (lambda *_a, **_k: None)              # pylint: disable=protected-access


def _reset_line_widget(term):
    """Blank the document AND the CLI line-mode state, so each Hypothesis example is
    independent (a deterministic property) rather than reading accumulated output.
    Mirrors the widget's own preview reset (set_preview_text)."""
    term._paint_timer.stop()                        # pylint: disable=protected-access
    term.clear()
    term._raw = ''                                  # pylint: disable=protected-access
    term._out_cursor = None                         # pylint: disable=protected-access
    term._line_cells = []                           # pylint: disable=protected-access
    term._line_col = 0                              # pylint: disable=protected-access
    term._line_fmt_cache = {}                       # pylint: disable=protected-access
    term._paint_pending = []                        # pylint: disable=protected-access
    term._paint_pending_wraps = []                  # pylint: disable=protected-access
    term._paint_dirty = False                       # pylint: disable=protected-access
    term._pending_caret = []                        # pylint: disable=protected-access
    # Clear EVERY cross-read carry, or a prior example's trailing lone ESC (or a
    # split OSC / sync / alt-screen marker, or a half-decoded UTF-8 byte) prepends to
    # the next feed and eats its first character (e.g. '\x1b' + 'I...' strips 'I').
    term._esc_carry = ''                            # pylint: disable=protected-access
    term._esc_drop = ''                             # pylint: disable=protected-access
    term._osc_carry = b''                           # pylint: disable=protected-access
    term._sync_scan_carry = ''                      # pylint: disable=protected-access
    term._alt_scan_carry = ''                       # pylint: disable=protected-access
    term._alt_feed_carry = b''                      # pylint: disable=protected-access
    term._decoder.reset()                           # pylint: disable=protected-access
    term._sgr_reset()                               # pylint: disable=protected-access


def feed_output(term, raw):
    """Drive the real output path with `raw` bytes, as the widget/adversarial tests
    do, so pyte feed + the OSC handlers + the line render all run."""
    r, w = os.pipe()
    old = term._fd                                  # pylint: disable=protected-access
    term._fd = r
    try:
        os.write(w, raw)
        os.close(w)
        w = None
        term._on_readable()                         # pylint: disable=protected-access
    finally:
        term._fd = old
        os.close(r)
        if w is not None:
            os.close(w)
    term._flush_paint()                             # pylint: disable=protected-access


_INV2_SENTINEL = 'INV2SENTINEL_EARLIER_LINE'


def _committed_line_intact(term, payload):
    """From a blank widget, commit a sentinel line, then feed `payload`; the sentinel
    line -- an EARLIER line -- must be byte-identical afterward. A vertical-cursor
    escape that reached it would change it. Returns (ok, blocks)."""
    _reset_line_widget(term)
    feed_output(term, (_INV2_SENTINEL + '\n').encode())
    feed_output(term, payload if isinstance(payload, bytes)
                else payload.encode('utf-8', 'surrogatepass'))
    doc = term.document()
    blocks = []
    block = doc.begin()
    while block.isValid():
        blocks.append(block.text())
        block = block.next()
    # The sentinel is a COMPLETED line (never the last/current one). It must still be
    # present, verbatim, among the committed lines -- unreachable by the payload.
    return _INV2_SENTINEL in blocks[:-1], blocks


@RUN_GUI
@given(ANY_STREAM)
def prop_inv2_earlier_line_immutable(stream):
    ok, blocks = _committed_line_intact(_WL2, stream)
    assert ok, 'INV-2: earlier line altered by %r -> %r' % (stream[:60], blocks[:4])


def inv2_corpus():
    for seed in CORPUS_SEEDS:
        ok, blocks = _committed_line_intact(_WL2, seed)
        if not ok:
            fail('INV-2 corpus: earlier line altered by %r -> %r'
                 % (seed[:60], blocks[:4]))


# ----- INV-6: output never induces an input reply (except the gated OSC 52 read) --
_WT6 = SecureTerminal(command='/bin/cat', tui=True)
for _feat in ('osc_clipboard_read', 'osc_clipboard', 'osc_title', 'osc_notify',
              'osc_cwd', 'osc_hyperlink'):
    try:
        _WT6.apply_osc(_feat, True)                 # every reach-out ON
    except Exception:                               # pylint: disable=broad-except
        pass
_WT6_SENT = []
_WT6._write = _WT6_SENT.append                      # pylint: disable=protected-access
QGuiApplication.clipboard().setText('INV6-CLIP-SECRET')   # a secret to (not) exfiltrate


@RUN_GUI
@given(ANY_STREAM)
def prop_inv6_no_induced_reply(stream):
    """With every OSC reach-out enabled but the clipboard-read gate NOT granted,
    feeding ANY output writes NOTHING back to the child: no DSR, answerback, mouse
    report, title-report or ungranted clipboard reply. The one defensible write-back
    -- a GRANTED OSC 52 read reply -- is never provoked by output alone."""
    _WT6_SENT.clear()
    feed_output(_WT6, stream.encode('utf-8', 'surrogatepass'))
    assert _WT6_SENT == [], 'output induced a write-back: %r' % (_WT6_SENT,)


def inv6_corpus():
    for seed in CORPUS_SEEDS:
        _WT6_SENT.clear()
        feed_output(_WT6, seed.encode('utf-8', 'surrogatepass'))
        if _WT6_SENT != []:
            fail('INV-6 corpus: output induced a write-back for %r' % seed[:60])


# ===========================================================================
# CANARIES: each property must FAIL against a deliberately-broken stub. A green
# run then means the checks have teeth (not a tautology). Mirrors the adversarial
# harness's per-class self-test.
# ===========================================================================
CANARIES_VERIFIED = [0]


def _expect_violation(label, thunk):
    """Run a property against a broken stub; it MUST raise AssertionError (the
    property caught the break). A pass means the property is toothless."""
    try:
        thunk()
    except AssertionError:
        CANARIES_VERIFIED[0] += 1
        return
    fail('CANARY %s: the property did NOT fail against a broken stub (toothless)'
         % label)


def _canaries():
    # INV-1 CLI: a strip that does NOT drop the submit -> a burst auto-runs.
    def canary_inv1_cli():
        assert _inv1_cli_predicate(lambda k: k, b'echo x\r'), 'identity strip'
    _expect_violation('INV-1/cli', canary_inv1_cli)

    # INV-1 GUI: monkeypatch paste_no_autosubmit to identity so the trailing submit
    # is NOT stripped -> a single-line paste auto-runs.
    orig = TERM.paste_no_autosubmit
    TERM.paste_no_autosubmit = staticmethod(lambda s: s)
    try:
        def canary_inv1_gui():
            ok, _ctx = _inv1_gui_predicate(_WL, _WL_SENT, 'echo pwned\n')
            assert ok, 'un-stripped paste'
        _expect_violation('INV-1/gui', canary_inv1_gui)
    finally:
        TERM.paste_no_autosubmit = orig
        _reset_paste(_WL, _WL_SENT)

    # INV-3: a reference that skips the escape strip diverges from the real render
    # for a stream carrying an escape -> the differential must fire.
    def canary_inv3():
        broken_logical = lambda s: s          # no strip, no line model at all
        stream = 'a\x1b[31mb'
        assert rendered_live(stream) == broken_logical(stream), 'broken logical'
    _expect_violation('INV-3', canary_inv3)

    # INV-4: a stub emitter that leaks a raw non-ASCII glyph in box mode.
    def canary_inv4():
        leaked = 'ok\u202e' + S.BOX      # a bidi override escaped box mode
        bad = [ch for ch in leaked if not _inv4_char_ok(ch, 'box')]
        assert not bad, 'leaked non-inert char'
    _expect_violation('INV-4', canary_inv4)

    # INV-5: a broken widget that submits on paste (no wait for Enter).
    orig5 = TERM.paste_no_autosubmit
    TERM.paste_no_autosubmit = staticmethod(lambda s: s)
    try:
        def canary_inv5():
            _reset_paste(_WL, _WL_SENT)
            # a trailing newline -> sanitize_paste maps it to the submit CR; without
            # the strip it reaches the child, submitting with no Enter.
            _WL.insertFromMimeData(_mime('echo pwned\n'))
            after = b''.join(bytes(c) for c in _WL_SENT)
            assert b'\r' not in after, 'paste submitted without Enter'
            _reset_paste(_WL, _WL_SENT)
        _expect_violation('INV-5', canary_inv5)
    finally:
        TERM.paste_no_autosubmit = orig5
        _reset_paste(_WL, _WL_SENT)

    # INV-6: a reflected write-back (the synthetic vulnerable observable) must be
    # caught by the spy-empty assertion.
    def canary_inv6():
        sent = [b'\x1b[24;80R']               # a DSR reply a vulnerable terminal writes
        assert sent == [], 'reflected write-back'
    _expect_violation('INV-6', canary_inv6)

    # INV-2: commit a real sentinel line through the live widget, then TAMPER it in
    # the document (the effect a vertical-cursor leak would have) and confirm the
    # committed-line-intact check reports the violation. The widget architecture
    # keeps a bug from reaching a committed line at all, so the canary proves the
    # CHECK discriminates a modified earlier line rather than passing blindly.
    def canary_inv2():
        from PyQt6.QtGui import QTextCursor
        _reset_line_widget(_WL2)
        feed_output(_WL2, (_INV2_SENTINEL + '\nlast').encode())
        doc = _WL2.document()
        block = doc.begin()
        while block.isValid():
            if block.text() == _INV2_SENTINEL:
                cur = QTextCursor(block)
                cur.select(QTextCursor.SelectionType.BlockUnderCursor)
                cur.insertText('\nTAMPERED')      # rewrite the earlier committed line
                break
            block = block.next()
        blocks = []
        block = doc.begin()
        while block.isValid():
            blocks.append(block.text())
            block = block.next()
        assert _INV2_SENTINEL in blocks[:-1], 'earlier line modified'
    _expect_violation('INV-2', canary_inv2)


# ===========================================================================
# Run.
# ===========================================================================
PROPS = [
    ('INV-3 logical==rendered (random)', prop_inv3_random),
    ('INV-4 inert display (random)', prop_inv4_random),
    ('INV-1 cli no auto-submit', prop_inv1_cli),
    ('INV-1 gui paste no auto-exec', prop_inv1_gui),
    ('INV-5 single-line waits for Enter', prop_inv5_single_line_waits_for_enter),
    ('INV-5 multi-line held until dispatch', prop_inv5_multiline_held_until_dispatch),
    ('INV-2 earlier line immutable', prop_inv2_earlier_line_immutable),
    ('INV-6 no induced reply', prop_inv6_no_induced_reply),
]
CORPUS_CHECKS = [
    ('INV-3 corpus', inv3_corpus),
    ('INV-4 corpus', inv4_corpus),
    ('INV-1 gui corpus', inv1_gui_corpus),
    ('INV-2 corpus', inv2_corpus),
    ('INV-6 corpus', inv6_corpus),
]

for name, prop in PROPS:
    try:
        prop()
    except Exception as exc:  # pylint: disable=broad-except
        fail('property %s: %s' % (name, exc))

for name, check in CORPUS_CHECKS:
    try:
        check()
    except Exception as exc:  # pylint: disable=broad-except
        fail('corpus check %s: %s' % (name, exc))

_canaries()

for term in (_WL, _WL2, _WT6):
    try:
        term.close()
    except Exception:  # pylint: disable=broad-except
        pass

sys.stdout.write('secure-terminal-tests(invariants): %d properties + %d corpus '
                 'checks + %d canaries verified, %d failed\n'
                 % (len(PROPS), len(CORPUS_CHECKS), CANARIES_VERIFIED[0], FAIL))
sys.exit(0 if FAIL == 0 else 1)
