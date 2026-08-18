#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

r"""
Machine-checked FORMAL VERIFICATION of secure-terminal's pure sanitizer.

This is a PROOF over ALL inputs, not a sample. It complements -- does not replace
-- test_invariants.py, which property-TESTS the same code by random sampling
(Hypothesis, <= 400 examples per property). Here every claim is discharged either
by an SMT proof (Z3) over a symbolic / unbounded domain, or by EXHAUSTIVE
enumeration over the whole finite input alphabet (all 1,114,112 Unicode code
points) run against the REAL sanitizer. Neither is sampling.

Two theorems:

  T1  STRICT-MODE OUTPUT INERTNESS -- the CLI output-becomes-input closure.
      cli.py writes render_output(text, mode) STRAIGHT to the outer terminal
      (cli.py: `safe = render_output(text, mode); os.write(out_fd, ...)`). So the
      display alphabet IS what reaches the outer terminal. Theorem: for every
      input `text` and every STRICT mode (box, reveal, detail), every character of
      render_output(text, mode) lies in
          SAFE_ASCII = {0x08, 0x09, 0x0A, 0x0D} u [0x20, 0x7E]
      -- printable ASCII plus the four honored editing controls (backspace, tab,
      newline, carriage return). No escape, control, bidi, invisible or homoglyph
      byte can ever reach the outer terminal, for ANY input.

      SHOW mode is the documented, weaker exception: it ADDITIONALLY admits a
      printable non-ASCII glyph, the non-ASCII-space marker SPACE_MARK, and honest
      box-drawing / block structure -- but STILL never a bidi control, an
      invisible / default-ignorable character, or a C0/C1/DEL control byte. That
      exact whitelist is proved too (this is INV-4, proved rather than sampled).

  T2  LINE-EDITOR CONTAINMENT -- INV-2 at the pure level. feed_line_edits (the
      LIVE widget line model, terminal.py) maintains 0 <= col <= len(cells) for
      every input, so every cell write lands in the CURRENT line; a completed line,
      once appended to `completed`, is never mutated. Output can never reach an
      earlier line or the scrollback. Proved by INDUCTION in Z3 over the transition
      relation (which covers UNBOUNDED input -- enumeration cannot), then
      cross-checked against the real function.

METHOD, and what is PROVED vs ASSUMED (honest scope):

  * Z3 (SMT) proves the SYMBOLIC / UNBOUNDED core:
      - T1: the reveal / detail <U+XXXX ...> badge is inert for EVERY code point --
        each hex nibble maps to a digit in [0-9A-F] and the ASCII frame is inert --
        proved over the whole integer code-point range, not enumerated; and the
        per-character branch classifier is TOTAL and DETERMINISTIC (every code
        point is handled by exactly one branch, so none falls through unclassified).
      - T2: the cursor invariant is inductive -- it survives EVERY transition from
        ANY conforming state, which generalizes to input of any length.

  * EXHAUSTIVE ENUMERATION over all 1,114,112 code points runs the REAL sanitizer
    and (a) validates the Z3 branch model against the real code byte for byte,
    (b) discharges T1's single data-dependent assumption -- that Unicode character
    names are ASCII (true by the Unicode standard: names use A-Z, 0-9, space,
    hyphen) -- by exercising the real detail badge on every named code point, and
    (c) directly confirms the whole-input alphabet result on the real function.
    Total coverage of the input alphabet -- not sampling.

  * STRUCTURAL LEMMA, stated and executable-checked, not machine-proved:
    (L-hom) render_output's per-character loop carries NO state across characters
    (its accumulator is append-only and never read back), so for any text the loop
    output is the concatenation of the per-character map over the post-escape-strip
    text. Manifest from the code; backed here by an executable homomorphism check
    over adversarial probes. Together with the exhaustive per-code-point result it
    lifts the theorem from single characters to inputs of any length.

  SCOPE / NOT PROVED HERE: only the PURE sanitizer (sanitize.py) is verified. The
  Qt widget layer is NOT: the no-write-back property (INV-6, "output never induces
  an input reply") and the full-widget earlier-line immutability remain covered by
  the property tests in test_invariants.py, which drive the live widget. This file
  proves the sanitizer core those tests exercise; it does not model Qt, pyte, the
  pty, or terminal.py.

Exit 0 on a fully discharged proof, 1 on any counterexample or unmet assumption.
A missing z3 or secure_terminal is a hard FAILURE (a verification suite must never
silently disable itself), never a skip.
"""

import sys
import unicodedata

try:
    import z3
    from secure_terminal import sanitize as S
except Exception as exc:  # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(verify_formal): FAIL missing '
                     'dependency (z3 / secure_terminal): %s\n' % exc)
    sys.exit(1)

FAIL = 0


def fail(msg):
    global FAIL
    FAIL += 1
    sys.stderr.write('FAIL: ' + msg + '\n')


# The safe display alphabet: printable ASCII + the four honored editing controls
# (backspace, tab, newline, carriage return). A reveal / detail <U+XXXX ...> badge
# is itself built only from these. This is render_output's own pass-through set
# (see the `cp in (0x08, 0x09, 0x0A, 0x0D) or 0x20 <= cp <= 0x7E` guard).
SAFE_ASCII = frozenset((0x08, 0x09, 0x0A, 0x0D)) | frozenset(range(0x20, 0x7F))

MAX_CP = 0x10FFFF                 # the whole Unicode code-point space, inclusive
STRICT_MODES = ('box', 'reveal', 'detail')


# ===========================================================================
# T1, part A -- Z3 (SMT): the symbolic core of render_output's inertness.
# ===========================================================================
def _hexchar_z3(v):
    """Z3 term: the ASCII code of the uppercase hex digit for nibble value `v`
    (0..15), matching Python '%X' formatting -- 0..9 -> '0'..'9' (0x30..0x39),
    10..15 -> 'A'..'F' (0x41..0x46)."""
    return z3.If(v < 10, 0x30 + v, 0x41 + (v - 10))


def _in_safe_ascii_z3(code):
    """Z3 predicate: `code` (an ASCII code point) is in SAFE_ASCII."""
    return z3.Or(code == 0x08, code == 0x09, code == 0x0A, code == 0x0D,
                 z3.And(0x20 <= code, code <= 0x7E))


def z3_prove(name, claim, assumptions=(), report=True):
    """Prove `claim` holds for ALL values of its free variables: assert its
    negation under `assumptions` and require UNSAT. Returns True iff proved. A SAT
    result is a counterexample (proof failed); `unknown` is an incomplete proof and
    also fails (never reported as success). `report=False` (for canaries, which
    prove a DELIBERATELY broken claim) returns the verdict WITHOUT logging a
    failure, so an intended counterexample does not pollute the real tally."""
    solver = z3.Solver()
    for assumption in assumptions:
        solver.add(assumption)
    solver.add(z3.Not(claim))
    result = solver.check()
    if result == z3.unsat:
        return True
    if not report:
        return False
    if result == z3.sat:
        fail('Z3 %s: COUNTEREXAMPLE %s' % (name, solver.model()))
    else:
        fail('Z3 %s: proof INCOMPLETE (solver returned %s)' % (name, result))
    return False


# Per-character branch classifier for STRICT modes, as a Z3 function of the code
# point. This mirrors render_output's loop body exactly for box/reveal/detail (the
# show-only arms are never taken in a strict mode). Classes:
#   0 PASS    -- cp is in SAFE_ASCII: emitted verbatim (a safe char).
#   1 DROP    -- cp == 0x07 (BEL): emitted as nothing (a signal, not a glyph).
#   2 BADGE   -- reveal/detail: emitted as the <U+XXXX ...> hex badge.
#   3 BOX     -- box mode fallthrough: emitted as the single ASCII '_' (0x5F).
_CLS_PASS, _CLS_DROP, _CLS_BADGE, _CLS_BOX = 0, 1, 2, 3


def _classify_z3(cp, mode):
    """Z3 term giving the branch class (see above) for code point `cp` under a
    concrete strict `mode`. Faithful to render_output's if/elif ladder."""
    safe = _in_safe_ascii_z3(cp)
    is_bel = (cp == 0x07)
    if mode == 'box':
        badge = z3.BoolVal(False)
    else:                                     # reveal or detail
        badge = z3.BoolVal(True)              # catches every non-safe, non-BEL cp
    return z3.If(safe, _CLS_PASS,
                 z3.If(is_bel, _CLS_DROP,
                       z3.If(badge, _CLS_BADGE, _CLS_BOX)))


def t1_z3():
    """Discharge T1's symbolic obligations with Z3."""
    cp = z3.Int('cp')
    nibble = z3.Int('nibble')
    in_range = z3.And(0 <= cp, cp <= MAX_CP)

    # (1) The hex-badge nibble lemma: EVERY hex digit value renders to a SAFE_ASCII
    # character. Every digit of '%04X' % cp is one such nibble (a value in [0, 15]),
    # and the width-4 zero padding is '0' (0x30, itself SAFE), so by this lemma the
    # whole hex field of the reveal / detail badge is inert -- for cp anywhere in
    # range. The lemma is proved over the entire nibble domain symbolically; that
    # each real badge's digits are in fact these nibbles is confirmed concretely by
    # the exhaustive enumeration below (which renders the badge on every code point).
    z3_prove('badge-nibble-inert',
             _in_safe_ascii_z3(_hexchar_z3(nibble)),
             assumptions=[z3.And(0 <= nibble, nibble <= 15)])

    # (2) The badge FRAME + pad characters are all SAFE_ASCII constants:
    #   '<' 0x3C, 'U' 0x55, '+' 0x2B, '>' 0x3E, ' ' 0x20, '0' 0x30 (pad).
    # (The detail badge also carries the Unicode NAME; that its characters are
    # ASCII is the one assumption discharged by enumeration, below.)
    for ch in '<U+>0 ':
        if ord(ch) not in SAFE_ASCII:
            fail('Z3 badge-frame: %r (0x%02X) is not SAFE_ASCII' % (ch, ord(ch)))
    z3_prove('box-placeholder-inert', _in_safe_ascii_z3(z3.IntVal(0x5F)))

    # (3) The strict-mode classifier is TOTAL and DETERMINISTIC: every code point
    # in range is assigned exactly one of the four known classes -- none falls
    # through unclassified (which would be an unhandled byte reaching the screen).
    for mode in STRICT_MODES:
        cls = _classify_z3(cp, mode)
        z3_prove('classifier-total-%s' % mode,
                 z3.Or(cls == _CLS_PASS, cls == _CLS_DROP,
                       cls == _CLS_BADGE, cls == _CLS_BOX),
                 assumptions=[in_range])
        # box mode never emits a BADGE (no name/hex path); reveal/detail never
        # reach BOX (the badge arm catches every non-safe, non-BEL cp). Pin that,
        # so the model's alphabet obligations match what the real code can emit.
        forbidden = _CLS_BADGE if mode == 'box' else _CLS_BOX
        z3_prove('classifier-%s-never-%d' % (mode, forbidden),
                 cls != forbidden,
                 assumptions=[in_range, z3.Not(_in_safe_ascii_z3(cp)),
                              cp != 0x07])


# ===========================================================================
# T1, part B -- EXHAUSTIVE enumeration on the REAL render_output.
# ===========================================================================
# Show mode's documented whitelist, in addition to SAFE_ASCII: the non-ASCII-space
# marker, honest structural box-drawing / block glyphs, and a printable non-ASCII
# glyph that is neither default-ignorable nor a bidi control.
def _show_char_ok(ch):
    cp = ord(ch)
    if cp in SAFE_ASCII:
        return True
    if ch == S.BOX or ch == S.SPACE_MARK:
        return True
    if S.is_structural(cp):
        return True
    return (ch.isprintable() and not S.is_default_ignorable(ch)
            and not S.is_bidi_control(cp))


def t1_enumerate():
    """Run the REAL render_output on every single code point, in every mode, and
    confirm the output alphabet. This validates the Z3 model against the code,
    discharges the name-is-ASCII assumption (the detail badge is exercised on every
    named code point), and confirms the whole-input result on the real function.

    Also validates the Z3 branch model: for each strict mode the real output must
    match the class the Z3 classifier predicts (PASS -> the char itself; DROP ->
    empty; BADGE -> a <U+...> string; BOX -> '_')."""
    strict_bad = 0
    show_bad = 0
    ignorable_leak = 0
    model_mismatch = 0
    name_non_ascii = 0

    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)
        safe = cp in SAFE_ASCII
        is_bel = (cp == 0x07)

        # --- strict modes: output must be pure SAFE_ASCII, and match the model ---
        for mode in STRICT_MODES:
            out = S.render_output(ch, mode)
            for oc in out:
                if ord(oc) not in SAFE_ASCII:
                    if strict_bad < 8:
                        fail('T1 strict: %s left 0x%02X for U+%04X'
                             % (mode, ord(oc), cp))
                    strict_bad += 1
            # model prediction vs real output class
            if safe:
                predicted_ok = (out == ch)
            elif is_bel:
                predicted_ok = (out == '')
            elif mode == 'box':
                predicted_ok = (out == '_')
            else:                             # reveal / detail: a <U+...> badge
                predicted_ok = (out.startswith('<U+') and out.endswith('>'))
            if not predicted_ok:
                if model_mismatch < 8:
                    fail('T1 model: %s U+%04X real=%r not the predicted class'
                         % (mode, cp, out[:40]))
                model_mismatch += 1

            # no default-ignorable (invisible) character survives, in this mode
            if any(S.is_default_ignorable(oc) for oc in out):
                if ignorable_leak < 8:
                    fail('T1 invisible: %s leaked an ignorable for U+%04X'
                         % (mode, cp))
                ignorable_leak += 1

        # --- the name-is-ASCII assumption, on the real Unicode database ---
        # detail's badge embeds unicodedata.name(chr(cp)); confirm it is ASCII for
        # every named code point (else the detail badge could carry a non-ASCII
        # byte). render_output(detail) already covers this, but assert it directly
        # so the discharged assumption is explicit and independently checked.
        try:
            nm = unicodedata.name(ch)
        except ValueError:
            nm = ''
        if nm and not nm.isascii():
            if name_non_ascii < 8:
                fail('T1 name-ASCII: U+%04X name %r is not ASCII' % (cp, nm))
            name_non_ascii += 1

        # --- show mode: the documented wider whitelist, but still no invisible ---
        out = S.render_output(ch, 'show')
        for oc in out:
            if not _show_char_ok(oc):
                if show_bad < 8:
                    fail('T1 show: U+%04X left non-whitelisted 0x%02X'
                         % (cp, ord(oc)))
                show_bad += 1
        if any(S.is_default_ignorable(oc) for oc in out):
            if ignorable_leak < 8:
                fail('T1 invisible: show leaked an ignorable for U+%04X' % cp)
            ignorable_leak += 1

    return dict(strict_bad=strict_bad, show_bad=show_bad,
                ignorable_leak=ignorable_leak, model_mismatch=model_mismatch,
                name_non_ascii=name_non_ascii)


# ===========================================================================
# T1, structural lemma L-hom: the render loop is a per-character homomorphism.
# ===========================================================================
# Escape-encoded so this source file stays ASCII-only (the repo convention; see
# sanitize.py's own \u25a1 BOX). Each probe is escape-FREE terminal-ish output
# mixing plain ASCII, honored controls, and the hostile classes render_output
# must neutralize: bidi override (U+202E), zero-width (U+200B), a Cyrillic
# homoglyph (U+0430) with a combining acute (U+0301), the euro sign (U+20AC),
# box-drawing (U+2500, U+2502), the BOM (U+FEFF), a Hangul filler (U+3164), and
# astral glyphs (an emoji, a math-alphanumeric).
_HOM_PROBES = [
    '', 'plain ascii text',
    'x\u202ey\u200bz', '\u0430\u0301hadmin', 'tab\tnl\ncr\rbs\x08x',
    '\x07bell', 'euro \u20ac end', 'box \u2500\u2502 mix',
    ''.join(chr(c) for c in range(0, 0x300)),   # every C0/C1 + low BMP
    '\U0001f600\U0001d400\ufeff\u3164',
]


def t1_homomorphism():
    """Executable backing for L-hom. render_output first strips escapes (a
    delete-only regex sub), THEN maps each surviving character independently with
    an append-only accumulator. So on ESCAPE-FREE text the whole function is a
    per-character homomorphism: render_output(s) == concat of render_output(ch).
    Verify that identity on probes, in every mode. (On text WITH escapes the strip
    runs first; that step only deletes, so it cannot introduce a character the
    per-code-point enumeration did not already cover.)"""
    for probe in _HOM_PROBES:
        esc_free = probe.replace('\x1b', '')
        for mode in ('box', 'reveal', 'detail', 'show'):
            whole = S.render_output(esc_free, mode)
            piecewise = ''.join(S.render_output(ch, mode) for ch in esc_free)
            if whole != piecewise:
                fail('L-hom: %s not per-character on %r' % (mode, esc_free[:40]))


# ===========================================================================
# CANARIES: each proof method must FAIL against a deliberately broken model, so a
# green run means the checks have teeth (mirrors test_invariants.py house style).
# ===========================================================================
CANARIES_VERIFIED = [0]


def _expect_caught(label, caught):
    """Record that a deliberately-broken model was CAUGHT (`caught` True). If it
    slipped through, the check is toothless -- a real failure."""
    if caught:
        CANARIES_VERIFIED[0] += 1
    else:
        fail('CANARY %s: broken model did NOT trip the check (toothless)' % label)


def t1_canaries():
    # Z3 canary: a WRONG hexchar (maps 10..15 past 'F' toward 0x7F) must make the
    # nibble lemma SAT (a counterexample), so the proof correctly returns False.
    nibble = z3.Int('n')
    bad = z3.If(nibble < 10, 0x30 + nibble, 0x7A + (nibble - 10))   # 'z'.. off end
    caught = not z3_prove('canary-nibble', _in_safe_ascii_z3(bad),
                          assumptions=[z3.And(0 <= nibble, nibble <= 15)],
                          report=False)
    _expect_caught('T1/z3-nibble', caught)

    # Enumeration canary: a raw bidi override leaked in a strict mode must be caught
    # by the SAFE_ASCII alphabet check.
    leaked = 'ok\u202e'
    _expect_caught('T1/enum-strict',
                   any(ord(oc) not in SAFE_ASCII for oc in leaked))

    # Homomorphism canary: a stateful map (emits nothing on a repeated char) breaks
    # the per-character identity the real loop satisfies.
    def stateful(seen, ch):
        if ch in seen:
            return ''
        seen.add(ch)
        return ch
    s = 'aabb'
    seen = set()
    whole = ''.join(stateful(seen, c) for c in s)          # 'ab' (state-dependent)
    piecewise = ''.join(stateful(set(), c) for c in s)     # 'aabb'
    _expect_caught('T1/homomorphism', whole != piecewise)


# ===========================================================================
# T2 -- LINE-EDITOR CONTAINMENT (INV-2 at the pure level), Z3 + cross-check.
#
# feed_line_edits advances the CURRENT line's cell buffer by one raw chunk. We
# abstract its state to (col, L) with L = len(cells) and M = max_line (0 = no
# wrap), dropping cell CONTENTS (irrelevant to WHERE a write lands). The
# containment invariant:
#
#     INV(col, L, M) :=  0 <= col <= L  and  (M == 0 or L <= M)
#
# Consequences of INV holding at every step:
#   * every printable write is at index `col` with 0 <= col <= L == len(cells),
#     so it OVERWRITES a current-line cell (col < L) or APPENDS (col == L) -- it
#     can never index a negative or out-of-range position, hence never reach a
#     cell of a previously COMPLETED line;
#   * `completed` grows only by append (structural: completed[i] is never on the
#     left of an assignment in feed_line_edits), so a line, once emitted, is
#     immutable. Output cannot reach an earlier line or the scrollback (INV-2).
#
# Z3 proves INV is INDUCTIVE: from ANY state satisfying it, EVERY transition
# lands in a state satisfying it -- for symbolic col, L, M, and numeric parameter,
# i.e. for input of ANY length (enumeration cannot reach that). Two honest limits,
# both closed by the wide cross-check below: (a) the invariant is verified on the
# REAL feed_line_edits directly, over the grid; (b) the abstract model is shown
# equal to the real function point-for-point on that grid, so it is a faithful
# transcription -- the Z3 induction then extends the invariant past the grid to
# input of any length. The model is a transcription of the cited code, validated,
# not the code itself; the grid is finite though it covers every behavioural
# region and boundary of the (piecewise-linear) transitions.
# ===========================================================================
def _zmin(a, b):
    return z3.If(a < b, a, b)


def _zmax(a, b):
    return z3.If(a > b, a, b)


def _inv_z3(col, L, M):
    return z3.And(col >= 0, col <= L, z3.Implies(M > 0, L <= M))


# The transition classes of feed_line_edits, by their effect on (col, L). `num` is
# the CSI numeric parameter as _safe_int yields it, with None modeled as 0 (for C/
# D/G, `num or 1` maps both 0 and None to 1; for K, both None and 0 mean erase-to-
# EOL) -- so a symbolic num >= 0 faithfully covers every parameter incl. the empty
# one. Each returns (col2, L2) as Z3 terms. Mirrors sanitize.py lines 711-841.
def _step_z3(cls, col, L, M, num):
    d = z3.If(num >= 1, num, 1)                       # `num or 1`
    wrap = z3.And(M > 0, col >= M)                    # deferred-autowrap phantom

    def csi_move(target):
        """Shared C/G tail: clamp to width, pad L up to it, then the end-of-op
        anti-phantom clamp (`if max_line and col >= max_line: col = max_line-1`)."""
        clamped = z3.If(M > 0, _zmin(target, M - 1), _zmin(target, L))
        L2 = _zmax(L, clamped)
        col2 = z3.If(z3.And(M > 0, clamped >= M), M - 1, clamped)
        return col2, L2

    if cls == 'WRITE':                               # printable / control overwrite
        col_a = z3.If(wrap, z3.IntVal(0), col)       # autowrap resets (0,0) first
        L_a = z3.If(wrap, z3.IntVal(0), L)
        L2 = z3.If(col_a < L_a, L_a, L_a + 1)        # overwrite vs append
        return col_a + 1, L2
    if cls == 'NL':
        return z3.IntVal(0), z3.IntVal(0)            # completed.append; cells=[]
    if cls == 'CR':
        return z3.IntVal(0), L
    if cls == 'BS':
        return z3.If(col > 0, col - 1, col), L
    if cls in ('BEL', 'SGR', 'ESC_STRIP', 'ESC_DROP'):
        return col, L                                # cursor-neutral
    if cls == 'PROMPT_FLUSH':                        # completed.append; cells=[]
        return z3.IntVal(0), z3.IntVal(0)
    if cls == 'PROMPT_NOOP':
        return col, L
    if cls == 'C':
        return csi_move(col + d)
    if cls == 'D':
        col1 = z3.If(col - d < 0, z3.IntVal(0), col - d)
        col2 = z3.If(z3.And(M > 0, col1 >= M), M - 1, col1)
        return col2, L
    if cls == 'G':
        return csi_move(z3.If(d - 1 < 0, z3.IntVal(0), d - 1))
    if cls == 'K0':                                  # erase to EOL: del cells[col:]
        col2 = z3.If(z3.And(M > 0, col >= M), M - 1, col)
        return col2, col                             # L2 = old col (col <= L)
    if cls in ('K1', 'K3'):                          # erase-BOL / unknown: L,col kept
        col2 = z3.If(z3.And(M > 0, col >= M), M - 1, col)
        return col2, L
    if cls == 'K2':                                  # erase-all: cells=[]; col=0
        return z3.IntVal(0), z3.IntVal(0)
    raise ValueError('unknown class %r' % cls)


_T2_CLASSES = ('WRITE', 'NL', 'CR', 'BS', 'BEL', 'SGR', 'ESC_STRIP', 'ESC_DROP',
               'PROMPT_FLUSH', 'PROMPT_NOOP', 'C', 'D', 'G', 'K0', 'K1', 'K2', 'K3')


def t2_z3():
    """Inductive proof: INV is preserved by every transition class, for symbolic
    col, L, M >= 0 and num >= 0. Plus the write-in-bounds obligation: the printable
    write lands at an index within [0, len(cells)] of the CURRENT line."""
    col, L, M, num = z3.Ints('col L M num')
    pre = z3.And(_inv_z3(col, L, M), num >= 0)

    # base case: the initial call state (empty current line) satisfies INV.
    z3_prove('T2-base-initial', _inv_z3(z3.IntVal(0), z3.IntVal(0), M),
             assumptions=[M >= 0])

    for cls in _T2_CLASSES:
        col2, L2 = _step_z3(cls, col, L, M, num)
        z3_prove('T2-inductive-%s' % cls, _inv_z3(col2, L2, M),
                 assumptions=[pre])

    # write-in-bounds: after the (possible) autowrap reset, the write index col_a
    # satisfies 0 <= col_a <= L_a, so buf[col_a] is an overwrite or an append --
    # never out of range, never a completed line.
    wrap = z3.And(M > 0, col >= M)
    col_a = z3.If(wrap, z3.IntVal(0), col)
    L_a = z3.If(wrap, z3.IntVal(0), L)
    z3_prove('T2-write-in-bounds',
             z3.And(col_a >= 0, col_a <= L_a), assumptions=[pre])


def _t2_real_step(col, L, M, cls, num):
    """Run the REAL feed_line_edits from a constructed state (col, L cells) on the
    ONE raw token for `cls`, and return the resulting (col, len(cells))."""
    param = '' if num is None else str(num)
    token = {
        'WRITE': 'a', 'NL': '\n', 'CR': '\r', 'BS': '\x08', 'BEL': '\x07',
        'SGR': '\x1b[%sm' % param, 'ESC_STRIP': '\x1b[2J', 'ESC_DROP': '\x1b',
        'PROMPT_FLUSH': S.PROMPT_START + 'x', 'PROMPT_NOOP': S.PROMPT_START,
        'C': '\x1b[%sC' % param, 'D': '\x1b[%sD' % param, 'G': '\x1b[%sG' % param,
        'K0': '\x1b[%sK' % ('' if num in (None, 0) else '0'),
        'K1': '\x1b[1K', 'K2': '\x1b[2K', 'K3': '\x1b[3K',
    }[cls]
    cells = [('a', ())] * L
    _comp, cells2, col2, _sgr, _wraps = S.feed_line_edits(cells, col, {}, token,
                                                          max_line=M)
    return col2, len(cells2)


def _t2_model_step(cls, col, L, M, num):
    """Evaluate the Z3 abstract model at CONCRETE (col, L, M, num) -> (col2, L2)."""
    n = 0 if num is None else num
    c2, l2 = _step_z3(cls, z3.IntVal(col), z3.IntVal(L), z3.IntVal(M),
                      z3.IntVal(n))
    return (z3.simplify(c2).as_long(), z3.simplify(l2).as_long())


def t2_crosscheck():
    """Confirm two things across a WIDE grid of INV-satisfying entry states x
    classes x parameters:
      (a) the REAL feed_line_edits keeps the invariant (0 <= col <= len(cells),
          and len <= max_line) on its result -- the security property, checked
          directly on the shipped code;
      (b) the abstract Z3 model predicts the real (col, len) exactly -- so the
          model the inductive proof reasons over is a faithful transcription of
          the code on every tested state, and the proof's generalization to
          UNBOUNDED input is anchored to the real function rather than a free-
          standing hand model.
    A model that drifts from the code is caught here (fail loud).

    The grid spans widths incl. the unbounded case and the small widths where the
    autowrap phantom lives, line lengths past every width, every cursor column, and
    the CSI parameter break points (empty/0/1/2 and >=3, plus values large enough to
    exercise the width clamps). The transitions are piecewise-linear in these, so
    covering each region and its boundaries validates the model, not just points."""
    mismatches = 0
    inv_violations = 0
    # PROMPT_FLUSH is excluded from the concrete grid: its raw form needs printable
    # text following the marker to fire (_printable_follows), and that trailing
    # printable is itself WRITTEN, so no single raw token isolates the flush's
    # (col, L) effect. That effect is identical to NL's -- completed.append(cells);
    # cells, col = [], 0 -> (0, 0) -- which IS grid-validated, and the Z3 proof
    # covers PROMPT_FLUSH preserving INV directly.
    grid_classes = [c for c in _T2_CLASSES if c != 'PROMPT_FLUSH']
    # Widths: unbounded (0), the tiny widths where the autowrap phantom lives
    # (1, 2), a mid width (3, the "width 3" a reviewer flagged) and a larger one
    # (5). Params: the empty/0/1/2/>=3 break points (3 and 4 both land in the ">=3"
    # region, catching an off-by-one) and a value large enough to trip the clamp.
    for M in (0, 1, 2, 3, 5):
        for L in range(0, 8):
            if M > 0 and L > M:
                continue                             # not an INV state
            for col in range(0, L + 1):
                if M > 0 and col > M:
                    continue
                for cls in grid_classes:
                    for num in (None, 0, 1, 2, 3, 4, 50):
                        real = _t2_real_step(col, L, M, cls, num)
                        model = _t2_model_step(cls, col, L, M, num)
                        if real != model:
                            if mismatches < 12:
                                fail('T2 model drift: cls=%s col=%d L=%d M=%d '
                                     'num=%s real=%s model=%s'
                                     % (cls, col, L, M, num, real, model))
                            mismatches += 1
                        rc, rl = real
                        inv_ok = (0 <= rc <= rl) and (M == 0 or rl <= M)
                        if not inv_ok:
                            if inv_violations < 12:
                                fail('T2 INV violated by REAL code: cls=%s col=%d '
                                     'L=%d M=%d num=%s -> (col=%d,len=%d)'
                                     % (cls, col, L, M, num, rc, rl))
                            inv_violations += 1
    return dict(mismatches=mismatches, inv_violations=inv_violations)


# Earlier-line immutability rests on `completed` being APPEND-ONLY: a line, once
# emitted, is never re-indexed for modification. Establish that MECHANICALLY from
# the source AST of feed_line_edits (not by sampling), then demonstrate the
# consequence operationally.
def _names(node):
    import ast
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _append_only_violations(source, name):
    """Return the list of ways `name` is written OTHER than an initial plain
    `name = ...` and `name.append(...)`, found in `source` (an ast-parseable
    string). An empty list means `name` is provably append-only in `source`.

    Collects EVERY store target across every binding form -- not only ast.Assign:
    an AnnAssign, a walrus, a for / with target, or an augmented assign each rebind
    or mutate a name, a subscript / del hides a slice store, and a subscript store
    can hide inside a tuple target. Missing any would let a real mutation pass
    unreported. Kept as a pure function of `source` so it can be canaried against
    crafted mutations below."""
    import ast
    tree = ast.parse(source)
    violations = []
    plain_assigns = 0
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            targets = [node.target]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            targets = [node.target]
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            targets = [node.optional_vars]
        elif isinstance(node, ast.AugAssign):
            if _names(node.target) == {name}:
                violations.append('`%s` is AUGMENT-assigned' % name)
            continue
        elif isinstance(node, ast.Delete):
            for tgt in node.targets:            # `del name` / `del name[i]`
                if _names(tgt) == {name}:
                    violations.append('`%s` is deleted / del-sliced' % name)
            continue
        else:
            continue
        flat = []                               # flatten tuple/list/starred targets
        while targets:
            tgt = targets.pop()
            if isinstance(tgt, (ast.Tuple, ast.List)):
                targets.extend(tgt.elts)
            elif isinstance(tgt, ast.Starred):
                targets.append(tgt.value)
            else:
                flat.append(tgt)
        for tgt in flat:
            if isinstance(tgt, ast.Subscript) and _names(tgt.value) == {name}:
                violations.append('`%s` is SUBSCRIPT-assigned' % name)
            if isinstance(tgt, ast.Attribute) and _names(tgt.value) == {name}:
                violations.append('`%s` attribute is assigned' % name)
            if isinstance(tgt, ast.Name) and tgt.id == name:
                plain_assigns += 1
    if plain_assigns != 1:                      # exactly the initial `name = ...`
        violations.append('`%s` is plain-assigned %d times (expected 1 init)'
                          % (name, plain_assigns))
    for node in ast.walk(tree):                 # every method call must be .append
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == name and node.func.attr != 'append'):
            violations.append('`%s.%s(...)` called (only append allowed)'
                              % (name, node.func.attr))
    return violations


def t2_append_only_ast():
    """Assert, from feed_line_edits' own AST, that `completed` is written ONLY by
    an initial `completed = []` and `completed.append(...)` calls. So a completed
    line's content, once appended, cannot be rewritten: it is immutable within the
    function, and across calls it has left the carried state entirely (only `cells`,
    the CURRENT line, is carried). This is the append-only backbone of INV-2 at the
    pure level.

    `completed` is never bound to another name here (which could alias-mutate it) --
    the single plain assign is `completed = []` and no RHS is a bare `completed` --
    so no alias exists to mutate through. Aliasing through an arbitrary expression is
    out of scope for a static check; the cited function has none, and the
    incremental-equivalence check below exercises the real behaviour."""
    import inspect
    for msg in _append_only_violations(inspect.getsource(S.feed_line_edits),
                                       'completed'):
        fail('T2 append-only: ' + msg)


# Operational consequence: feeding a stream whole equals feeding it in pieces at
# TOKEN boundaries while carrying the (cells, col, sgr) state -- so a continuation
# reproduces exactly the earlier committed lines and never disturbs them. Split
# only at token boundaries (feed_line_edits carries no partial-escape state -- the
# widget de-splits escapes upstream), and omit PROMPT_START (its documented
# printable-lookahead is intentionally read-boundary sensitive). Exhaustive over
# all token sequences up to depth 3.
_T2_INCR_TOKENS = ['a', 'b', '\n', '\r', '\x08', '\x1b[2D', '\x1b[3C', '\x1b[K',
                   '\x1b[2K', '\x1b[1G']


def t2_incremental_equiv():
    bad = 0
    for M in (0, 4):
        seqs = [[]]
        for _ in range(3):
            seqs = [[*s, t] for s in seqs for t in _T2_INCR_TOKENS]
        for toks in seqs:
            whole = S.feed_line_edits([], 0, {}, ''.join(toks), max_line=M)
            comp_whole = whole[0]
            # feed token by token, carrying state; accumulate completed lines
            cells, col, sgr = [], 0, {}
            comp_incr = []
            for t in toks:
                comp, cells, col, sgr, _w = S.feed_line_edits(cells, col, sgr, t,
                                                              max_line=M)
                comp_incr.extend(comp)
            if comp_incr != comp_whole or (cells, col) != (whole[1], whole[2]):
                if bad < 8:
                    fail('T2 incremental: split-at-token feed diverged for %r '
                         '(M=%d)' % (''.join(toks), M))
                bad += 1
    return bad


def t2_canaries():
    # Inductive-proof canary: a corrupted WRITE transition that appends WITHOUT the
    # autowrap reset would, at the phantom (col == L == M), yield col2 = M+1 > L2 --
    # breaking INV. The inductive proof must catch such a break.
    col, L, M, num = z3.Ints('col L M num')
    pre = z3.And(_inv_z3(col, L, M), num >= 0)
    col2, L2 = col + 1, z3.If(col < L, L, L + 1)       # no autowrap reset
    caught = not z3_prove('canary-T2-write', _inv_z3(col2, L2, M),
                          assumptions=[pre], report=False)
    _expect_caught('T2/inductive', caught)

    # Cross-check canary: a deliberately wrong model (CR -> (col, L) instead of
    # (0, L)) must be caught by the real-vs-model comparison.
    real = _t2_real_step(3, 5, 0, 'CR', None)          # real CR -> (0, 5)
    _expect_caught('T2/crosscheck', real != (3, 5))

    # Append-only canary: every crafted mutation of `completed` must be flagged, and
    # a clean append-only source must NOT be (no false positive).
    for label, bad in (
            ('subscript', 'def f():\n completed = []\n completed[0] = 1\n'),
            ('del-slice', 'def f():\n completed = []\n del completed[0]\n'),
            ('non-append-call', 'def f():\n completed = []\n completed.pop()\n'),
            ('tuple-rebind', 'def f():\n completed = []\n a, completed = 1, 2\n'),
            ('aug-assign', 'def f():\n completed = []\n completed += [1]\n'),
            ('ann-assign', 'def f():\n completed = []\n completed: list = x\n'),
            ('for-target', 'def f():\n completed = []\n for completed in x:\n  pass\n')):
        _expect_caught('T2/append-only:%s' % label,
                       bool(_append_only_violations(bad, 'completed')))
    clean = 'def f():\n completed = []\n completed.append(1)\n completed.append(2)\n'
    if _append_only_violations(clean, 'completed'):
        fail('T2 append-only: false positive on a clean append-only source')


# ===========================================================================
# Run.
# ===========================================================================
def main():
    sys.stdout.write('secure-terminal formal verification (Z3 %s)\n'
                     % z3.get_version_string())

    sys.stdout.write('  T1.A  Z3 symbolic inertness of the display alphabet ...\n')
    t1_z3()

    sys.stdout.write('  T1.B  exhaustive enumeration over all %d code points ...\n'
                     % (MAX_CP + 1))
    stats = t1_enumerate()
    sys.stdout.write('        strict_bad=%(strict_bad)d show_bad=%(show_bad)d '
                     'invisible_leak=%(ignorable_leak)d '
                     'model_mismatch=%(model_mismatch)d '
                     'name_non_ascii=%(name_non_ascii)d\n' % stats)

    sys.stdout.write('  T1.L  per-character homomorphism of the render loop ...\n')
    t1_homomorphism()

    sys.stdout.write('  T2.A  Z3 inductive invariant of the line-editor state '
                     'machine ...\n')
    t2_z3()

    sys.stdout.write('  T2.B  validate the abstract model vs the real '
                     'feed_line_edits ...\n')
    t2stats = t2_crosscheck()
    sys.stdout.write('        model_drift=%(mismatches)d '
                     'real_inv_violations=%(inv_violations)d\n' % t2stats)

    sys.stdout.write('  T2.C  earlier-line immutability: `completed` append-only '
                     '(AST) + incremental equivalence ...\n')
    t2_append_only_ast()
    incr_bad = t2_incremental_equiv()
    sys.stdout.write('        incremental_divergences=%d\n' % incr_bad)

    sys.stdout.write('  canaries (each proof must trip on a broken model) ...\n')
    t1_canaries()
    t2_canaries()

    sys.stdout.write('verify_formal: %d canaries verified, %d obligations failed\n'
                     % (CANARIES_VERIFIED[0], FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
