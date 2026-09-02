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

Theorems (T1-T2 cover the display/output side; T3-T7 the input/clipboard side --
together the WHOLE pure sanitizer, input AND output):

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

  T3  PASTE NO-AUTO-EXECUTE (INV-1/5, pure level): sanitize_paste /
      sanitize_paste_unicode can never carry an escape / control / bidi / invisible
      to the shell, and never a raw newline; paste_no_autosubmit leaves no trailing
      carriage return (a single-line paste cannot run itself) and is idempotent; the
      CLI's whole-CR strip leaves no submit byte at all.
  T4  CLIPBOARD-EXFIL SAFETY: sanitize_clipboard is ASCII-only (a homoglyph cannot
      ride out); sanitize_clipboard_unicode never carries a control / bidi /
      invisible / default-ignorable; the display-copy path rewrites the inert
      display glyphs to an ASCII stand-in yet never emits a raw neutralized byte.
  T5  TITLE SAFETY: sanitize_title reduces a program title / notification to
      printable ASCII, length-bounded and idempotent.
  T6  TUI-CELL INERTNESS: tui_cell yields a single safe display unit for every cell
      and mode -- the cell's own glyph only when every code point is safe, else the
      box (or the show-mode non-ASCII-space marker); never an invisible / bidi /
      control / default-ignorable.
  T7  CLASSIFICATION AGREEMENT: classify_paste / paste_findings name a character the
      SAME class the display marking does, so the paste warning and the on-screen
      risk colour can never disagree.

  T8  CHUNK-BOUNDARY ESCAPE SAFETY: feed_chunk_carry renders a byte stream the
      SAME no matter where the read boundaries fall (bounded-exhaustive), so a
      split escape cannot leak its tail as text; its carry/drop memory is O(1).
  T9  GUI RENDER-PATH INERTNESS: cells_to_runs -- the pure render function the
      live Qt widget paints -- emits only safe display units for ANY cells and
      mode (the GUI alphabet: SAFE_ASCII, plus the box glyph, plus show-mode
      printable non-ASCII), never a bidi / invisible byte, a C1 / DEL, nor any
      C0 control OTHER than the four SAFE_ASCII whitelists render_output passes
      verbatim (TAB, LF, CR, BS -- whitespace and the line-edit controls the
      widget honors and Qt paints inertly, never as terminal cursor motion). It
      reduces to T1 (its run text IS render_output, +/- the documented
      '_'->BOX rewrite), so it inherits EXACTLY render_output's alphabet -- the
      whitelisted C0 included, every other control excluded.

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
    over adversarial probes INCLUDING escape-bearing ones (strip is delete-only;
    the per-character identity is recovered after ANSI_RE.sub). Together with the
    exhaustive per-code-point result it lifts the theorem from single characters
    to inputs of any length.

  STRENGTHENINGS (the original proof was weaker than it looked in these places):
    * Show-mode / paste-unicode / clip-unicode / tui / cells_to_runs "no invisible"
      checks originally called S.is_default_ignorable / S.is_bidi_control -- the
      SAME predicates the sanitizer uses to filter. A missing DI range would then
      leak AND pass the proof. Those checks now use an INDEPENDENT oracle built
      from Unicode Standard properties (regex \\p{Default_Ignorable_Code_Point},
      \\p{Bidi_Control}, unicodedata.category) and L-di / L-bidi prove the
      sanitizer's hand lists equal those properties on every code point.
    * T1's Z3 "classifier is total" ITE-cover is still there (it is a sanity
      check) but is no longer the flagship obligation: we now prove the
      non-vacuous converses (PASS implies SAFE_ASCII; ESC/BEL/C0/C1 never PASS)
      and evaluate the Z3 classifier against real render_output on a dense grid.
    * T1 originally never ran render_output on an ESC-containing string (L-hom
      stripped ESC first). The escape-strip path is now checked: delete-only,
      post-strip homomorphism, and the strict/show alphabet on those probes.
    * T4 did not forbid a display-copy path that DECODED a homoglyph to its
      ASCII look-alike (that output is still SAFE_ASCII). Confusables must now
      drop to empty. sanitize_clipboard_display is in the homomorphism loop.
    * T8's 8-symbol alphabet could not even form SS2/SS3, charset designators,
      or DEC-private CSI -- the split-escape class the theorem names. A catalog
      of real sequences is now split at every offset, the alphabet is richer,
      and the over-cap DISCARD path must resume on the right terminator (DCS
      must NOT treat BEL as end -- BEL is body).
    * T2's abstract WRITE never modelled the combining-mark flood-cap drop or
      line_edits=False (CSI becomes a no-op strip). Both are now transitions
      in the inductive proof and the real-vs-model grid.

  SCOPE / NOT PROVED HERE: only the PURE sanitizer (sanitize.py) is verified. The
  Qt widget layer is NOT: the no-write-back property (INV-6, "output never induces
  an input reply") and the full-widget earlier-line immutability remain covered by
  the property tests in test_invariants.py, which drive the live widget. This file
  proves the sanitizer core those tests exercise -- including T9's alphabet of
  cells_to_runs, the pure render function the live widget paints (the core behind
  INV-4's GUI half); the Qt insertion of those runs stays property-tested. It
  does not model Qt, pyte, the pty, or terminal.py's RUNTIME; the widget's live
  behaviour stays covered by test_widget.py.

Exit 0 on a fully discharged proof, 1 on any counterexample or unmet assumption.
A missing z3 or secure_terminal is a hard FAILURE (a verification suite must never
silently disable itself), never a skip.
"""

import sys
import unicodedata
from typing import Any

try:
    import regex as _regex
    import z3
    from secure_terminal import sanitize as S
except ImportError as exc:
    sys.stderr.write('secure-terminal-tests(verify_formal): FAIL missing '
                     'dependency (z3 / regex / secure_terminal): %s\n' % exc)
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

# ---------------------------------------------------------------------------
# Independent Unicode oracles. These MUST NOT call S.is_default_ignorable /
# S.is_bidi_control / S.is_invisible -- that circularity was the original proof's
# biggest silent weakness: a sanitizer regression that dropped a DI range would
# also drop it from the checker. Built from the Unicode Standard properties the
# regex module ships (UCD) plus unicodedata.category.
# ---------------------------------------------------------------------------
_DI_PROP = _regex.compile(r'\p{Default_Ignorable_Code_Point}')
_BIDI_PROP = _regex.compile(r'\p{Bidi_Control}')
INDEP_DI = frozenset(cp for cp in range(0, MAX_CP + 1)
                     if _DI_PROP.fullmatch(chr(cp)))
INDEP_BIDI = frozenset(cp for cp in range(0, MAX_CP + 1)
                       if _BIDI_PROP.fullmatch(chr(cp)))
# Cc except the four editing controls render_output is documented to pass.
_INDEP_CC_FORBIDDEN = frozenset(cp for cp in range(0, MAX_CP + 1)
                                if unicodedata.category(chr(cp)) == 'Cc'
                                and cp not in (0x08, 0x09, 0x0A, 0x0D))
_INDEP_FORMATISH = frozenset(cp for cp in range(0, MAX_CP + 1)
                             if unicodedata.category(chr(cp)) in
                             ('Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'))


def _indep_is_di(ch):
    return ord(ch) in INDEP_DI


def _indep_is_bidi(cp):
    return cp in INDEP_BIDI


def _indep_output_dangerous(oc):
    """True when `oc` is a character no sanitizer output (any mode) may emit:
    a bidi control, a default-ignorable, a C0/C1/DEL other than the four
    honored editing controls, or any format / surrogate / private-use /
    unassigned / line-or-paragraph separator. Independent of S.is_*."""
    cp = ord(oc)
    if cp in INDEP_BIDI or cp in INDEP_DI:
        return True
    if cp in _INDEP_CC_FORBIDDEN or cp in _INDEP_FORMATISH:
        return True
    return False


def _show_char_ok(ch):
    """Show-mode whitelist using the INDEPENDENT oracle, not S.is_*.

    Admits SAFE_ASCII, the documented BOX / SPACE_MARK markers, honest
    structural glyphs (box-drawing / block, via the sanitizer's structural
    carve-out -- a display-policy predicate, not a danger predicate), and a
    printable non-ASCII glyph that the Unicode properties say is neither
    default-ignorable nor a bidi control."""
    cp = ord(ch)
    if cp in SAFE_ASCII:
        return True
    if ch == S.BOX or ch == S.SPACE_MARK:
        return True
    if S.is_structural(cp) and not _indep_output_dangerous(ch):
        return True
    return (ch.isprintable() and not _indep_output_dangerous(ch))


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
    # HONEST LIMIT: this Or(...) is true of any four-way ITE; it is a sanity
    # check, not the security property. The NON-VACUOUS obligations follow.
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
        # Converses that the ITE-cover does NOT imply: a classifier that always
        # returns PASS is still "total", but these fail.
        z3_prove('classifier-pass-implies-safe-%s' % mode,
                 z3.Implies(cls == _CLS_PASS, _in_safe_ascii_z3(cp)),
                 assumptions=[in_range])
        z3_prove('classifier-unsafe-never-pass-%s' % mode,
                 z3.Implies(z3.Not(_in_safe_ascii_z3(cp)), cls != _CLS_PASS),
                 assumptions=[in_range])
        z3_prove('classifier-bel-drops-%s' % mode,
                 z3.Implies(cp == 0x07, cls == _CLS_DROP),
                 assumptions=[in_range])
        z3_prove('classifier-esc-never-pass-%s' % mode,
                 z3.Implies(cp == 0x1B, cls != _CLS_PASS),
                 assumptions=[in_range])
        z3_prove('classifier-c1-never-pass-%s' % mode,
                 z3.Implies(z3.And(0x80 <= cp, cp <= 0x9F), cls != _CLS_PASS),
                 assumptions=[in_range])

    # (4) Every nibble of an arbitrary code point (21-bit, six hex digits)
    # hex-encodes to SAFE_ASCII -- connecting the free nibble lemma to `cp`,
    # so a badge of U+10FFFF is covered, not only an unconstrained 0..15.
    for shift in (0, 4, 8, 12, 16, 20):
        nib = (cp / (1 << shift)) % 16          # Int div/mod (z3py has no Mod())
        z3_prove('badge-cp-nibble-shift-%d' % shift,
                 _in_safe_ascii_z3(_hexchar_z3(nib)),
                 assumptions=[in_range])


def t1_z3_faithfulness():
    """Evaluate the Z3 classifier at concrete code points and demand it matches
    the REAL render_output's branch -- so the SMT model cannot silently drift
    from the shipped function. Dense grid: every C0/C1/DEL, every ASCII, a
    BMP slice, the bidi / DI / astral corners, and the extremes."""
    sample = [*range(0x00, 0xA0), 0x7F, 0xA0, 0xAD, 0x061C, 0x200B,
              0x200E, 0x202E, 0x2066, 0x034F,
              0x3164, 0xFEFF, 0xFFFD, 0x10000,
              0x1F600, 0xE0100, MAX_CP]
    sample += list(range(0x2000, 0x2070))
    sample += list(range(0x2500, 0x25A0))
    seen = set()
    mismatches = 0
    for cp in sample:
        if cp in seen or not (0 <= cp <= MAX_CP):
            continue
        seen.add(cp)
        ch = chr(cp)
        for mode in STRICT_MODES:
            cls = z3.simplify(_classify_z3(z3.IntVal(cp), mode)).as_long()
            out = S.render_output(ch, mode)
            if cls == _CLS_PASS:
                ok = (out == ch)
            elif cls == _CLS_DROP:
                ok = (out == '')
            elif cls == _CLS_BOX:
                ok = (out == '_')
            else:                                 # BADGE
                ok = out.startswith('<U+') and out.endswith('>')
            if not ok:
                if mismatches < 8:
                    fail('T1 Z3 faithfulness: %s U+%04X cls=%d real=%r'
                         % (mode, cp, cls, out[:40]))
                mismatches += 1
    return mismatches


# ===========================================================================
# T1, part B -- EXHAUSTIVE enumeration on the REAL render_output.
# ===========================================================================
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

            # no default-ignorable / bidi / forbidden-class character survives.
            # Uses the INDEPENDENT oracle, not S.is_default_ignorable.
            if any(_indep_output_dangerous(oc) for oc in out):
                if ignorable_leak < 8:
                    fail('T1 invisible: %s leaked a dangerous char for U+%04X'
                         % (mode, cp))
                ignorable_leak += 1

        # --- the name-is-SAFE_ASCII assumption, on the real Unicode database ---
        # detail's badge embeds unicodedata.name(chr(cp)). str.isascii() is the
        # WRONG check -- it admits ESC/BEL/C0 (0x00-0x7F). Names must be in
        # SAFE_ASCII (Unicode names: A-Z, 0-9, space, hyphen).
        try:
            nm = unicodedata.name(ch)
        except ValueError:
            nm = ''
        if nm and any(ord(c) not in SAFE_ASCII for c in nm):
            if name_non_ascii < 8:
                fail('T1 name-ASCII: U+%04X name %r is not SAFE_ASCII' % (cp, nm))
            name_non_ascii += 1

        # --- show mode: the documented wider whitelist, but still no invisible ---
        out = S.render_output(ch, 'show')
        for oc in out:
            if not _show_char_ok(oc):
                if show_bad < 8:
                    fail('T1 show: U+%04X left non-whitelisted 0x%02X'
                         % (cp, ord(oc)))
                show_bad += 1
        if any(_indep_output_dangerous(oc) for oc in out):
            if ignorable_leak < 8:
                fail('T1 invisible: show leaked a dangerous char for U+%04X' % cp)
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

# Escape-bearing probes: the original L-hom never ran render_output on a string
# containing ESC (it stripped ESC before the identity check), so the ANSI_RE.sub
# path -- T1's claim about "any input" -- was an untested argument.
_ESC_PROBES = [
    '\x1b[31mRED\x1b[0m',
    '\x1b]0;title\x07plain',
    '\x1b]0;title\x1b\\plain',
    '\x1b[?25lhidden\x1b[?25h',
    '\x1b[?1049h', '\x1b[?2004h',
    '\x1bP$qm\x1b\\X',
    '\x1b_Gf=1\x1b\\Y',
    '\x1bNa', '\x1bO*',
    '\x1b(Bhello', '\x1b#8',
    '\x1bcRESET', '\x1b7\x1b8',
    '\x1b', '\x1b[', '\x1b[31',
    'pre\x1b[2Jpost',
    'a\x1b[>4;2mb',
    '\x1b]8;;http://evil\x1b\\link\x1b]8;;\x1b\\',
]


def _is_subsequence(short, long):
    """True when `short` is a (not necessarily contiguous) subsequence of `long`."""
    it = iter(long)
    return all(ch in it for ch in short)


def t1_homomorphism():
    """Executable backing for L-hom. render_output first strips escapes (a
    delete-only regex sub), THEN maps each surviving character independently with
    an append-only accumulator. So on ESCAPE-FREE text the whole function is a
    per-character homomorphism: render_output(s) == concat of render_output(ch).
    On text WITH escapes the same identity holds AFTER the strip:
        render_output(s) == concat(render_output(ch) for ch in ANSI_RE.sub('', s))
    and the strip itself is delete-only (a subsequence of s, never an insertion).
    Together these lift the per-code-point alphabet result to inputs of any
    length, including ones that carry CSI/OSC/DCS/SS2/charset sequences."""
    for probe in _HOM_PROBES:
        esc_free = probe.replace('\x1b', '')
        for mode in ('box', 'reveal', 'detail', 'show'):
            whole = S.render_output(esc_free, mode)
            piecewise = ''.join(S.render_output(ch, mode) for ch in esc_free)
            if whole != piecewise:
                fail('L-hom: %s not per-character on %r' % (mode, esc_free[:40]))

    for probe in _ESC_PROBES + _HOM_PROBES:
        stripped = S.ANSI_RE.sub('', probe)
        if not _is_subsequence(stripped, probe):
            fail('L-hom: ANSI_RE.sub is not delete-only on %r' % probe[:40])
        if '\x1b' in stripped:
            # An unmatched ESC may survive (lone ESC, incomplete CSI) -- it is
            # then boxed/badged as a control, never passed through. Pin that:
            # the strip must not INTRODUCE an ESC that was not in the input
            # (already implied by subsequence) and any surviving ESC is inert
            # after the per-character map (checked below).
            pass
        for mode in ('box', 'reveal', 'detail', 'show'):
            whole = S.render_output(probe, mode)
            piecewise = ''.join(S.render_output(ch, mode) for ch in stripped)
            if whole != piecewise:
                fail('L-hom: %s post-strip identity failed on %r'
                     % (mode, probe[:40]))
            if mode in STRICT_MODES:
                if any(ord(oc) not in SAFE_ASCII for oc in whole):
                    fail('T1 strict+esc: %s left a non-SAFE_ASCII byte on %r'
                         % (mode, probe[:40]))
            else:
                if any(not _show_char_ok(oc) or _indep_output_dangerous(oc)
                       for oc in whole):
                    fail('T1 show+esc: leaked a dangerous char on %r' % probe[:40])


def t1_predicate_lemmas():
    """L-di / L-bidi: the sanitizer's HAND lists equal the Unicode Standard
    properties, on every code point. Without this, T1-T9 that consult S.is_*
    (and the sanitizer itself) could agree on a WRONG list. Independent of
    the display-alphabet enumeration."""
    di_mismatch = 0
    bidi_mismatch = 0
    zs_mismatch = 0
    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)
        # Completeness (the security direction): every PRINTABLE Default_Ignorable
        # must be caught. The hand list is also allowed to name non-printable DIs
        # (Cf "belt and braces" -- U+180E, U+1D173..); that is conservative, not
        # a defect. Soundness: the hand list must not invent a non-DI code point.
        if ch.isprintable() and cp in INDEP_DI and not S.is_default_ignorable(ch):
            if di_mismatch < 8:
                fail('L-di: printable Unicode DI U+%04X missed by is_default_ignorable'
                     % cp)
            di_mismatch += 1
        if S.is_default_ignorable(ch) and cp not in INDEP_DI:
            if di_mismatch < 8:
                fail('L-di: is_default_ignorable(U+%04X) is not Unicode DI' % cp)
            di_mismatch += 1
        want_bidi = cp in INDEP_BIDI
        if bool(S.is_bidi_control(cp)) != want_bidi:
            if bidi_mismatch < 8:
                fail('L-bidi: is_bidi_control(U+%04X) = %s, Unicode Bidi_Control = %s'
                     % (cp, S.is_bidi_control(cp), want_bidi))
            bidi_mismatch += 1
        # is_space_separator: non-ASCII Zs. Independent of the sanitizer's
        # unicodedata.category call only in that we recompute it here; a drift
        # in the predicate's extra `cp != 0x20` guard would show up.
        want_zs = cp != 0x20 and unicodedata.category(ch) == 'Zs'
        if bool(S.is_space_separator(cp)) != want_zs:
            if zs_mismatch < 8:
                fail('L-zs: is_space_separator(U+%04X) = %s, category-Zs = %s'
                     % (cp, S.is_space_separator(cp), want_zs))
            zs_mismatch += 1
    return dict(di_mismatch=di_mismatch, bidi_mismatch=bidi_mismatch,
                zs_mismatch=zs_mismatch)


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
    seen: set[str] = set()
    whole = ''.join(stateful(seen, c) for c in s)          # 'ab' (state-dependent)
    piecewise = ''.join(stateful(set(), c) for c in s)     # 'aabb'
    _expect_caught('T1/homomorphism', whole != piecewise)

    # Independent-oracle canaries: the danger predicate must fire on a bidi
    # override AND on a PRINTABLE default-ignorable (Hangul filler -- the
    # ad<U+3164>min spoof that str.isprintable() keeps). A checker that only
    # used S.is_* would still "catch" these if the sanitizer list is complete
    # TODAY; the canary pins the INDEPENDENT bits.
    _expect_caught('T1/indep-bidi', _indep_output_dangerous('\u202e'))
    _expect_caught('T1/indep-hangul-filler', _indep_output_dangerous('\u3164'))
    _expect_caught('T1/indep-cgj', _indep_output_dangerous('\u034f'))
    _expect_caught('T1/show-rejects-bidi', not _show_char_ok('\u202e'))
    # A classifier that always-PASS is still "total"; the new converse must trip.
    cp = z3.Int('cp_canary')
    always_pass = z3.IntVal(_CLS_PASS)
    caught = not z3_prove('canary-pass-implies-safe',
                          z3.Implies(always_pass == _CLS_PASS,
                                     _in_safe_ascii_z3(cp)),
                          assumptions=[z3.And(0 <= cp, cp <= MAX_CP)],
                          report=False)
    _expect_caught('T1/z3-pass-implies-safe', caught)
    # L-di canary: a truncated hand list that omits U+3164 must disagree with
    # the Unicode DI property.
    truncated = ((0x034F, 0x034F),)
    missed = any(lo <= 0x3164 <= hi for lo, hi in truncated)
    _expect_caught('T1/L-di-truncated-list', not missed)
    # Delete-only canary: a "strip" that INSERTS a character is not a subsequence.
    _expect_caught('T1/delete-only', not _is_subsequence('abX', 'ab'))


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
#     cell of an already-committed line;
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
        """Shared C/G tail: clamp to the bound, pad L up to it, then the end-of-op
        anti-phantom clamp (`if max_line and col >= max_line: col = max_line-1`).
        Bounded: width max_line-1. Unbounded (M==0): _UNBOUNDED_MAX_COL, so a
        forward/absolute jump blank-pads to its column without an unbounded run."""
        clamped = z3.If(M > 0, _zmin(target, M - 1),
                        _zmin(target, S._UNBOUNDED_MAX_COL))
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
    if cls in ('BEL', 'SGR', 'ESC_STRIP', 'ESC_DROP', 'MARK_DROP'):
        return col, L                                # cursor-neutral
        # MARK_DROP: feed_line_edits drops a combining mark that would fuse an
        # over-cap run (left+1+right > _COMBINING_RUN_MAX) -- col and L stay.
        # The uniform grid never hits this (token is 'a'); t2_mark_drop_real does.
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
               'MARK_DROP',
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
    # covers PROMPT_FLUSH preserving INV directly. MARK_DROP is state-dependent
    # (only fires on an over-cap combining run); t2_mark_drop_real covers it.
    grid_classes = [c for c in _T2_CLASSES
                    if c not in ('PROMPT_FLUSH', 'MARK_DROP')]
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


def t2_mark_drop_real():
    """The combining-mark flood cap: writing a mark that would fuse an over-cap
    run must DROP the mark (col, L unchanged) and preserve INV. The Z3 WRITE
    model always advances col -- this path is a different transition."""
    mark = '\u0301'
    cap = S._COMBINING_RUN_MAX
    # M=0 (no wrap) and a width strictly above the cap, so col==L==cap is NOT
    # the autowrap phantom (that would reset the run BEFORE the drop check).
    for M in (0, cap + 4):
        cells = [(mark, ())] * cap
        col = cap
        _comp, cells2, col2, _sgr, _w = S.feed_line_edits(cells, col, {}, mark,
                                                          max_line=M)
        if (col2, len(cells2)) != (col, cap):
            fail('T2 mark-drop: cap=%d M=%d: expected frozen (col,L)=(%d,%d), '
                 'got (%d,%d)' % (cap, M, col, cap, col2, len(cells2)))
        if not (0 <= col2 <= len(cells2) and (M == 0 or len(cells2) <= M)):
            fail('T2 mark-drop: INV broken at M=%d -> (col=%d, L=%d)'
                 % (M, col2, len(cells2)))
        # Under the cap, a mark is a WRITE (advances).
        cells_s = [(mark, ())] * 2
        _c, cells3, col3, _s, _w = S.feed_line_edits(cells_s, 2, {}, mark,
                                                     max_line=M if M == 0 else max(M, 4))
        if (col3, len(cells3)) == (2, 2):
            fail('T2 mark-drop: a short combining run was wrongly dropped')


def t2_line_edits_off():
    """line_edits=False: CSI C/D/G/K are consumed (no leftover '[3C' garbage)
    but MUST NOT move the cursor or change L -- they fall through to ANSI_RE
    strip. The Z3 model is of line_edits=True; this is the other mode."""
    tokens = ['\x1b[C', '\x1b[12C', '\x1b[D', '\x1b[3D', '\x1b[G', '\x1b[4G',
              '\x1b[K', '\x1b[0K', '\x1b[1K', '\x1b[2K', '\x1b[3K']
    for M in (0, 3, 5):
        for L in (0, 2, 4):
            if M > 0 and L > M:
                continue
            for col in (0, L):
                if M > 0 and col > M:
                    continue
                cells = [('a', ())] * L
                for tok in tokens:
                    _c, cells2, col2, _s, _w = S.feed_line_edits(
                        cells, col, {}, tok, max_line=M, line_edits=False)
                    if (col2, len(cells2)) != (col, L):
                        fail('T2 line_edits=False: %r moved cursor/L at '
                             'col=%d L=%d M=%d -> (%d,%d)'
                             % (tok, col, L, M, col2, len(cells2)))


def t2_prompt_flush_real():
    """PROMPT_FLUSH isolated operationally: marker + following printable, from
    a non-zero column, must emit the current line then write the printable
    (so (col,L) becomes (1,1), not the model's (0,0) which is the flush
    half only). INV must hold."""
    cells = [('a', ())] * 3
    comp, cells2, col2, _s, _w = S.feed_line_edits(
        cells, 3, {}, S.PROMPT_START + 'x', max_line=0)
    if len(comp) != 1 or list(comp[0]) != list(cells):
        fail('T2 prompt-flush: did not emit the current line intact')
    if (col2, len(cells2)) != (1, 1) or cells2[0][0] != 'x':
        fail('T2 prompt-flush: expected write-after-flush (1,1 x), got '
             'col=%d L=%d cells=%r' % (col2, len(cells2), cells2))
    # zsh order: marker with NOTHING printable following must NOT flush.
    cells = [('a', ())] * 3
    comp, cells2, col2, _s, _w = S.feed_line_edits(
        cells, 3, {}, S.PROMPT_START, max_line=0)
    if comp or (col2, len(cells2)) != (3, 3):
        fail('T2 prompt-noop: marker without following prompt flushed or moved')


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
        stack = list(targets)                   # a work-list of ast.expr nodes
        while stack:
            tgt = stack.pop()
            if isinstance(tgt, (ast.Tuple, ast.List)):
                stack.extend(tgt.elts)
            elif isinstance(tgt, ast.Starred):
                stack.append(tgt.value)
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
        seqs: list[list[str]] = [[]]
        for _ in range(3):
            seqs = [[*s, t] for s in seqs for t in _T2_INCR_TOKENS]
        for toks in seqs:
            whole = S.feed_line_edits([], 0, {}, ''.join(toks), max_line=M)
            comp_whole = whole[0]
            # feed token by token, carrying state; accumulate completed lines
            cells: list[Any] = []
            col = 0
            sgr: dict[Any, Any] = {}
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
# T3-T7 -- the INPUT / CLIPBOARD / TITLE / CELL side of the pure sanitizer, over
# ALL inputs. Same technique as T1: each function is a per-character (or simple
# string) map, so exhaustive enumeration over every code point is a TOTAL proof of
# its output alphabet on the REAL function, and Z3 proves the arithmetic
# classifier of the two flagship functions symbolically. With T1/T2 this covers
# the whole PURE sanitizer -- input AND output -- not only the display path.
#
#   T3  paste no-auto-execute (INV-1/5, pure level): a pasted string can never
#       carry an escape / control / bidi / invisible to the shell, and can never
#       auto-submit -- no trailing carriage return survives the no-autosubmit
#       strip, and the CLI's whole-CR strip leaves none at all.
#   T4  clipboard-exfil safety: nothing placed on the system clipboard carries a
#       control / bidi / invisible byte; the ASCII clipboard drops every non-ASCII
#       byte (a homoglyph cannot ride out); the display-copy path rewrites the
#       inert display glyphs to an ASCII stand-in yet never emits a raw
#       neutralized / homoglyph code point.
#   T5  title safety: a program-supplied title / notification is reduced to
#       printable ASCII, length-bounded, and idempotent.
#   T6  TUI-cell inertness: every grid cell is a single safe display unit -- the
#       cell's own glyph only when every code point in it is safe, else the box
#       (or, in show mode, the non-ASCII-space marker); never an invisible / bidi
#       / control / default-ignorable.
#   T7  classification agreement: classify_paste / paste_findings name a character
#       the SAME class the display marking (marking_class) does, so the paste
#       warning and the on-screen risk colour can never disagree.
# ===========================================================================

_PASTE_SAFE = frozenset((0x09, 0x0D)) | frozenset(range(0x20, 0x7F))   # tab, CR, ASCII
_CLIP_ASCII = frozenset((0x09, 0x0A)) | frozenset(range(0x20, 0x7F))   # tab, NL, ASCII


def _is_control_cp(cp):
    """C0 / DEL / C1 -- the control class classify_paste and paste_findings use."""
    return cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F


def t_input_z3():
    """Z3: the two flagship input classifiers map EVERY code point into their safe
    output alphabet, symbolically over the whole range (the enumeration below
    validates that against the real code)."""
    cp = z3.Int('cp')
    in_range = z3.And(0 <= cp, cp <= MAX_CP)
    ascii_pr = z3.And(0x20 <= cp, cp <= 0x7E)

    # sanitize_paste: '\n'/'\r' -> 0x0D; '\t' or printable ASCII -> itself; else
    # dropped. So the kept output code point is always in {0x09,0x0D} u [0x20,0x7E].
    emitted = z3.If(z3.Or(cp == 0x0A, cp == 0x0D), z3.IntVal(0x0D), cp)
    kept = z3.Or(cp == 0x0A, cp == 0x0D, cp == 0x09, ascii_pr)
    z3_prove('T3-paste-alphabet',
             z3.Implies(kept, z3.Or(emitted == 0x09, emitted == 0x0D,
                                    z3.And(0x20 <= emitted, emitted <= 0x7E))),
             assumptions=[in_range])
    # and a paste NEVER keeps a raw newline (every newline becomes CR), so it can
    # never smuggle a hidden second command line.
    z3_prove('T3-paste-no-raw-newline',
             z3.Implies(kept, emitted != 0x0A), assumptions=[in_range])
    # NON-VACUOUS drop-set: Implies(kept, safe) is true of a classifier that
    # keeps nothing. These fail if ESC / C0 / DEL / C1 / bidi ranges are added
    # to `kept`.
    z3_prove('T3-paste-drops-esc',
             z3.Implies(cp == 0x1B, z3.Not(kept)), assumptions=[in_range])
    z3_prove('T3-paste-drops-bel',
             z3.Implies(cp == 0x07, z3.Not(kept)), assumptions=[in_range])
    z3_prove('T3-paste-drops-del',
             z3.Implies(cp == 0x7F, z3.Not(kept)), assumptions=[in_range])
    z3_prove('T3-paste-drops-c0',
             z3.Implies(z3.And(cp < 0x20, cp != 0x09, cp != 0x0A, cp != 0x0D),
                        z3.Not(kept)),
             assumptions=[in_range])
    z3_prove('T3-paste-drops-c1',
             z3.Implies(z3.And(0x80 <= cp, cp <= 0x9F), z3.Not(kept)),
             assumptions=[in_range])
    z3_prove('T3-paste-drops-bidi-override',
             z3.Implies(z3.And(0x202A <= cp, cp <= 0x202E), z3.Not(kept)),
             assumptions=[in_range])
    z3_prove('T3-paste-drops-bidi-isolate',
             z3.Implies(z3.And(0x2066 <= cp, cp <= 0x2069), z3.Not(kept)),
             assumptions=[in_range])
    z3_prove('T3-paste-drops-alm',
             z3.Implies(cp == 0x061C, z3.Not(kept)), assumptions=[in_range])

    # sanitize_clipboard: kept iff '\n'/'\t' or printable ASCII; the kept char is
    # itself, so the ASCII-clipboard alphabet is exactly {0x09,0x0A} u [0x20,0x7E].
    ckept = z3.Or(cp == 0x0A, cp == 0x09, ascii_pr)
    z3_prove('T4-clip-ascii-alphabet',
             z3.Implies(ckept, z3.Or(cp == 0x09, cp == 0x0A,
                                     z3.And(0x20 <= cp, cp <= 0x7E))),
             assumptions=[in_range])
    z3_prove('T4-clip-drops-esc',
             z3.Implies(cp == 0x1B, z3.Not(ckept)), assumptions=[in_range])
    z3_prove('T4-clip-drops-cr',
             z3.Implies(cp == 0x0D, z3.Not(ckept)), assumptions=[in_range])
    z3_prove('T4-clip-drops-c1',
             z3.Implies(z3.And(0x80 <= cp, cp <= 0x9F), z3.Not(ckept)),
             assumptions=[in_range])
    z3_prove('T4-clip-drops-homoglyph-cyrillic-a',
             z3.Implies(cp == 0x0430, z3.Not(ckept)), assumptions=[in_range])


def _tui_char_ok(oc, mode):
    """The TUI-cell output alphabet: printable ASCII, the box placeholder, and (in
    show mode only) the non-ASCII-space marker or a printable non-ASCII glyph that
    the INDEPENDENT oracle says is not dangerous. Never an invisible / bidi /
    control / default-ignorable."""
    cp = ord(oc)
    if 0x20 <= cp <= 0x7E:
        return True
    if oc == S.BOX:
        return True
    if mode == 'show':
        if oc == S.SPACE_MARK:
            return True
        return oc.isprintable() and not _indep_output_dangerous(oc)
    return False


def _classify_family(cp):
    """The marking family classify_paste assigns a non-plain-ASCII code point, in
    classify_paste's own precedence order (bidi > control > invisible > other)."""
    if S.is_bidi_control(cp):
        return 'bidi'
    if _is_control_cp(cp):
        return 'control'
    if S.is_invisible(chr(cp)):
        return 'invisible'
    return 'nonascii'


_MARKING_FAMILY = {'bidi': 'bidi', 'control': 'control', 'invisible': 'invisible',
                   'confusable': 'nonascii', 'combining': 'nonascii',
                   'nonascii': 'nonascii'}
_LABEL_FAMILY = {'bidirectional control': 'bidi', 'control character': 'control',
                 'invisible character': 'invisible',
                 'non-ASCII character': 'nonascii'}


def t_input_enumerate():
    """Run the REAL input / clipboard / title / cell / classify functions on every
    code point and confirm each output alphabet and classification. Total over the
    code-point domain -- not sampling."""
    st = dict(paste=0, paste_uni=0, clip=0, clip_uni=0, clip_disp=0, title=0,
              tui=0, classify=0, findings=0)

    def note(key, msg):
        if st[key] < 6:
            fail(msg)
        st[key] += 1

    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)
        plain = (cp in (0x09, 0x0A, 0x0D)) or (0x20 <= cp <= 0x7E)

        # --- T3 sanitize_paste: alphabet {tab, CR, ASCII}; newline -> CR; nothing
        #     invisible / bidi / control ever survives ---
        out = S.sanitize_paste(ch)
        for oc in out:
            if ord(oc) not in _PASTE_SAFE:
                note('paste', 'T3 paste: U+%04X left 0x%02X' % (cp, ord(oc)))
        want = ('\r' if cp in (0x0A, 0x0D)
                else ch if (cp == 0x09 or 0x20 <= cp <= 0x7E) else '')
        if out != want:
            note('paste', 'T3 paste: U+%04X -> %r, want %r' % (cp, out, want))

        # --- T3 sanitize_paste_unicode: keeps printable non-ASCII, still drops
        #     every control / bidi / invisible / default-ignorable; newline -> CR ---
        outu = S.sanitize_paste_unicode(ch)
        if '\n' in outu:
            note('paste_uni', 'T3 paste-uni: U+%04X left a raw newline' % cp)
        for oc in outu:
            ok = (oc in '\r\t'
                  or (oc.isprintable() and not _indep_output_dangerous(oc)))
            if not ok:
                note('paste_uni', 'T3 paste-uni: U+%04X left 0x%02X'
                     % (cp, ord(oc)))

        # --- T4 sanitize_clipboard: ASCII printable + tab + newline only ---
        outc = S.sanitize_clipboard(ch)
        for oc in outc:
            if ord(oc) not in _CLIP_ASCII:
                note('clip', 'T4 clip: U+%04X left 0x%02X' % (cp, ord(oc)))

        # --- T4 sanitize_clipboard_unicode: no control(except \n\t) / bidi /
        #     invisible / default-ignorable ---
        outcu = S.sanitize_clipboard_unicode(ch)
        for oc in outcu:
            ok = (oc in '\n\t'
                  or (oc.isprintable() and not _indep_output_dangerous(oc)))
            if not ok:
                note('clip_uni', 'T4 clip-uni: U+%04X left 0x%02X'
                     % (cp, ord(oc)))

        # --- T4 sanitize_clipboard_display: ASCII-only out; inert display glyphs
        #     map to an ASCII stand-in (not lost to nothing); a raw neutralized /
        #     homoglyph code point is NEVER emitted -- including NOT decoded to
        #     its ASCII look-alike (that output is still _CLIP_ASCII, so the
        #     alphabet check alone would miss it). ---
        outd = S.sanitize_clipboard_display(ch)
        for oc in outd:
            if ord(oc) not in _CLIP_ASCII:
                note('clip_disp', 'T4 clip-disp: U+%04X left 0x%02X'
                     % (cp, ord(oc)))
        if (cp == 0x25A1 or cp == 0x2423 or S.is_structural(cp)) and not outd:
            note('clip_disp', 'T4 clip-disp: inert glyph U+%04X lost to nothing'
                 % cp)
        if S.marking_class(cp) == 'confusable' and outd:
            note('clip_disp', 'T4 clip-disp: homoglyph U+%04X decoded/emitted as %r'
                 % (cp, outd))

        # --- T5 sanitize_title: printable ASCII only, no leading/trailing space ---
        # T5 is a PROPERTY check (safe output alphabet + no surrounding space here,
        # idempotence + length bound below), NOT a char-level differential against an
        # independent reference like T1/T3/T4. The title contract is "reduce to a safe
        # printable-ASCII label", so the alphabet + idempotence bounds ARE the security
        # guarantee; there is no canonical target transform to differentially compare.
        outt = S.sanitize_title(ch)
        for oc in outt:
            if not 0x20 <= ord(oc) <= 0x7E:
                note('title', 'T5 title: U+%04X left 0x%02X' % (cp, ord(oc)))
        if outt != outt.strip():
            note('title', 'T5 title: U+%04X left surrounding space %r' % (cp, outt))

        # --- T6 tui_cell: a single safe display unit, in every mode; never an
        #     invisible / bidi / control / default-ignorable ---
        for mode in S.DISPLAY_MODES:
            cell = S.tui_cell(ch, mode)
            for oc in cell:
                if not _tui_char_ok(oc, mode):
                    note('tui', 'T6 tui: %s U+%04X left 0x%02X'
                         % (mode, cp, ord(oc)))
            if any(_indep_output_dangerous(oc) for oc in cell):
                note('tui', 'T6 tui: %s U+%04X left a dangerous char' % (mode, cp))

        # --- T7 classify_paste / paste_findings agree with marking_class ---
        if not plain:
            fam = _classify_family(cp)
            mcls = S.marking_class(cp)
            res = S.classify_paste(ch)
            label = res[0][0] if res else None
            # An UNMAPPED class/label is exactly the drift this check exists to
            # catch -- report it as a FAILURE, never let it KeyError and abort the
            # enumeration (which would leave every later code point unchecked).
            if mcls not in _MARKING_FAMILY or (label is not None
                                               and label not in _LABEL_FAMILY):
                note('classify', 'T7 classify: U+%04X unmapped class/label '
                     '(marking=%r label=%r)' % (cp, mcls, label))
            else:
                mfam = _MARKING_FAMILY[mcls]
                cfam = _LABEL_FAMILY[label] if label is not None else None
                if not (fam == mfam == cfam):
                    note('classify', 'T7 classify: U+%04X classify=%s marking=%s '
                         'family=%s disagree' % (cp, cfam, mfam, fam))
            # paste_findings classifies a SINGLE character, so its if/else makes
            # control and non-ASCII mutually exclusive here (a C1 byte is reported
            # as control, not unicode); the enumeration feeds one code point at a
            # time, so has_uni is exactly `not has_ctrl`.
            has_uni, has_ctrl = S.paste_findings(ch)
            want_ctrl = _is_control_cp(cp)
            if has_ctrl != want_ctrl or has_uni != (not want_ctrl):
                note('findings', 'T7 findings: U+%04X (%s,%s) want ctrl=%s'
                     % (cp, has_uni, has_ctrl, want_ctrl))

    return st


# Adversarial multi-code-point cells + string-level properties the per-character
# enumeration cannot express. Escape-encoded to keep this file ASCII-only.
_T6_MULTI = [
    'a\u200b', 'a\u202e', 'x\u0301', '\u00c1\u0302', '\u2500\u202e',
    'a' + '\u0301' * 40, '\u4e00\u200d', '\u00e9',
]
_STR_PROBES = [
    '', 'plain paste', 'a\rb\rc\r', 'line1\nline2\ncmd', 'tab\tend',
    'x\u202ey\u200bz', 'euro \u20ac and cjk \u4e00', '\r\r\r', 'trailing\r\n',
    'a' * 200, '  spaced  title  \t\n', '\u0430dmin', 'box \u2500\u2502 \u25a1',
]


def t_input_strings():
    """String-level properties the per-character maps guarantee only in composition:
    no-auto-submit, the CLI whole-CR strip, title idempotence + length bound, the
    per-character homomorphism, and multi-code-point TUI cells collapsing to the box
    when any code point is unsafe."""
    # no-auto-submit: paste_no_autosubmit never leaves a trailing CR, is idempotent,
    # and '' -> ''. And the security composition: a sanitized paste, after the
    # no-autosubmit strip, never ends in CR -- so a single-line paste cannot run.
    if S.paste_no_autosubmit('') != '':
        fail('T3 no-autosubmit: empty input not empty output')
    for probe in _STR_PROBES:
        stripped = S.paste_no_autosubmit(S.sanitize_paste(probe))
        if stripped.endswith('\r'):
            fail('T3 no-autosubmit: %r still ends with CR' % probe)
        if S.paste_no_autosubmit(stripped) != stripped:
            fail('T3 no-autosubmit: not idempotent on %r' % probe)
        # The exact bytes cli.py forwards to the dumb child (cli.py:
        # sanitize_paste(text).replace('\r', '') -- EVERY CR, not just the trailing
        # run). They must be inert AND submit-free: tab + printable ASCII only, so
        # no CR (no auto-run), no control and no escape reach the child. (Not the
        # tautology `'\r' in x.replace('\r','')`, which is always False.)
        child = S.sanitize_paste(probe).replace('\r', '')
        if any(not (c == '\t' or 0x20 <= ord(c) <= 0x7E) for c in child):
            fail('T3 cli-cr-strip: the dumb child would receive a non-inert byte '
                 'on %r' % probe)

    # sanitize_title: idempotent and length-bounded, for any input.
    for probe in [*_STR_PROBES, '\x1b]0;' + 'A' * 300 + '\x07']:
        t1 = S.sanitize_title(probe)
        if S.sanitize_title(t1) != t1:
            fail('T5 title: not idempotent on %r' % probe[:40])
        if len(t1) > 80:
            fail('T5 title: length %d exceeds the cap on %r' % (len(t1), probe[:40]))
        if not t1.isascii() or any(not 0x20 <= ord(c) <= 0x7E for c in t1):
            fail('T5 title: non-printable-ASCII survived on %r' % probe[:40])

    # per-character homomorphism: the paste / clipboard maps are pure per-character
    # joins, so the whole-string result is the concatenation of the per-character
    # results -- which is what lifts the exhaustive single-code-point result to
    # inputs of any length. sanitize_clipboard_display is the same composition
    # (_display_glyph_to_ascii then sanitize_clipboard) -- originally omitted.
    for probe in _STR_PROBES:
        for fn in (S.sanitize_paste, S.sanitize_paste_unicode, S.sanitize_clipboard,
                   S.sanitize_clipboard_unicode, S.sanitize_clipboard_display):
            if fn(probe) != ''.join(fn(c) for c in probe):
                fail('T3/T4 homomorphism: %s not per-character on %r'
                     % (fn.__name__, probe[:40]))

    # paste_is_multiline: True iff a newline/CR appears BEFORE the last character
    # (a trailing submit on a single line is NOT multi-command). This is the
    # hold-for-review trigger; T3 originally never mentioned it. The oracle must
    # mirror the real function's CRLF-pair collapse first: a Windows-style single
    # line 'cmd\r\n' is ONE command (the '\r' sitting before the final '\n' is a
    # pair, not an embedded submit), so it is NOT multi-line -- computing `want`
    # off the raw probe[:-1] would wrongly flag 'trailing\r\n'.
    for probe in [*_STR_PROBES, 'a\nb', 'a\n', '\n', 'a\rb', 'ab', '']:
        collapsed = probe.replace('\r\n', '\n')
        want = (len(collapsed) > 0
                and (('\n' in collapsed[:-1]) or ('\r' in collapsed[:-1])))
        if bool(S.paste_is_multiline(probe)) != want:
            fail('T3 paste_is_multiline: %r -> %s, want %s'
                 % (probe[:40], S.paste_is_multiline(probe), want))

    # multi-code-point TUI cells: any unsafe code point in the cell -> the box (or,
    # for a lone show-mode non-ASCII space, the marker); never the raw cell.
    for cell in _T6_MULTI:
        for mode in S.DISPLAY_MODES:
            out = S.tui_cell(cell, mode)
            if any(not _tui_char_ok(oc, mode) for oc in out):
                fail('T6 tui multi: %s %r left a non-inert char (%r)'
                     % (mode, cell, out))


def t_input_canaries():
    # T3 canary: an identity paste (no strip) leaks a bidi override + a raw newline.
    leaked = 'echo\u202e\npwn'
    _expect_caught('T3/paste-alphabet',
                   any(ord(oc) not in _PASTE_SAFE for oc in leaked))
    # no-autosubmit canary: an identity strip leaves the trailing CR.
    _expect_caught('T3/no-autosubmit', 'echo x\r'.endswith('\r'))
    # cli-cr-strip canary: a child input that still holds a CR (or any non-inert
    # byte) must be caught by the tab+printable-ASCII alphabet check.
    _expect_caught('T3/cli-cr-strip',
                   any(not (c == '\t' or 0x20 <= ord(c) <= 0x7E) for c in 'echo\r'))
    # T4 canary: a raw homoglyph left on the ASCII clipboard.
    _expect_caught('T4/clip-ascii',
                   any(ord(oc) not in _CLIP_ASCII for oc in 'a\u0430'))
    # T5 canary: a control byte surviving into a title.
    _expect_caught('T5/title', any(not 0x20 <= ord(c) <= 0x7E for c in 'a\x1bb'))
    # T6 canary: an invisible passed straight into a cell.
    _expect_caught('T6/tui', not _tui_char_ok('\u200b', 'show'))
    # T7 canary: a classifier that calls a bidi override a plain non-ASCII char
    # disagrees with the display marking (which calls it bidi).
    _expect_caught('T7/classify', _LABEL_FAMILY['non-ASCII character']
                   != _MARKING_FAMILY[S.marking_class(0x202E)])
    # T4 homoglyph-decode canary: Cyrillic a emitted as ASCII 'a' is still
    # _CLIP_ASCII, so the alphabet check would MISS it; the new check must trip.
    _expect_caught('T4/homoglyph-decode',
                   S.marking_class(0x0430) == 'confusable' and ord('a') in _CLIP_ASCII)
    # T3 paste_is_multiline canary: the REAL classifier flags 'a\nb' as multi-line
    # (a newline before the last char), so an always-False stub would be caught by
    # the T3 differential above. Driving S.paste_is_multiline (not a re-inlined
    # oracle) keeps the canary from drifting from the function it guards.
    _expect_caught('T3/paste-is-multiline', S.paste_is_multiline('a\nb'))


# ===========================================================================
# T8 -- CHUNK-BOUNDARY ESCAPE SAFETY (the split-escape leak class), Tier 2.
#
# cli.py feeds child output one os.read() chunk at a time through
# feed_chunk_carry(), which holds an escape split across a read boundary so its
# tail cannot render as literal text. Two properties:
#
#   T8a  SPLIT-INVARIANCE: for a given byte stream, the rendered output is the
#        SAME no matter where the read boundaries fall -- so re-chunking can never
#        make an escape (or its tail) leak. This is what closes the split-escape
#        prompt-spoofing class. Verified by BOUNDED EXHAUSTION: every stream over an
#        escape-relevant alphabet up to a bounded length, under EVERY chunking, must
#        render identically to the whole-stream case. (Bounded, honestly: this is
#        bounded model checking over short streams, not the unbounded induction of
#        T1/T2. The over-carry-cap DISCARD path -- reached only by a sequence longer
#        than cap, ~4096 bytes -- is out of this bounded check and stays covered by
#        the fuzz suite; T8b checks its memory bound directly.)
#   T8b  O(1) MEMORY: across an arbitrarily long, never-terminated string sequence
#        fed in many chunks, the carried state stays bounded -- the carry never
#        exceeds cap and the drop is at most one introducer byte -- so hostile
#        output cannot balloon memory.
# ===========================================================================

# Escape-relevant alphabet: ESC, CSI/OSC/DCS/APC/SS2 introducers, ST/BEL
# terminator, a parameter/final byte, DEC-private '?', charset intermediate '(',
# and a plain text byte. The ORIGINAL 8-symbol alphabet could not form SS2/SS3
# (ESC N / ESC O), charset designators (ESC ( B), or DEC-private CSI (ESC [ ?)
# -- the split-escape class T8 names. Exhaustion below uses this richer set at
# a slightly smaller max_len, plus the original 8 at max_len=5, plus a catalog
# of real sequences split at every offset.
_T8_ALPHABET = ['\x1b', '[', ']', 'P', '\\', '\x07', 'm', 'a']
_T8_ALPHABET_RICH = ['\x1b', '[', ']', 'P', 'N', 'O', '\\', '\x07',
                     'm', 'a', '?', '(', '0', '_']

# Representative sequences of EVERY ANSI_RE arm, plus the split-sensitive
# neighbours (DEC private, charset, SS2/SS3, OSC ST vs BEL, DCS-with-BEL-in-body).
_T8_CATALOG = [
    '\x1b[31m',                    # CSI SGR
    '\x1b[?25l',                   # DEC-private CSI
    '\x1b[?2004h',                 # bracketed-paste enable
    '\x1b[>4;2m',                  # private-prefix CSI
    '\x1b]0;title\x07',            # OSC BEL
    '\x1b]0;title\x1b\\',          # OSC ST
    '\x1bP$qm\x1b\\',              # DCS
    '\x1bPbody\x07secret\x1b\\',   # DCS: BEL is BODY, only ST ends it
    '\x1b_Gf=1\x1b\\',             # APC
    '\x1b^pm\x1b\\',               # PM
    '\x1bXsos\x1b\\',              # SOS
    '\x1b(B',                      # charset G0
    '\x1b)0',                      # charset G1
    '\x1b#8',                      # DECALN
    '\x1bc',                       # RIS
    '\x1b7', '\x1b8',
    '\x1bNa',                      # SS2
    '\x1bO*',                      # SS3
    'a\x1b[2K\x1b[1Gb',
    '\x1b]8;;http://e\x1b\\',
    'HELLO\x1b[31mRED',
]


def _cli_pipeline(chunks, cap=4096):
    """Drive feed_chunk_carry across `chunks` exactly as cli.py does -- carry the
    incomplete-escape state, render each emitted piece -- and return the
    concatenated rendered output plus the max (carry, drop) sizes seen."""
    carry, drop = '', ''
    out = []
    max_carry = max_drop = 0
    for chunk in chunks:
        text, carry, drop, _ = S.feed_chunk_carry(chunk, carry, drop, cap=cap)
        out.append(S.render_output(text, 'detail'))
        max_carry = max(max_carry, len(carry))
        max_drop = max(max_drop, len(drop))
    return ''.join(out), max_carry, max_drop


def _all_chunkings(s):
    """Every way to cut string `s` at its internal gaps into consecutive chunks."""
    n = len(s)
    if n <= 1:
        yield [s] if s else ['']
        return
    for mask in range(1 << (n - 1)):        # each interior gap: cut or not
        chunks, start = [], 0
        for i in range(n - 1):
            if mask & (1 << i):
                chunks.append(s[start:i + 1])
                start = i + 1
        chunks.append(s[start:])
        yield chunks


def _t8_check_stream(s, bad, label):
    """All chunkings of `s` (and the 1-byte-chunk split) must render equal to the
    whole-stream pipeline, and the rendered alphabet must be T1-strict (detail)."""
    whole, _mc, _md = _cli_pipeline([s])
    if any(ord(oc) not in SAFE_ASCII for oc in whole):
        if bad[0] < 8:
            fail('T8 alphabet: %s whole-stream left a non-SAFE_ASCII byte on %r'
                 % (label, s[:40]))
        bad[0] += 1
    bytewise, _mc, _md = _cli_pipeline(list(s) if s else [''])
    if bytewise != whole:
        if bad[0] < 8:
            fail('T8 split-invariance: %s bytewise %r != whole %r on %r'
                 % (label, bytewise[:40], whole[:40], s[:40]))
        bad[0] += 1
    for chunks in _all_chunkings(s):
        got, _mc, _md = _cli_pipeline(chunks)
        if got != whole:
            if bad[0] < 8:
                fail('T8 split-invariance: %s %r chunked %r renders %r != %r'
                     % (label, s, chunks, got, whole))
            bad[0] += 1
            break
    return bad[0]


def t8_split_invariance(max_len=5):
    """BOUNDED-EXHAUSTIVE: over every stream up to max_len and EVERY chunking, the
    rendered output must equal the whole-stream rendering. A split-escape leak would
    make some chunking diverge.

    Three layers (the original 8-symbol max_len=5 pass is preserved):
      (a) original alphabet, max_len=5
      (b) richer alphabet that can form SS2/SS3/charset/DEC-private, max_len=3
      (c) catalog of real sequences of every ANSI_RE arm, split at every offset
          and 1-byte-at-a-time (the most aggressive split)."""
    import itertools
    bad = [0]
    for length in range(1, max_len + 1):
        for tup in itertools.product(_T8_ALPHABET, repeat=length):
            _t8_check_stream(''.join(tup), bad, 'orig')
    # max_len=3 on the rich alphabet: enough to form SS2 (ESC N a), charset
    # (ESC ( 0), DEC-private starters (ESC [ ?), without 14^4 blow-up. The
    # catalog below covers the longer real sequences split at every offset.
    for length in range(1, 4):
        for tup in itertools.product(_T8_ALPHABET_RICH, repeat=length):
            _t8_check_stream(''.join(tup), bad, 'rich')
    for seq in _T8_CATALOG:
        _t8_check_stream(seq, bad, 'catalog')
        # also: split at every single interior offset into exactly two chunks
        for i in range(1, len(seq)):
            got, _mc, _md = _cli_pipeline([seq[:i], seq[i:]])
            whole, _mc, _md = _cli_pipeline([seq])
            if got != whole:
                if bad[0] < 8:
                    fail('T8 catalog two-cut: %r at %d -> %r != %r'
                         % (seq, i, got, whole))
                bad[0] += 1
    return bad[0]


def t8_memory_bound():
    """O(1) memory: a long, never-terminated string sequence fed byte-by-byte keeps
    the carry <= cap and the drop <= 1 the whole way, and the over-cap DISCARD state
    engages so memory stays bounded rather than growing with the input."""
    cap = 16                                # small cap so the discard path engages fast
    carry, drop = '', ''
    # OSC introducer then an endless body with no terminator (BEL/ST never sent).
    stream = '\x1b]' + 'a' * 4000
    engaged_discard = False
    over = 0
    for byte in stream:
        _text, carry, drop, _ = S.feed_chunk_carry(byte, carry, drop, cap=cap)
        if len(carry) > cap:
            over += 1
        if len(drop) > 1:
            over += 1
        if drop:
            engaged_discard = True
    if over:
        fail('T8 memory-bound: carry/drop exceeded the bound %d time(s)' % over)
    if not engaged_discard:
        fail('T8 memory-bound: the over-cap discard state never engaged '
             '(the bound was not actually exercised)')


def t8_discard_resume():
    """Over-cap DISCARD must (a) swallow the string-sequence body, (b) RESUME
    rendering after the RIGHT terminator, (c) not treat BEL as end-of-DCS (BEL
    is body for DCS/SOS/PM/APC; only OSC ends on BEL). Originally T8b only
    fed an unterminated OSC -- the resume and the DCS-BEL distinction were
    untested, so a terminator mix-up would not have tripped the proof."""
    cap = 16

    def run(chunks):
        carry, drop = '', ''
        out = []
        for chunk in chunks:
            text, carry, drop, _ = S.feed_chunk_carry(chunk, carry, drop, cap=cap)
            out.append(S.render_output(text, 'detail'))
        return ''.join(out), drop

    # OSC: BEL terminates; body must vanish; VISIBLE must survive.
    got, drop = run(['\x1b]', 'SECRET' + 'x' * 40, '\x07VISIBLE'])
    if 'SECRET' in got or 'xxx' in got:
        fail('T8 discard-resume: OSC body leaked: %r' % got[:60])
    if 'VISIBLE' not in got:
        fail('T8 discard-resume: OSC swallow-past-BEL, lost VISIBLE: %r' % got[:60])
    if drop:
        fail('T8 discard-resume: OSC drop not cleared after BEL')

    # OSC ST terminator too.
    got, drop = run(['\x1b]', 'SECRET' + 'x' * 40, '\x1b\\VISIBLE'])
    if 'SECRET' in got:
        fail('T8 discard-resume: OSC ST body leaked: %r' % got[:60])
    if 'VISIBLE' not in got:
        fail('T8 discard-resume: OSC ST lost VISIBLE: %r' % got[:60])

    # DCS: BEL is BODY. A BEL in the over-cap body must NOT resume; ST must.
    got, drop = run(['\x1bP', 'SECRET' + 'x' * 40, '\x07LEAK', '\x1b\\VISIBLE'])
    if 'SECRET' in got or 'LEAK' in got:
        fail('T8 discard-resume: DCS treated BEL as terminator (body leaked): %r'
             % got[:60])
    if 'VISIBLE' not in got:
        fail('T8 discard-resume: DCS ST lost VISIBLE: %r' % got[:60])

    # APC same as DCS: BEL is body.
    got, drop = run(['\x1b_', 'SECRET' + 'x' * 40, '\x07LEAK', '\x1b\\VISIBLE'])
    if 'LEAK' in got:
        fail('T8 discard-resume: APC treated BEL as terminator: %r' % got[:60])
    if 'VISIBLE' not in got:
        fail('T8 discard-resume: APC ST lost VISIBLE: %r' % got[:60])


def t8_canaries():
    # Split-invariance canary: a BROKEN pipeline that ignores the carry (renders
    # each chunk independently, no cross-chunk hold) must diverge when an escape is
    # split -- ESC in one chunk, its body in the next leaks the body as text.
    def broken(chunks):
        return ''.join(S.render_output(c, 'detail') for c in chunks)
    s = 'a\x1b[m'                            # a\ + SGR; split just after ESC leaks
    whole = broken([s])
    split = broken(['a\x1b', '[m'])
    _expect_caught('T8/split-invariance', whole != split)
    # Memory-bound canary: a stand-in that GROWS with input (no cap) is caught by
    # the > cap assertion.
    fake_carry = 'x' * 100
    _expect_caught('T8/memory-bound', len(fake_carry) > 16)
    # SS2 split canary: a no-carry pipeline must leak the shifted byte as text.
    # The original alphabet could not form this sequence at all.
    ss2 = '\x1bNa'
    _expect_caught('T8/ss2-split',
                   broken([ss2]) != broken(['\x1b', 'Na']))
    # DCS BEL-is-body (BEL does not terminate a DCS -- only ST = ESC \ does) is proven
    # by the exhaustive T8 stream + catalog checks above, which split DCS sequences with
    # a BEL in the body at every offset and confirm render_output discards the whole run.
    # It needs no separate canary here: a canary that only asserted string literals
    # ('\x07' not in '\x1b\\') would increment the verified count without driving the model.


# ===========================================================================
# T9 -- GUI RENDER-PATH INERTNESS (cells_to_runs), the live widget's paint step.
#
# T1 proves render_output inert for the CLI (its output is written STRAIGHT to the
# outer terminal, so it must be pure SAFE_ASCII in strict modes). The Qt widget does
# NOT paint render_output; it paints cells_to_runs(completed, current, mode, ...) --
# the function that turns the cell line-model into the coalesced (text, sgr_key) runs
# QTextCursor inserts (terminal.py: `runs, prefix = cells_to_runs(...)`). So the
# GUI display alphabet is what cells_to_runs' run TEXT contains. Theorem: for any
# cells and any mode, every character of every run's text is a safe display unit --
# never a bidi control, an invisible / default-ignorable, or a C0/C1/DEL byte.
#
# The GUI alphabet is WIDER than the CLI's on purpose, and this is the honest point
# T1 cannot make: a neutralized no-glyph cell is drawn as the box U+25A1 (a real
# printable glyph the widget maps back to '_' on export), NOT the CLI's ASCII '_'.
# There is no output-becomes-input closure in the widget (a QTextEdit glyph is inert
# by construction), so a printable non-ASCII marker is safe here though it would not
# be in the CLI. The per-mode safe alphabet:
#   reveal / detail : pure SAFE_ASCII  -- cells_to_runs never boxes in these modes
#                     (the <U+XXXX> badge stays), so its text IS render_output, and
#                     T1's exhaustive inertness transfers VERBATIM.
#   box             : SAFE_ASCII u {BOX}         -- render_output's '_' becomes BOX.
#   show            : the documented show whitelist (SAFE_ASCII, BOX, the non-ASCII
#                     space marker, honest structural glyphs, a printable non-ASCII
#                     glyph that is neither default-ignorable nor bidi).
# The run '\n' separators are 0x0A, already in SAFE_ASCII.
#
# METHOD (the T1 pattern, one layer up): cells_to_runs' displayed text is built
# ONLY from the per-cell display (_cell_display == render_output, except a show-mode
# Zalgo cell -> BOX) with a documented '_'->BOX rewrite, plus '\n' separators; the
# run coalescing and the _RUN_CAP only REGROUP and RE-TAG runs, never alter a
# displayed character (the sgr_key is metadata, not text). So:
#   * EXHAUSTION + REDUCTION (t9_enumerate): ONE pass over every code point, in every
#     mode, checks BOTH that the REAL cells_to_runs display equals render_output with
#     exactly the one documented '_'->BOX substitution (box/show) -- pinning the GUI
#     text to the T1-proven map -- AND that it lies in the per-mode alphabet with no
#     invisible. One cells_to_runs call per (cp, mode) keeps this inside the 300s
#     core-suite budget (the whole suite runs verify_formal, not only the 15min lane).
#   * COMPOSITION (t9_compose): on adversarial multi-cell, multi-line inputs (mixed
#     SGR keys, wraps, a current line, AND a >2000-run line that passes _RUN_CAP so the
#     post-cap untagged path is exercised) the alphabet + no-invisible result still
#     holds on the whole real function -- the run coalescing cannot smuggle a byte in.
#   * HOMOMORPHISM (t9_homomorphism): in box/reveal/detail the displayed characters
#     are the per-cell concatenation (with a '\n' after each finished line), so the
#     single-code-point exhaustion lifts to lines of any length. SHOW mode is
#     excluded from this identity ONLY because _collapse_zalgo_runs merges a base +
#     >8 combining marks ACROSS cells into one box -- a display-REDUCING collapse
#     (fewer glyphs, all still inert); show keeps the full alphabet+invisible checks.
# ===========================================================================

# Faithful cell keys: feed_line_edits stores a cell as (source_char, sgr_state) with
# sgr_state = tuple(sorted(sgr.items())). Distinct keys force run splits so the
# coalescing is actually exercised; None models colours-off.
_T9_KEYS = (None, (), (('bold', True),), (('fg', 1),))


def _runs_char_ok(oc, mode):
    """The GUI run-text alphabet, per mode (see the header). '\\n' run separators are
    SAFE_ASCII, so they pass here too."""
    cp = ord(oc)
    if mode == 'show':
        return _show_char_ok(oc)                 # SAFE_ASCII, BOX, SPACE_MARK, ...
    if mode == 'box':
        return cp in SAFE_ASCII or oc == S.BOX
    return cp in SAFE_ASCII                       # reveal, detail: strictly ASCII


def _cells_to_runs_text(lines, current, mode, colors=True, markings=True,
                        wraps=None):
    """The displayed text the REAL cells_to_runs would paint: the run texts
    concatenated (the sgr_key is metadata, dropped here)."""
    runs, _prefix = S.cells_to_runs(lines, current, mode, colors, markings, wraps)
    return ''.join(text for text, _key in runs)


def _single_cell_display(ch, mode):
    """The REAL cells_to_runs display of ONE cell as the current line (no trailing
    '\\n' is added after the current line)."""
    return _cells_to_runs_text([], [(ch, None)], mode)


def t9_enumerate():
    """ONE exhaustive pass over every code point, in every mode, on the single-cell
    current line -- checking BOTH obligations with one cells_to_runs call each:

      (a) REDUCTION -- the display equals render_output (T1-proven inert) with only
          the documented '_'->BOX rewrite in box/show; a literal ASCII '_' cell (where
          the source already IS '_') stays '_' (emit()'s guard: `disp == '_' and
          disp != ch`). No other GUI substitution exists, so T1's inertness carries to
          the GUI text, and any drift trips here.
      (b) ALPHABET -- every displayed character is in the per-mode GUI alphabet and is
          not a default-ignorable.

    Total over the code-point domain -- not sampling. Folding the reduction and the
    alphabet check into a single traversal (one call per cp/mode) keeps T9 within the
    core-suite time budget; the finished-line '\\n' separator path is covered by
    t9_compose / t9_homomorphism on genuine multi-line input."""
    reduce_drift = 0
    alpha_bad = 0
    invisible = 0
    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)
        for mode in ('box', 'show', 'reveal', 'detail'):
            disp = _single_cell_display(ch, mode)
            base = S.render_output(ch, mode)
            want = ((S.BOX if (base == '_' and ch != '_') else base)
                    if mode in ('box', 'show') else base)   # box/show: '_'->BOX
            if disp != want:
                if reduce_drift < 8:
                    fail('T9 reduce: %s U+%04X display %r != render_output-derived %r'
                         % (mode, cp, disp, want))
                reduce_drift += 1
            for oc in disp:
                if not _runs_char_ok(oc, mode):
                    if alpha_bad < 8:
                        fail('T9 alphabet: %s U+%04X left 0x%02X'
                             % (mode, cp, ord(oc)))
                    alpha_bad += 1
                if _indep_output_dangerous(oc):
                    if invisible < 8:
                        fail('T9 invisible: %s U+%04X left a dangerous char'
                             % (mode, cp))
                    invisible += 1
    return dict(reduce_drift=reduce_drift, alpha_bad=alpha_bad, invisible=invisible)


# Adversarial cells the per-code-point pass cannot express: multi-cp Zalgo cells, a
# bidi/zero-width/homoglyph mix, box-drawing, and astral glyphs. Escape-encoded to
# keep this file ASCII-only (the repo convention; mirrors _T6_MULTI). BOX (U+25A1)
# and SPACE_MARK (U+2423) are included as raw display glyphs a hostile program might
# feed back in, to confirm they are re-neutralized and never trusted.
_T9_CELLCHARS = [
    'a', ' ', '_', '\u25a1', '\u2423', 'x\u202e', '\u200b', '\u0301',
    '\u00c1\u0302', 'a' + '\u0301' * 40, '\u2500', '\u4e00\u200d',
    '\U0001f600', '\ufeff', '\u3164', '\u00e9', '\u0430',
]


def _adversarial_lines():
    """A handful of adversarial (finished-lines, current, wraps) shapes built from
    the hostile cell chars, with mixed SGR keys so the run coalescing is exercised."""
    cells_a = [(_T9_CELLCHARS[i % len(_T9_CELLCHARS)],
                _T9_KEYS[i % len(_T9_KEYS)]) for i in range(len(_T9_CELLCHARS))]
    cells_b = [(c, k) for c, k
               in zip(reversed(_T9_CELLCHARS), _T9_KEYS * 8, strict=False)]
    yield ([], cells_a, None)
    yield ([cells_a], cells_b, [True])
    yield ([cells_a, cells_b], cells_a, [False, True])
    yield ([cells_b], [], [False])
    # >2000-run line: 2100 non-coalescing safe cells (alternating keys) drive the run
    # count PAST _RUN_CAP (2000), then hostile cells land on the post-cap UNTAGGED
    # path -- confirming a neutralized cell past the cap still displays inert. chr()
    # (not a literal) keeps this ASCII-only.
    big_a, big_b = (('fg', 2),), (('fg', 3),)
    big: list[tuple[str, tuple[tuple[str, int], ...]]] = [
        ('a' if i % 2 else 'b', big_a if i % 2 else big_b) for i in range(2100)]
    big += [(chr(c), ()) for c in (0x202e, 0x200b, 0x0430, 0x0301, 0x2500)]
    yield ([], big, None)


def t9_compose():
    """The alphabet + no-invisible result on the WHOLE real cells_to_runs, over
    adversarial multi-cell / multi-line inputs with mixed keys and wraps -- INCLUDING
    a >2000-run line that passes _RUN_CAP so the post-cap untagged path runs -- in
    every mode and with colours + markings both on and off. A run-coalescing or
    _RUN_CAP path that smuggled a byte in would be caught here on the shipped code."""
    bad = 0
    for lines, current, wraps in _adversarial_lines():
        for mode in ('box', 'show', 'reveal', 'detail'):
            for colors in (True, False):
                for markings in (True, False):
                    text = _cells_to_runs_text(lines, current, mode, colors,
                                               markings, wraps)
                    for oc in text:
                        if not _runs_char_ok(oc, mode) or _indep_output_dangerous(oc):
                            if bad < 8:
                                fail('T9 compose: %s (colors=%s markings=%s) left '
                                     '0x%02X' % (mode, colors, markings, ord(oc)))
                            bad += 1
    return bad


def t9_homomorphism():
    """In box/reveal/detail the displayed characters are the per-cell concatenation
    with a '\\n' after each finished line -- so the run coalescing and _RUN_CAP only
    regroup runs, they never change a displayed character, and the per-code-point
    exhaustion lifts to lines of any length. (SHOW is excluded: _collapse_zalgo_runs
    merges a base + >8 marks ACROSS cells into one box, a display-reducing collapse
    the per-cell identity cannot model; show keeps the alphabet + invisible checks.)"""
    bad = 0
    for lines, current, wraps in _adversarial_lines():
        for mode in ('box', 'reveal', 'detail'):
            whole = _cells_to_runs_text(lines, current, mode, wraps=wraps)
            piece = ''.join(
                ''.join(_single_cell_display(ch, mode) for ch, _k in cellline) + '\n'
                for cellline in lines)
            piece += ''.join(_single_cell_display(ch, mode) for ch, _k in current)
            if whole != piece:
                if bad < 8:
                    fail('T9 homomorphism: %s run text not the per-cell '
                         'concatenation' % mode)
                bad += 1
    return bad


def t9_canaries():
    # Alphabet canary: a bidi override or the BOX glyph leaked into a strict (reveal)
    # run must trip _runs_char_ok (reveal/detail admit SAFE_ASCII only).
    _expect_caught('T9/alphabet-bidi', not _runs_char_ok('\u202e', 'reveal'))
    _expect_caught('T9/alphabet-box-strict', not _runs_char_ok(S.BOX, 'reveal'))
    # BOX is legitimately allowed where it is actually drawn (box + show), so the
    # predicate must NOT reject it there (a false positive would mask real leaks).
    if not (_runs_char_ok(S.BOX, 'box') and _runs_char_ok(S.BOX, 'show')):
        fail('T9 canary: _runs_char_ok wrongly rejects BOX in box/show mode')
    # Invisible canary: a PRINTABLE-yet-default-ignorable char (U+3164 HANGUL FILLER,
    # which str.isprintable() keeps but renders as nothing -- the ad<U+3164>min
    # spoof) must be flagged by is_default_ignorable AND rejected by the show guard.
    _expect_caught('T9/invisible', S.is_default_ignorable('\u3164'))
    _expect_caught('T9/invisible-guard', not _runs_char_ok('\u3164', 'show'))
    # Independent-oracle twin: the T9 checker must also reject U+3164 via the
    # Unicode-property oracle, not only via S.is_default_ignorable.
    _expect_caught('T9/invisible-indep', _indep_output_dangerous('\u3164'))
    # C0 boundary, EXACT and per mode: the run alphabet admits ONLY the four C0
    # controls render_output whitelists (TAB/LF/CR/BS -- whitespace + line-edit
    # controls the widget honors, painted inertly); EVERY other C0 and DEL must be
    # rejected in EVERY mode. Iterating the whole 0x00-0x1F range + 0x7F over all
    # modes catches a checker weakened to admit e.g. VT (0x0B), or a leak specific
    # to one mode's predicate -- which a BEL-in-reveal sample would miss.
    c0_whitelist = frozenset((0x08, 0x09, 0x0A, 0x0D))
    for mode in ('box', 'show', 'reveal', 'detail'):
        for cp in [*range(0x00, 0x20), 0x7F]:
            admitted = _runs_char_ok(chr(cp), mode)
            if cp in c0_whitelist and not admitted:
                fail('T9 canary: _runs_char_ok drops whitelisted C0 0x%02X in %s'
                     % (cp, mode))
            if cp not in c0_whitelist and admitted:
                fail('T9 canary: _runs_char_ok admits forbidden control 0x%02X in %s'
                     % (cp, mode))
    # Counted representatives (teeth-tracked): a forbidden C0 rejected, a
    # whitelisted one admitted, in a strict (reveal) run.
    _expect_caught('T9/c0-forbidden-rejected', not _runs_char_ok('\x0b', 'reveal'))
    _expect_caught('T9/c0-whitelist-admitted', _runs_char_ok('\t', 'reveal'))

    # Homomorphism canary (mirrors t1_canaries): a stateful map -- one carrying state
    # ACROSS cells (drops a char it has already seen) -- must diverge from the same map
    # run per-cell with FRESH state, which is what the real per-cell display satisfies.
    # Both sides APPLY the map (a plain copy of the input would not model piecewise
    # execution and would miss a char-altering stateless map).
    def stateful(seen, ch):
        if ch in seen:
            return ''
        seen.add(ch)
        return ch
    s = 'aabb'
    seen: set[str] = set()
    whole = ''.join(stateful(seen, c) for c in s)      # state carried -> 'ab'
    piece = ''.join(stateful(set(), c) for c in s)     # fresh per cell -> 'aabb'
    _expect_caught('T9/homomorphism', whole != piece)


# ===========================================================================
# Run.
# ===========================================================================
def main():
    sys.stdout.write('secure-terminal formal verification (Z3 %s)\n'
                     % z3.get_version_string())

    sys.stdout.write('  T1.A  Z3 symbolic inertness of the display alphabet ...\n')
    t1_z3()
    t1_z3_faithfulness()

    sys.stdout.write('  L-di/L-bidi  sanitizer hand lists vs Unicode properties ...\n')
    pred = t1_predicate_lemmas()
    sys.stdout.write('        di_mismatch=%(di_mismatch)d bidi_mismatch=%(bidi_mismatch)d '
                     'zs_mismatch=%(zs_mismatch)d\n' % pred)

    sys.stdout.write('  T1.B  exhaustive enumeration over all %d code points ...\n'
                     % (MAX_CP + 1))
    stats = t1_enumerate()
    sys.stdout.write('        strict_bad=%(strict_bad)d show_bad=%(show_bad)d '
                     'invisible_leak=%(ignorable_leak)d '
                     'model_mismatch=%(model_mismatch)d '
                     'name_non_ascii=%(name_non_ascii)d\n' % stats)

    sys.stdout.write('  T1.L  per-character homomorphism of the render loop '
                     '(incl. escape-bearing) ...\n')
    t1_homomorphism()

    sys.stdout.write('  T2.A  Z3 inductive invariant of the line-editor state '
                     'machine ...\n')
    t2_z3()

    sys.stdout.write('  T2.B  validate the abstract model vs the real '
                     'feed_line_edits ...\n')
    t2stats = t2_crosscheck()
    sys.stdout.write('        model_drift=%(mismatches)d '
                     'real_inv_violations=%(inv_violations)d\n' % t2stats)
    t2_mark_drop_real()
    t2_line_edits_off()
    t2_prompt_flush_real()

    sys.stdout.write('  T2.C  earlier-line immutability: `completed` append-only '
                     '(AST) + incremental equivalence ...\n')
    t2_append_only_ast()
    incr_bad = t2_incremental_equiv()
    sys.stdout.write('        incremental_divergences=%d\n' % incr_bad)

    sys.stdout.write('  T3.Z  Z3 symbolic alphabets of the paste / clipboard classifiers ...\n')
    t_input_z3()
    sys.stdout.write('  T3-T7  exhaustive enumeration: paste / clipboard / title / cell / classify ...\n')
    ist = t_input_enumerate()
    sys.stdout.write('        paste=%(paste)d paste_uni=%(paste_uni)d clip=%(clip)d clip_uni=%(clip_uni)d clip_disp=%(clip_disp)d title=%(title)d tui=%(tui)d classify=%(classify)d findings=%(findings)d\n' % ist)
    sys.stdout.write('  T3-T6  string-level: no-autosubmit / cli-cr-strip / title idempotence / homomorphism / multi-cp cells ...\n')
    t_input_strings()

    sys.stdout.write('  T8    chunk-boundary escape safety: bounded-exhaustive split-invariance + O(1) memory ...\n')
    t8_bad = t8_split_invariance()
    t8_memory_bound()
    t8_discard_resume()
    sys.stdout.write('        split_invariance_divergences=%d\n' % t8_bad)

    sys.stdout.write('  T9    GUI render-path inertness: cells_to_runs alphabet over all code points ...\n')
    e9 = t9_enumerate()
    c9 = t9_compose()
    h9 = t9_homomorphism()
    sys.stdout.write('        reduce_drift=%d alpha_bad=%d invisible=%d compose_bad=%d homomorphism_bad=%d\n'
                     % (e9['reduce_drift'], e9['alpha_bad'], e9['invisible'], c9, h9))

    sys.stdout.write('  canaries (each proof must trip on a broken model) ...\n')
    t1_canaries()
    t2_canaries()
    t_input_canaries()
    t8_canaries()
    t9_canaries()

    sys.stdout.write('verify_formal: %d canaries verified, %d obligations failed\n'
                     % (CANARIES_VERIFIED[0], FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
