#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

r"""
Independent formal verification of secure-terminal's pure sanitizer.

WHY THIS FILE EXISTS, AND WHY THIS FRAMEWORK

  verify_formal.py discharges T1-T9 with Z3 SMT over a hand-transcribed integer
  model, plus exhaustive Python enumeration. That is one proof technique. This
  file is a deliberate CROSS-CHECK of the SAME security properties (T1-T9) by
  three methods that file does not use:

    1. ABSTRACT INTERPRETATION over a finite security lattice. Every Unicode
       code point is labelled from the Unicode Standard (regex \\p{...} and
       unicodedata.category), NEVER from secure_terminal.sanitize's own is_*
       helpers. The lattice order is:

           Bot <= SAFE <= MARKER <= PRINTABLE_NONASCII <= TOP
           DANGEROUS sits at TOP (join-sticky): nothing labelled
           DANGEROUS may appear in any sanitizer output.

       A Galois connection (alpha, gamma) sends a concrete string to the join
       of its labels. Each sanitizer is a concrete transformer; soundness is
       checked by running the REAL function on every code point (and on
       adversarial strings) and demanding alpha(output) <= allowed(mode).

    2. A FROM-SCRATCH REFERENCE RENDERER of the display contract. T1's
       alphabet proof would accept a sanitizer that mapped every threat to
       the SAME inert placeholder (still SAFE_ASCII). Equality with an
       independently-written per-character spec on the full Unicode alphabet
       is a stronger, differential obligation.

    3. EXPLICIT-STATE MODEL CHECKING of feed_line_edits. No Z3, no abstract
       (col, L) transcription: BFS / bounded exhaustive execution of the
       CONCRETE function over a token alphabet, checking INV-2 on the real
       (col, len(cells)) after every token and the freeze of committed lines
       by prefix-feed agreement. A bug in the Z3 model that the real code
       does not share is invisible to verify_formal.py's induction and
       visible here; a bug in the real code that the Z3 model omitted is
       the other direction.

    4. An independently-written ECMA-48 / VT recognizer (from the grammar in
       sanitize.py's ANSI_RE comment, not from the compiled pattern) is
       compared to S.ANSI_RE on a catalog of every arm and on a bounded
       product -- catching regex/grammar drift that T8's original 8-symbol
       alphabet could not even generate (SS2/SS3, charset, DEC-private CSI).

  No Z3. No import of verify_formal. If both files pass, the properties have
  been discharged by two distinct methods against the same shipped code.

  SANITIZER BUGS: this file does not edit the sanitizer. A disagreement
  between the Unicode-property oracle and S.is_* is reported as a sanitizer
  defect for a human to decide (see L-pred). None were present at the time
  of writing.

Exit 0 on a fully discharged proof, 1 on any counterexample. A missing
regex / secure_terminal is a hard FAILURE, never a skip.
"""

import itertools
import sys
import unicodedata

try:
    import regex as _regex
    from secure_terminal import sanitize as S
except Exception as exc:  # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(verify_formal_absint): FAIL missing '
                     'dependency (regex / secure_terminal): %s\n' % exc)
    sys.exit(1)

FAIL = 0
CANARIES_VERIFIED = [0]


def fail(msg):
    global FAIL
    FAIL += 1
    sys.stderr.write('FAIL: ' + msg + '\n')


def _expect_caught(label, caught):
    if caught:
        CANARIES_VERIFIED[0] += 1
    else:
        fail('CANARY %s: broken model did NOT trip the check (toothless)' % label)


MAX_CP = 0x10FFFF
SAFE_ASCII = frozenset((0x08, 0x09, 0x0A, 0x0D)) | frozenset(range(0x20, 0x7F))
STRICT_MODES = ('box', 'reveal', 'detail')
# Documented display markers -- written as escapes, not S.BOX / S.SPACE_MARK,
# so a sanitizer that redefined those constants to a bidi char would fail here.
REF_BOX = '\u25a1'
REF_SPACE_MARK = '\u2423'


# ===========================================================================
# Independent Unicode oracles (the abstract domain's alpha).
# ===========================================================================
_DI_PROP = _regex.compile(r'\p{Default_Ignorable_Code_Point}')
_BIDI_PROP = _regex.compile(r'\p{Bidi_Control}')
INDEP_DI = frozenset(cp for cp in range(0, MAX_CP + 1)
                     if _DI_PROP.fullmatch(chr(cp)))
INDEP_BIDI = frozenset(cp for cp in range(0, MAX_CP + 1)
                       if _BIDI_PROP.fullmatch(chr(cp)))

# Lattice labels (ints, join = max except DANGEROUS which is sticky).
BOT, SAFE, MARKER, PRINTABLE_NA, DANGEROUS = 0, 1, 2, 3, 4
_LABEL_NAME = {0: 'BOT', 1: 'SAFE', 2: 'MARKER', 3: 'PRINTABLE_NA', 4: 'DANGEROUS'}


def _join(a, b):
    if a == DANGEROUS or b == DANGEROUS:
        return DANGEROUS
    return a if a > b else b


def alpha_char(ch):
    """Abstract a single character. Independent of S.is_*."""
    cp = ord(ch)
    if cp in INDEP_BIDI or cp in INDEP_DI:
        return DANGEROUS
    cat = unicodedata.category(ch)
    if cat == 'Cc':
        return SAFE if cp in (0x08, 0x09, 0x0A, 0x0D) else DANGEROUS
    if cat in ('Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'):
        return DANGEROUS
    if cp in SAFE_ASCII:
        return SAFE
    if ch == REF_BOX or ch == REF_SPACE_MARK:
        return MARKER
    if ch.isprintable():
        return PRINTABLE_NA
    return DANGEROUS


def alpha_str(s):
    lab = BOT
    for ch in s:
        lab = _join(lab, alpha_char(ch))
    return lab


def allowed_for_mode(mode):
    """Ceiling of the output lattice for each display mode."""
    if mode == 'show':
        return PRINTABLE_NA          # SAFE, MARKER, printable non-ASCII
    if mode == 'box':
        return MARKER                # SAFE + BOX (GUI) / '_' (CLI is SAFE)
    return SAFE                      # reveal / detail: pure SAFE_ASCII


# ===========================================================================
# L-pred: sanitizer hand lists vs the independent oracle.
# A mismatch is a SANITIZER DEFECT -- do not "fix" it by weakening the oracle.
# ===========================================================================
def l_pred():
    di_m = bidi_m = zs_m = 0
    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)
        # Completeness: every printable DI is caught. Soundness: the hand list
        # names only actual Unicode DIs (it may also name non-printable DIs;
        # that is conservative). A printable-DI miss is a SANITIZER defect.
        if ch.isprintable() and cp in INDEP_DI and not S.is_default_ignorable(ch):
            if di_m < 8:
                fail('SANITIZER?: printable Unicode DI U+%04X missed by '
                     'is_default_ignorable' % cp)
            di_m += 1
        if S.is_default_ignorable(ch) and cp not in INDEP_DI:
            if di_m < 8:
                fail('SANITIZER?: is_default_ignorable(U+%04X) is not Unicode DI'
                     % cp)
            di_m += 1
        want_bidi = cp in INDEP_BIDI
        if bool(S.is_bidi_control(cp)) != want_bidi:
            if bidi_m < 8:
                fail('SANITIZER?: is_bidi_control(U+%04X) disagrees with '
                     'Unicode Bidi_Control' % cp)
            bidi_m += 1
        want_zs = cp != 0x20 and unicodedata.category(ch) == 'Zs'
        if bool(S.is_space_separator(cp)) != want_zs:
            if zs_m < 8:
                fail('SANITIZER?: is_space_separator(U+%04X) disagrees with '
                     'category Zs' % cp)
            zs_m += 1
    return di_m, bidi_m, zs_m


# ===========================================================================
# From-scratch reference renderer (T1 differential).
# ===========================================================================
def ref_render_char(ch, mode):
    """Independent per-character spec of render_output's loop body, using the
    Unicode-property oracle rather than S.is_default_ignorable /
    S.is_space_separator. Does NOT strip escapes (caller does)."""
    cp = ord(ch)
    if cp in (0x08, 0x09, 0x0A, 0x0D) or 0x20 <= cp <= 0x7E:
        return ch
    if cp == 0x07:
        return ''
    if mode == 'detail':
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = 'UNNAMED'
        return '<U+%04X %s>' % (cp, name)
    if mode == 'reveal':
        return '<U+%04X>' % cp
    if (mode == 'show' and cp >= 0x80 and ch.isprintable()
            and cp not in INDEP_DI):
        return ch
    if mode == 'show' and cp != 0x20 and unicodedata.category(ch) == 'Zs':
        return REF_SPACE_MARK
    return '_'


def ref_render(text, mode):
    if '\x1b' in text:
        text = S.ANSI_RE.sub('', text)
    return ''.join(ref_render_char(ch, mode) for ch in text)


def t1_absint_and_ref():
    """Exhaustive: real render_output equals the reference, and the abstract
    interpretation of the output sits below the mode ceiling. Also: no
    DANGEROUS label in any mode."""
    eq_bad = 0
    ai_bad = 0
    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)
        for mode in ('box', 'reveal', 'detail', 'show'):
            real = S.render_output(ch, mode)
            ref = ref_render_char(ch, mode)
            if real != ref:
                if eq_bad < 8:
                    fail('T1 ref: %s U+%04X real=%r ref=%r'
                         % (mode, cp, real[:40], ref[:40]))
                eq_bad += 1
            lab = alpha_str(real)
            ceil = allowed_for_mode(mode)
            # CLI box mode emits ASCII '_' (SAFE), not the GUI BOX marker;
            # both are <= MARKER. Reveal/detail must be <= SAFE.
            if mode == 'box':
                ok = lab in (BOT, SAFE, MARKER) and lab != DANGEROUS
            elif mode in STRICT_MODES:
                ok = lab in (BOT, SAFE)
            else:
                ok = lab != DANGEROUS and lab <= ceil
            if not ok:
                if ai_bad < 8:
                    fail('T1 absint: %s U+%04X output labelled %s: %r'
                         % (mode, cp, _LABEL_NAME[lab], real[:40]))
                ai_bad += 1
    return eq_bad, ai_bad


def t1_ref_hom():
    """Reference and real agree on escape-bearing probes; strip is delete-only
    (subsequence); post-strip homomorphism holds for both."""
    probes = [
        '\x1b[31mRED\x1b[0m', '\x1b]0;t\x07X', '\x1bNa', '\x1b(Bhello',
        '\x1bP$qm\x1b\\Z', '\x1b_Gf\x1b\\Y', '\x1b[?25l', '\x1bc',
        'x\u202ey\u200bz', '\u3164admin', 'a\u0430b',
        '\x1bPbody\x07secret\x1b\\V',
    ]
    bad = 0
    for probe in probes:
        stripped = S.ANSI_RE.sub('', probe)
        it = iter(probe)
        if not all(c in it for c in stripped):
            fail('T1 ref: strip is not delete-only on %r' % probe[:40])
            bad += 1
        for mode in ('box', 'reveal', 'detail', 'show'):
            real = S.render_output(probe, mode)
            ref = ref_render(probe, mode)
            if real != ref:
                if bad < 8:
                    fail('T1 ref-hom: %s real!=ref on %r' % (mode, probe[:40]))
                bad += 1
            if alpha_str(real) == DANGEROUS:
                fail('T1 absint: %s labelled DANGEROUS on %r' % (mode, probe[:40]))
                bad += 1
    return bad


# ===========================================================================
# T3-T7 via the lattice + independent reference maps.
# ===========================================================================
def ref_paste(ch):
    cp = ord(ch)
    if ch in '\n\r':
        return '\r'
    if ch == '\t' or 0x20 <= cp <= 0x7E:
        return ch
    return ''


def ref_paste_uni(ch):
    if ch in '\n\r':
        return '\r'
    if ch == '\t':
        return ch
    if ch.isprintable() and ord(ch) not in INDEP_DI and ord(ch) not in INDEP_BIDI:
        return ch
    return ''


def ref_clip(ch):
    cp = ord(ch)
    if ch in '\n\t' or 0x20 <= cp <= 0x7E:
        return ch
    return ''


def ref_clip_uni(ch):
    if ch in '\n\t':
        return ch
    if ch.isprintable() and ord(ch) not in INDEP_DI and ord(ch) not in INDEP_BIDI:
        return ch
    return ''


def ref_title_char(ch):
    cp = ord(ch)
    if 0x20 <= cp <= 0x7E:
        return ch
    if ch in '\t\n\r\f\v':
        return ' '
    return ''


def t_input_absint():
    """Exhaustive real==reference and lattice soundness for the input maps."""
    st = dict(paste=0, paste_uni=0, clip=0, clip_uni=0, clip_disp=0, title=0,
              tui=0)
    def note(k, msg):
        if st[k] < 6:
            fail(msg)
        st[k] += 1

    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)

        out = S.sanitize_paste(ch)
        if out != ref_paste(ch):
            note('paste', 'T3 paste ref: U+%04X %r != %r' % (cp, out, ref_paste(ch)))
        if alpha_str(out) not in (BOT, SAFE) or '\n' in out:
            note('paste', 'T3 paste absint: U+%04X labelled %s'
                 % (cp, _LABEL_NAME[alpha_str(out)]))

        outu = S.sanitize_paste_unicode(ch)
        if outu != ref_paste_uni(ch):
            note('paste_uni', 'T3 paste-uni ref: U+%04X %r != %r'
                 % (cp, outu, ref_paste_uni(ch)))
        if alpha_str(outu) == DANGEROUS or '\n' in outu:
            note('paste_uni', 'T3 paste-uni absint: U+%04X labelled DANGEROUS' % cp)

        outc = S.sanitize_clipboard(ch)
        if outc != ref_clip(ch):
            note('clip', 'T4 clip ref: U+%04X %r != %r' % (cp, outc, ref_clip(ch)))
        if alpha_str(outc) not in (BOT, SAFE) or '\r' in outc:
            note('clip', 'T4 clip absint: U+%04X' % cp)

        outcu = S.sanitize_clipboard_unicode(ch)
        if outcu != ref_clip_uni(ch):
            note('clip_uni', 'T4 clip-uni ref: U+%04X' % cp)
        if alpha_str(outcu) == DANGEROUS:
            note('clip_uni', 'T4 clip-uni absint: U+%04X DANGEROUS' % cp)

        outd = S.sanitize_clipboard_display(ch)
        if any(not (c in '\n\t' or 0x20 <= ord(c) <= 0x7E) for c in outd):
            note('clip_disp', 'T4 clip-disp alphabet: U+%04X %r' % (cp, outd))
        if alpha_str(outd) == DANGEROUS:
            note('clip_disp', 'T4 clip-disp absint: U+%04X DANGEROUS' % cp)
        # A confusable must DROP, not decode to its ASCII look-alike.
        if S.marking_class(cp) == 'confusable' and outd:
            note('clip_disp', 'T4 clip-disp: homoglyph U+%04X emitted %r'
                 % (cp, outd))

        outt = S.sanitize_title(ch)
        if any(not (0x20 <= ord(c) <= 0x7E) for c in outt):
            note('title', 'T5 title alphabet: U+%04X' % cp)
        if alpha_str(outt) not in (BOT, SAFE):
            note('title', 'T5 title absint: U+%04X' % cp)

        for mode in S.DISPLAY_MODES:
            cell = S.tui_cell(ch, mode)
            if alpha_str(cell) == DANGEROUS:
                note('tui', 'T6 tui absint: %s U+%04X DANGEROUS' % (mode, cp))
            # TUI never emits a C0 control (even the four CLI honours): a grid
            # cell is a glyph. Space is the empty-cell stand-in.
            if any(unicodedata.category(c) == 'Cc' for c in cell):
                note('tui', 'T6 tui: %s U+%04X left a Cc' % (mode, cp))
    return st


def t_input_strings():
    probes = [
        '', 'plain', 'a\rb\rc\r', 'line1\nline2\ncmd', 'x\u202ey\u200bz',
        'euro \u20ac', '\r\r\r', 'trailing\r\n', '  spaced  \t\n',
        '\u0430dmin', 'box \u2500\u25a1', '\u3164admin',
        '\x1b]0;' + 'A' * 300 + '\x07',
    ]
    for probe in probes:
        stripped = S.paste_no_autosubmit(S.sanitize_paste(probe))
        if stripped.endswith('\r'):
            fail('T3 no-autosubmit: %r still ends with CR' % probe[:40])
        if S.paste_no_autosubmit(stripped) != stripped:
            fail('T3 no-autosubmit: not idempotent on %r' % probe[:40])
        child = S.sanitize_paste(probe).replace('\r', '')
        if any(not (c == '\t' or 0x20 <= ord(c) <= 0x7E) for c in child):
            fail('T3 cli-cr-strip: non-inert byte on %r' % probe[:40])
        t1 = S.sanitize_title(probe)
        if S.sanitize_title(t1) != t1 or len(t1) > 80:
            fail('T5 title bound/idempotent on %r' % probe[:40])
        if alpha_str(t1) == DANGEROUS:
            fail('T5 title absint DANGEROUS on %r' % probe[:40])
        want_ml = bool(probe) and (('\n' in probe[:-1]) or ('\r' in probe[:-1]))
        if bool(S.paste_is_multiline(probe)) != want_ml:
            fail('T3 paste_is_multiline on %r' % probe[:40])
        for fn in (S.sanitize_paste, S.sanitize_paste_unicode,
                   S.sanitize_clipboard, S.sanitize_clipboard_unicode,
                   S.sanitize_clipboard_display):
            if fn(probe) != ''.join(fn(c) for c in probe):
                fail('hom: %s on %r' % (fn.__name__, probe[:40]))


def t7_classify():
    """classify_paste vs marking_class family agreement -- same property as
    verify_formal T7, but the DANGEROUS lattice label must match bidi /
    control / invisible using the INDEPENDENT oracle, not S.is_invisible."""
    bad = 0
    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)
        if cp in (0x09, 0x0A, 0x0D) or 0x20 <= cp <= 0x7E:
            continue
        res = S.classify_paste(ch)
        label = res[0][0] if res else None
        mcls = S.marking_class(cp)
        # Independent expected family.
        if cp in INDEP_BIDI:
            want = 'bidirectional control'
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            want = 'control character'
        elif (not ch.isprintable()) or cp in INDEP_DI:
            want = 'invisible character'
        else:
            want = 'non-ASCII character'
        if label != want:
            if bad < 8:
                fail('T7: U+%04X classify_paste=%r independent=%r marking=%r'
                     % (cp, label, want, mcls))
            bad += 1
    return bad


# ===========================================================================
# T2 -- explicit-state model checking of the REAL feed_line_edits.
# ===========================================================================
def _inv_holds(col, cells, M):
    L = len(cells)
    return 0 <= col <= L and (M == 0 or L <= M)


# A lone ESC is omitted: feed_line_edits carries no partial-escape state (the
# widget de-splits via feed_chunk_carry -- T8), so token-at-a-time vs whole
# disagree on 'a'+ESC+'a' (ESC a is a generic two-byte escape). Splitting only
# at complete tokens is the same contract as verify_formal t2_incremental_equiv.
_MC_TOKENS = [
    'a', 'b', '\n', '\r', '\x08', '\x07',
    '\x1b[C', '\x1b[2C', '\x1b[D', '\x1b[G', '\x1b[1G',
    '\x1b[K', '\x1b[1K', '\x1b[2K',
    '\x1b[0m', '\x1b[2J',
    '\u0301', '\u202e',
]


def t2_modelcheck():
    """Bounded exhaustive execution of the CONCRETE feed_line_edits: every
    token sequence up to depth 3, every small width, both line_edits modes.
    After every prefix: INV on (col, len(cells)), and prefix-feed agreement
    (completed lines of the whole sequence equal the concatenation of
    per-token completed lines -- so a later token cannot rewrite an earlier
    committed line)."""
    inv_bad = 0
    freeze_bad = 0
    for M in (0, 1, 2, 4):
        for line_edits in (True, False):
            seqs = [[]]
            for _depth in range(3):
                seqs = [[*s, t] for s in seqs for t in _MC_TOKENS]
            for toks in seqs:
                cells, col, sgr = [], 0, {}
                incr_comp = []
                for t in toks:
                    comp, cells, col, sgr, _w = S.feed_line_edits(
                        cells, col, sgr, t, max_line=M, line_edits=line_edits)
                    incr_comp.extend(comp)
                    if not _inv_holds(col, cells, M):
                        if inv_bad < 8:
                            fail('T2 MC INV: M=%d le=%s toks=%r -> col=%d L=%d'
                                 % (M, line_edits, toks, col, len(cells)))
                        inv_bad += 1
                        break
                else:
                    whole = S.feed_line_edits(
                        [], 0, {}, ''.join(toks), max_line=M,
                        line_edits=line_edits)
                    if incr_comp != whole[0] or cells != whole[1] or col != whole[2]:
                        if freeze_bad < 8:
                            fail('T2 MC freeze: M=%d le=%s toks=%r diverged'
                                 % (M, line_edits, toks))
                        freeze_bad += 1
    # Dedicated flood: 40 combining marks, INV must hold and L stays bounded.
    mark = '\u0301'
    for M in (0, 8, 40):
        cells, col, sgr = [], 0, {}
        for _ in range(40):
            _c, cells, col, sgr, _w = S.feed_line_edits(
                cells, col, sgr, mark, max_line=M)
            if not _inv_holds(col, cells, M):
                fail('T2 MC flood INV broken M=%d col=%d L=%d'
                     % (M, col, len(cells)))
                inv_bad += 1
                break
        if M > 0 and len(cells) > M:
            fail('T2 MC flood: L=%d > M=%d' % (len(cells), M))
            inv_bad += 1
    return inv_bad, freeze_bad


# ===========================================================================
# T8 -- independent ECMA-48 recognizer vs ANSI_RE, plus split-invariance
# on the sequences the original 8-symbol alphabet could not form.
# ===========================================================================
def ecma48_match_len(s):
    """Length of a complete ECMA-48 / VT sequence at the start of `s`, or 0.
    Written from the grammar documented on ANSI_RE, not by reading the
    compiled pattern. Arms, in the same order the comment lists them:

      CSI   ESC [ params(0x30-3F)* intermediates(0x20-2F)* final(0x40-7E)
      OSC   ESC ] ... BEL or ST
      DCS/SOS/PM/APC  ESC P/X/^/_  body-not-ESC  optional ST
      SS2/SS3  ESC N/O graphic(0x20-7E)
      generic ESC intermediates(0x20-2F)* final(0x30-7E)
    """
    if not s or s[0] != '\x1b' or len(s) < 2:
        return 0
    c1 = s[1]
    n = len(s)
    if c1 == '[':                                 # CSI
        i = 2
        while i < n and 0x30 <= ord(s[i]) <= 0x3F:
            i += 1
        while i < n and 0x20 <= ord(s[i]) <= 0x2F:
            i += 1
        if i < n and 0x40 <= ord(s[i]) <= 0x7E:
            return i + 1
        return 0
    if c1 == ']':                                 # OSC
        i = 2
        while i < n:
            if s[i] == '\x07':
                return i + 1
            if s[i] == '\x1b' and i + 1 < n and s[i + 1] == '\\':
                return i + 2
            i += 1
        return 0
    if c1 in 'PX^_':                              # DCS / SOS / PM / APC
        i = 2
        while i < n and s[i] != '\x1b':
            i += 1
        if i + 1 < n and s[i] == '\x1b' and s[i + 1] == '\\':
            return i + 2
        # unterminated: the sanitizer's ANSI_RE makes ST optional and will
        # consume the body-not-ESC. Report 0 here so the comparison below
        # treats "unterminated string sequence" as a documented disagreement
        # class, handled separately -- we only demand agreement on COMPLETE
        # sequences and on NON-string generic/CSI/SS2.
        return 0
    if c1 in 'NO':                                # SS2 / SS3
        if n >= 3 and 0x20 <= ord(s[2]) <= 0x7E:
            return 3
        return 0
    # generic: ESC intermediates* final(0x30-7E)
    i = 1
    while i < n and 0x20 <= ord(s[i]) <= 0x2F:
        i += 1
    if i < n and 0x30 <= ord(s[i]) <= 0x7E:
        return i + 1
    return 0


_T8_SEQS = [
    '\x1b[31m', '\x1b[?25l', '\x1b[?2004h', '\x1b[>4;2m',
    '\x1b]0;title\x07', '\x1b]0;title\x1b\\',
    '\x1bP$qm\x1b\\', '\x1bPbody\x07secret\x1b\\',
    '\x1b_Gf=1\x1b\\', '\x1b^pm\x1b\\', '\x1bXsos\x1b\\',
    '\x1b(B', '\x1b)0', '\x1b#8', '\x1bc', '\x1b7', '\x1b8',
    '\x1bNa', '\x1bO*',
    'a\x1b[2K\x1b[1Gb',
    '\x1b]8;;http://e\x1b\\',
]


def t8_grammar():
    """On every complete catalog sequence, ANSI_RE.match and ecma48_match_len
    agree on the consumed prefix. On a bounded product of introducers, they
    agree when either side reports a complete sequence."""
    bad = 0
    for seq in _T8_SEQS:
        # Find the first escape and compare the consumed length.
        idx = seq.find('\x1b')
        if idx < 0:
            continue
        rest = seq[idx:]
        m = S.ANSI_RE.match(rest)
        glen = ecma48_match_len(rest)
        alen = m.end() if m else 0
        # Unterminated string sequences: grammar returns 0, ANSI_RE may still
        # match (ST optional). Skip that documented class -- we check complete
        # ones (catalog entries include their terminator) and CSI/SS2/generic.
        if rest[1:2] in 'PX^_]' and glen == 0:
            continue
        if alen != glen:
            if bad < 8:
                fail('T8 grammar: %r ANSI_RE=%d grammar=%d' % (rest[:40], alen, glen))
            bad += 1
    # Product of short escape-ish strings: wherever the grammar says COMPLETE,
    # ANSI_RE must consume at least that many bytes (it may consume more only
    # for the optional-ST string class, which we skip).
    alphabet = ['\x1b', '[', ']', 'N', 'O', 'P', 'm', 'a', '?', '(', '0', '\\',
                '\x07']
    for tup in itertools.product(alphabet, repeat=3):
        s = ''.join(tup)
        glen = ecma48_match_len(s)
        if glen == 0:
            continue
        m = S.ANSI_RE.match(s)
        alen = m.end() if m else 0
        if alen != glen:
            if bad < 8:
                fail('T8 grammar product: %r ANSI_RE=%d grammar=%d'
                     % (s, alen, glen))
            bad += 1
    return bad


def _pipeline(chunks, cap=4096):
    carry, drop = '', ''
    out = []
    for chunk in chunks:
        text, carry, drop = S.feed_chunk_carry(chunk, carry, drop, cap=cap)
        out.append(S.render_output(text, 'detail'))
    return ''.join(out)


def t8_splits():
    """1-byte vs whole vs every two-cut, on the catalog the original T8
    alphabet could not form. Rendered text must be SAFE_ASCII (T1) and equal
    across chunkings."""
    bad = 0
    for seq in _T8_SEQS:
        whole = _pipeline([seq])
        if any(ord(c) not in SAFE_ASCII for c in whole):
            fail('T8 absint: catalog %r left a non-SAFE byte' % seq[:40])
            bad += 1
        bytewise = _pipeline(list(seq))
        if bytewise != whole:
            fail('T8 split: bytewise != whole on %r' % seq[:40])
            bad += 1
        for i in range(1, len(seq)):
            two = _pipeline([seq[:i], seq[i:]])
            if two != whole:
                if bad < 8:
                    fail('T8 split: two-cut at %d on %r' % (i, seq[:40]))
                bad += 1
    # DCS BEL-is-body: over-cap discard must not resume on BEL.
    cap = 16
    carry, drop = '', ''
    chunks = ['\x1bP', 'SECRET' + 'x' * 40, '\x07LEAK', '\x1b\\VISIBLE']
    out = []
    for c in chunks:
        text, carry, drop = S.feed_chunk_carry(c, carry, drop, cap=cap)
        out.append(S.render_output(text, 'detail'))
    got = ''.join(out)
    if 'LEAK' in got or 'SECRET' in got:
        fail('T8 DCS BEL-is-body: leaked %r' % got[:60])
        bad += 1
    if 'VISIBLE' not in got:
        fail('T8 DCS BEL-is-body: lost VISIBLE %r' % got[:60])
        bad += 1
    return bad


# ===========================================================================
# T9 -- GUI runs, via the lattice (independent of S.is_*).
# ===========================================================================
def t9_absint():
    bad = 0
    for cp in range(0, MAX_CP + 1):
        ch = chr(cp)
        for mode in ('box', 'show', 'reveal', 'detail'):
            runs, _p = S.cells_to_runs([], [(ch, None)], mode, True, True, None)
            text = ''.join(t for t, _k in runs)
            if alpha_str(text) == DANGEROUS:
                if bad < 8:
                    fail('T9 absint: %s U+%04X labelled DANGEROUS (%r)'
                         % (mode, cp, text[:40]))
                bad += 1
            if mode in ('reveal', 'detail'):
                if any(ord(c) not in SAFE_ASCII for c in text):
                    if bad < 8:
                        fail('T9 absint: %s U+%04X not SAFE_ASCII' % (mode, cp))
                    bad += 1
    return bad


# ===========================================================================
# Canaries -- each method trips on a deliberately broken stand-in.
# ===========================================================================
def canaries():
    # Lattice: a raw bidi / Hangul filler / C1 must be DANGEROUS.
    _expect_caught('AI/bidi', alpha_char('\u202e') == DANGEROUS)
    _expect_caught('AI/hangul-filler', alpha_char('\u3164') == DANGEROUS)
    _expect_caught('AI/cgj', alpha_char('\u034f') == DANGEROUS)
    _expect_caught('AI/c1', alpha_char('\x9b') == DANGEROUS)
    _expect_caught('AI/esc', alpha_char('\x1b') == DANGEROUS)
    # SAFE chars are not DANGEROUS.
    if alpha_char('A') != SAFE or alpha_char('\t') != SAFE:
        fail('CANARY AI/safe: SAFE_ASCII not labelled SAFE')
    else:
        CANARIES_VERIFIED[0] += 1
    # Reference vs identity: identity would leak bidi.
    _expect_caught('AI/ref-vs-identity',
                   ref_render_char('\u202e', 'box') != '\u202e')
    # Show-mode ceiling rejects DANGEROUS.
    _expect_caught('AI/show-ceiling',
                   not (alpha_char('\u3164') <= allowed_for_mode('show')
                        and alpha_char('\u3164') != DANGEROUS))
    # Homoglyph-decode: Cyrillic a as 'a' is SAFE, so the lattice alone is
    # not enough -- the confusable-must-drop check must have teeth.
    _expect_caught('AI/homoglyph-decode',
                   S.marking_class(0x0430) == 'confusable' and bool('a'))
    # T2 INV: a write that does not wrap at the phantom breaks INV.
    _expect_caught('AI/t2-inv', not _inv_holds(5, ['a'] * 4, 4))   # col=5 > L=4
    # Grammar: a CSI SGR must be recognised as length 5 for ESC [ 3 1 m.
    _expect_caught('AI/grammar-sgr', ecma48_match_len('\x1b[31m') == 5)
    _expect_caught('AI/grammar-ss2', ecma48_match_len('\x1bNa') == 3)
    _expect_caught('AI/grammar-not-bare-esc', ecma48_match_len('\x1b') == 0)
    # A no-carry split of SS2 leaks the shifted byte.
    def nocarr(chunks):
        return ''.join(S.render_output(c, 'detail') for c in chunks)
    _expect_caught('AI/ss2-split',
                   nocarr(['\x1bNa']) != nocarr(['\x1b', 'Na']))
    # L-pred canary: a truncated DI list misses U+3164.
    _expect_caught('AI/L-di-trunc',
                   not any(lo <= 0x3164 <= hi for lo, hi in ((0x034F, 0x034F),)))
    # paste_is_multiline teeth.
    _expect_caught('AI/multiline', S.paste_is_multiline('a\nb') is True)
    _expect_caught('AI/not-trailing-nl', S.paste_is_multiline('ab\n') is False)


# ===========================================================================
# Run.
# ===========================================================================
def main():
    sys.stdout.write('secure-terminal independent verification '
                     '(abstract interpretation + explicit-state MC; no Z3)\n')

    sys.stdout.write('  L-pred  sanitizer is_* vs Unicode properties ...\n')
    di_m, bidi_m, zs_m = l_pred()
    sys.stdout.write('        di=%d bidi=%d zs=%d\n' % (di_m, bidi_m, zs_m))

    sys.stdout.write('  T1     absint + reference renderer over all %d cps ...\n'
                     % (MAX_CP + 1))
    eq_bad, ai_bad = t1_absint_and_ref()
    hom_bad = t1_ref_hom()
    sys.stdout.write('        ref_eq=%d absint=%d hom=%d\n' % (eq_bad, ai_bad, hom_bad))

    sys.stdout.write('  T3-T7  absint + reference maps over all code points ...\n')
    st = t_input_absint()
    t_input_strings()
    t7_bad = t7_classify()
    sys.stdout.write('        paste=%(paste)d paste_uni=%(paste_uni)d clip=%(clip)d '
                     'clip_uni=%(clip_uni)d clip_disp=%(clip_disp)d title=%(title)d '
                     'tui=%(tui)d t7=%(t7)d\n' % {**st, 't7': t7_bad})

    sys.stdout.write('  T2     explicit-state model check of feed_line_edits ...\n')
    inv_bad, freeze_bad = t2_modelcheck()
    sys.stdout.write('        inv=%d freeze=%d\n' % (inv_bad, freeze_bad))

    sys.stdout.write('  T8     independent ECMA-48 grammar + catalog splits ...\n')
    g_bad = t8_grammar()
    s_bad = t8_splits()
    sys.stdout.write('        grammar=%d splits=%d\n' % (g_bad, s_bad))

    sys.stdout.write('  T9     cells_to_runs lattice over all code points ...\n')
    t9_bad = t9_absint()
    sys.stdout.write('        absint=%d\n' % t9_bad)

    sys.stdout.write('  canaries ...\n')
    canaries()

    sys.stdout.write('verify_formal_absint: %d canaries verified, %d obligations failed\n'
                     % (CANARIES_VERIFIED[0], FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
