#!/usr/bin/python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Display + test artifact: a cat-able Unicode showcase proving secure-terminal
## can show and risk-tint every character class. Sibling of truecolor-art.py.
##
## Default stdout -> unicode.payload:
##   - graphic-glyph block grids over the terminal-font-RENDERABLE subset (no CJK
##     / emoji / tofu): only spacing GRAPHIC glyphs, spaces and newlines -- zero
##     control bytes, so a grid is safe to cat on ANY terminal;
##   - dedicated RISK-SPECIMEN sections carrying the raw dangerous bytes (C0/C1
##     controls, bidi, zero-width/invisible, non-ASCII spaces, combining), each
##     specimen ISOLATED one-per-line so an escape it starts aborts at the newline
##     (the accepted inline-isolated containment). SO is paired with SI so no
##     charset shift lingers. secure-terminal neutralizes/tints all of it.
##   No SGR of our own: every colour you see is secure-terminal's risk tint.
##   No alt-screen, no OSC, no persistent state -> no `reset` needed.
##
## `--summary` -> a machine-readable JSON summary (per display-block + overall
##   class/category counts). Uses classify(), the INDEPENDENT oracle the dist-ai
##   test cross-checks secure-terminal's marking_class against.
##
## Deterministic for a fixed Unicode version (stamped in the header + summary).
## Source stays ASCII (R-001): every non-ASCII byte is emitted via chr() at
## runtime, never a literal in this file.

import json
import sys
import unicodedata

UNIDATA_VERSION = unicodedata.unidata_version

# Box-drawing frame (structural: secure-terminal shows these in the program's own
# colour, a live demo of the structural carve-out; a plain terminal draws them too).
H = '\u2500'          # BOX DRAWINGS LIGHT HORIZONTAL
DOTTED_CIRCLE = '\u25cc'   # standard isolated presentation of a combining mark

GRID_COLS = 16

# --- the independent classifier (oracle) --------------------------------------
# Mirrors secure_terminal.sanitize.marking_class BRANCH ORDER, but derives each
# class from a source INDEPENDENT of that module, so a drift in its ranges is
# caught rather than mirrored: control from general category Cc (== C0+DEL+C1
# exactly), bidi from the authoritative Bidi_Control list, invisible from
# str.isprintable() plus our own default-ignorable copy, confusable from the
# shipped confusables data, combining from a UAX #29 grapheme-cluster test.

# Unicode Bidi_Control=Yes -- the complete list.
_BIDI_CONTROL = frozenset({
    0x061C, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
})

# Default-ignorable code points str.isprintable() wrongly keeps (own copy of the
# secure-terminal spec: a divergence here IS the drift the test exists to catch).
_DEFAULT_IGNORABLE_RANGES = (
    (0x034F, 0x034F), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
    (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFFA0, 0xFFA0), (0x1D173, 0x1D17A),
    (0xE0100, 0xE01EF),
)

_ASCII_CONFUSABLES = None
_CLUSTER_RE = None


def _is_default_ignorable(cp):
    return any(lo <= cp <= hi for lo, hi in _DEFAULT_IGNORABLE_RANGES)


def _ascii_confusables():
    """Non-ASCII code points the shipped confusables data maps to a printable
    ASCII glyph -- the homoglyphs. Loaded independently of secure-terminal (same
    data file, separate code path). Empty if the package is absent (then such a
    character just stays 'nonascii', matching secure-terminal)."""
    global _ASCII_CONFUSABLES
    if _ASCII_CONFUSABLES is None:
        found = set()
        try:
            import os
            from confusable_homoglyphs import confusables as cf
            path = os.path.join(os.path.dirname(cf.__file__), 'confusables.json')
            with open(path, encoding='utf-8') as handle:
                data = json.load(handle)
            for source, alternatives in data.items():
                if len(source) != 1 or ord(source) <= 0x7F:
                    continue
                for alt in alternatives:
                    glyph = alt.get('c', '')
                    if len(glyph) == 1 and 0x20 <= ord(glyph) <= 0x7E:
                        found.add(ord(source))
                        break
        except Exception:      # pylint: disable=broad-except
            pass
        _ASCII_CONFUSABLES = frozenset(found)
    return _ASCII_CONFUSABLES


def _is_mark(ch):
    """True when 'a'+ch is one grapheme cluster, i.e. ch EXTENDS the base --
    UAX #29, the same property secure-terminal's combining branch uses. Own
    regex.compile(r'\\X'), independent of that module."""
    global _CLUSTER_RE
    if _CLUSTER_RE is None:
        import regex
        _CLUSTER_RE = regex.compile(r'\X')
    return len(_CLUSTER_RE.findall('a' + ch)) == 1


def classify(cp):
    """Independent oracle for secure_terminal.sanitize.marking_class. Same branch
    order (bidi > control > invisible > confusable > combining > nonascii)."""
    if not 0 <= cp <= 0x10FFFF:
        return 'nonascii'
    ch = chr(cp)
    if cp in _BIDI_CONTROL:
        return 'bidi'
    if unicodedata.category(ch) == 'Cc':         # C0 + DEL + C1, independent of ranges
        return 'control'
    if not ch.isprintable() or _is_default_ignorable(cp):
        return 'invisible'
    if cp > 0x7F and cp in _ascii_confusables():
        return 'confusable'
    if cp >= 0x0300 and _is_mark(ch):
        return 'combining'
    return 'nonascii'


# --- assigned-code-point iteration --------------------------------------------

def assigned_code_points():
    """Every assigned NON-private code point, minus surrogates. Skips unassigned
    (category Cn) and Private Use (Co): PUA has no character identity (its glyph is
    font-private), so secure-terminal boxes it and marking_class calls it
    'invisible' -- 137k of them would swamp and mislead the class summary, and the
    DISPLAY drops PUA too. Deterministic for a fixed Unicode version."""
    for cp in range(0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        if unicodedata.category(chr(cp)) in ('Cn', 'Co'):
            continue
        yield cp


# --- payload: the renderable-subset block grids -------------------------------
# Curated blocks the shipped monospace font (Hack, then DejaVu Sans Mono) draws --
# graphic scripts and symbols, tofu-free. Inherently-RTL scripts (Hebrew, Arabic)
# and CJK / emoji / astral are deliberately absent from the DISPLAY (they tofu or
# reorder); the conformance test covers them, font-independently. Trim by shot
# review if a sub-range tofus under the actual capture font.
DISPLAY_BLOCKS = (
    ('Latin-1 Supplement', 0x00A0, 0x00FF),
    ('Latin Extended-A', 0x0100, 0x017F),
    ('Latin Extended-B', 0x0180, 0x024F),
    ('IPA Extensions', 0x0250, 0x02AF),
    ('Spacing Modifier Letters', 0x02B0, 0x02FF),
    ('Greek and Coptic', 0x0370, 0x03FF),
    ('Cyrillic', 0x0400, 0x04FF),
    ('Armenian', 0x0531, 0x058F),
    ('Greek Extended', 0x1F00, 0x1FFF),
    ('Currency Symbols', 0x20A0, 0x20BF),
    ('Letterlike Symbols', 0x2100, 0x214F),
    ('Number Forms', 0x2150, 0x218F),
    ('Arrows', 0x2190, 0x21FF),
    ('Mathematical Operators', 0x2200, 0x22FF),
    ('Miscellaneous Technical', 0x2300, 0x23FF),
    ('Control Pictures', 0x2400, 0x243F),
    ('Box Drawing', 0x2500, 0x257F),
    ('Block Elements', 0x2580, 0x259F),
    ('Geometric Shapes', 0x25A0, 0x25FF),
    ('Dingbats', 0x2700, 0x27BF),
    ('Braille Patterns', 0x2800, 0x28FF),
)

# Categories a grid cell renders as its glyph: letters, numbers, punctuation,
# symbols. Everything else (control, format, separators, combining marks,
# surrogates, private-use, unassigned) is a BLANK in the grid -- the canonical
# code-chart look -- and, where it is a risk class, demonstrated in its own
# section below instead.
_GRAPHIC_PREFIX = ('L', 'N', 'P', 'S')


def _grid_cell(cp):
    # Graphic spacing glyphs only (L/N/P/S -- letters, numbers, punctuation,
    # symbols incl. Sk modifier symbols); everything else blanks, canonical chart.
    if 0xD800 <= cp <= 0xDFFF:
        return ' '
    if unicodedata.category(chr(cp))[0] in _GRAPHIC_PREFIX:
        return chr(cp)
    return ' '


def _block_grid(lo, hi):
    lines = []
    lines.append('       ' + '  '.join('%X' % c for c in range(GRID_COLS)))
    start = lo - (lo % GRID_COLS)
    for base in range(start, hi + 1, GRID_COLS):
        cells = []
        for col in range(GRID_COLS):
            cp = base + col
            cells.append(_grid_cell(cp) if lo <= cp <= hi else ' ')
        lines.append('U+%04X ' % base + '  '.join(cells))
    return lines


def _rule(title):
    bar = H * 4
    return '\n%s %s %s' % (bar, title, H * max(3, 66 - len(title)))


# --- payload: the risk-specimen sections (raw dangerous bytes) ----------------

_C0_NAMES = (
    'NUL', 'SOH', 'STX', 'ETX', 'EOT', 'ENQ', 'ACK', 'BEL', 'BS', 'HT', 'LF',
    'VT', 'FF', 'CR', 'SO', 'SI', 'DLE', 'DC1', 'DC2', 'DC3', 'DC4', 'NAK',
    'SYN', 'ETB', 'CAN', 'EM', 'SUB', 'ESC', 'FS', 'GS', 'RS', 'US',
)
_C1_NAMES = (
    'PAD', 'HOP', 'BPH', 'NBH', 'IND', 'NEL', 'SSA', 'ESA', 'HTS', 'HTJ', 'VTS',
    'PLD', 'PLU', 'RI', 'SS2', 'SS3', 'DCS', 'PU1', 'PU2', 'STS', 'CCH', 'MW',
    'SPA', 'EPA', 'SOS', 'SGC', 'SCI', 'CSI', 'ST', 'OSC', 'PM', 'APC',
)

# Zero-width / invisible / BOM specimens (the 'invisible' class). Raw, one-per-line.
_INVISIBLE = (
    (0x00AD, 'SOFT HYPHEN'), (0x200B, 'ZERO WIDTH SPACE'),
    (0x200C, 'ZERO WIDTH NON-JOINER'), (0x200D, 'ZERO WIDTH JOINER'),
    (0x2060, 'WORD JOINER'), (0x2061, 'FUNCTION APPLICATION'),
    (0xFEFF, 'ZERO WIDTH NO-BREAK SPACE (BOM)'), (0x034F, 'COMBINING GRAPHEME JOINER'),
    (0xFE00, 'VARIATION SELECTOR-1'), (0x2028, 'LINE SEPARATOR'),
    (0x2029, 'PARAGRAPH SEPARATOR'),
)
# Non-ASCII spaces (the 'invisible' class; Show mode marks them SPACE_MARK).
_SPACES = (0x00A0, 0x1680, 0x2000, 0x2003, 0x2007, 0x2009, 0x202F, 0x205F, 0x3000)
# Combining marks on a dotted circle (the 'combining' class).
_COMBINING = (0x0300, 0x0301, 0x0302, 0x0303, 0x0308, 0x030A, 0x0327, 0x0328,
              0x0335, 0x0489)
# Homoglyphs next to their ASCII twin (the 'confusable' class).
_CONFUSABLE = ((0x0430, 'a'), (0x0435, 'e'), (0x043E, 'o'), (0x0440, 'p'),
               (0x0441, 'c'), (0x0445, 'x'), (0x03BF, 'o'), (0x0391, 'A'),
               (0x0392, 'B'), (0x0395, 'E'), (0x2170, 'i'), (0x2160, 'I'))
# Noncharacters: labeled, a few examples only (never a full 66-cell grid).
_NONCHARS = (0xFDD0, 0xFFFE, 0x10FFFF)


def _spec_line(cp, label, glyph):
    """One isolated specimen: ASCII label, then the raw glyph LAST, then the
    caller's newline -- so any sequence the raw byte starts aborts at that newline."""
    return 'U+%04X  %-34s : %s' % (cp, label, glyph)


def _control_name(cp):
    if cp <= 0x1F:
        return _C0_NAMES[cp]
    if cp == 0x7F:
        return 'DEL'
    return _C1_NAMES[cp - 0x80]


def render_payload():
    out = []
    top = H * 72
    out.append(top)
    out.append('secure-terminal Unicode gallery -- safe to cat.')
    out.append('Unicode %s. A plain terminal shows this flat; secure-terminal tints'
               % UNIDATA_VERSION)
    out.append('every character by risk class and boxes what has no safe glyph.')
    out.append('Grids below emit only graphic glyphs (safe anywhere). The RISK')
    out.append('sections carry raw control/bidi/invisible bytes, isolated one per')
    out.append('line; on a plain terminal expect one BEL beep and minor cursor')
    out.append('nudges -- bounded, no persistent state, no `reset` needed.')
    out.append(top)

    # Renderable-subset block chart.
    for name, lo, hi in DISPLAY_BLOCKS:
        out.append(_rule('%s  U+%04X..U+%04X' % (name, lo, hi)))
        out.extend(_block_grid(lo, hi))

    # Risk specimens (raw dangerous bytes, inline-isolated).
    out.append(_rule('RISK: C0 control bytes  (secure-terminal tint: control)'))
    for cp in range(0x20):
        glyph = chr(cp) + (chr(0x0F) if cp == 0x0E else '')   # SO paired with SI
        out.append(_spec_line(cp, _control_name(cp), glyph))
    out.append(_spec_line(0x7F, 'DEL', chr(0x7F)))

    out.append(_rule('RISK: C1 control bytes  (tint: control)'))
    for cp in range(0x80, 0xA0):
        out.append(_spec_line(cp, _control_name(cp), chr(cp)))

    out.append(_rule('RISK: bidirectional controls  (tint: bidi -- reorders text)'))
    for cp in sorted(_BIDI_CONTROL):
        out.append(_spec_line(cp, unicodedata.name(chr(cp), '?'), chr(cp)))

    out.append(_rule('RISK: zero-width / invisible  (tint: invisible)'))
    for cp, label in _INVISIBLE:
        out.append(_spec_line(cp, label, chr(cp)))

    out.append(_rule('RISK: non-ASCII spaces  (tint: invisible; Show marks them)'))
    for cp in _SPACES:
        out.append(_spec_line(cp, unicodedata.name(chr(cp), '?'), chr(cp)))

    out.append(_rule('RISK: combining marks on a dotted circle  (tint: combining)'))
    for cp in _COMBINING:
        out.append(_spec_line(cp, unicodedata.name(chr(cp), '?'),
                              DOTTED_CIRCLE + chr(cp)))

    out.append(_rule('RISK: homoglyphs vs ASCII twin  (tint: confusable)'))
    for cp, twin in _CONFUSABLE:
        out.append(_spec_line(cp, '%s  (looks like ASCII %r)'
                              % (unicodedata.name(chr(cp), '?'), twin), chr(cp)))

    out.append(_rule('RISK: noncharacters  (a few examples only)'))
    for cp in _NONCHARS:
        out.append(_spec_line(cp, 'noncharacter', chr(cp)))

    out.append(_rule('honest foreign text is the mild "nonascii" tint, not a hazard'))
    out.append('Greek: ' + ''.join(chr(c) for c in range(0x0391, 0x03A2))
               + '   Cyrillic: ' + ''.join(chr(c) for c in range(0x0410, 0x0420)))
    out.append(top)
    return '\n'.join(out) + '\n'


# --- machine-readable summary -------------------------------------------------

def summary():
    by_class = {}
    by_category = {}
    total = 0
    display = []
    for name, lo, hi in DISPLAY_BLOCKS:
        display.append({'name': name, 'lo': lo, 'hi': hi, 'count': 0, 'by_class': {}})
    for cp in assigned_code_points():
        total += 1
        klass = classify(cp)
        cat = unicodedata.category(chr(cp))
        by_class[klass] = by_class.get(klass, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
        for blk in display:
            if blk['lo'] <= cp <= blk['hi']:
                blk['count'] += 1
                blk['by_class'][klass] = blk['by_class'].get(klass, 0) + 1
                break
    return {
        'unidata_version': UNIDATA_VERSION,
        'total_assigned': total,
        'by_class': dict(sorted(by_class.items())),
        'by_category': dict(sorted(by_category.items())),
        'display_blocks': display,
    }


def main(argv):
    if len(argv) > 1 and argv[1] == '--summary':
        # sort_keys matches the repo's pretty-format-json gate, so the committed
        # artifact regenerates byte-identically and never trips the static gate.
        sys.stdout.write(json.dumps(summary(), indent=2, ensure_ascii=True,
                                    sort_keys=True) + '\n')
        return 0
    if len(argv) > 1:
        sys.stderr.write('usage: unicode-gallery.py [--summary]\n')
        return 2
    sys.stdout.write(render_payload())
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
