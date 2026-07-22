#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Security-corpus tests for secure-terminal's sanitization core, mirroring the
corpora the stdisplay test suite runs against so the terminal is held to the same
bar: a named "dangerous" corpus (escapes, C0/C1 controls, bidi/zero-width/format,
homoglyphs), an EVERY-CODEPOINT sweep over all of Unicode, the Trojan-Source
paper's techniques, and every fixture from the git-diffs-lie adversarial corpus.

The invariant, across EVERY display mode:
  - no truly dangerous code point survives (escape/CSI/OSC, non-honored control,
    DEL, C1, bidi override, zero-width, BOM, line/paragraph separator);
  - box and reveal emit only safe ASCII + the honored editing controls (a
    homoglyph is neutralized to "_" or a <U+XXXX> badge);
  - show may keep a printable non-ASCII glyph (its documented risk) but STILL
    neutralizes every invisible/deceptive class;
  - sanitization is idempotent and independent of the byte SOURCE (a program's
    output, a local cat, or cat over ssh all pass through the same renderer).

Pure ASCII source: every codepoint is a number or a \\x/\\u escape. Qt-free.
"""

import sys

try:
    from secure_terminal import sanitize as S
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests(corpus): FAIL missing dependency: '
                     '%s\n' % exc)
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


MODES = ('box', 'show', 'reveal')

# controls the terminal HONORS as line-local editing (a program may use them, but
# the widget's line model bounds them to the current line -- see the fuzz tests);
# everything else in the control range must be neutralized.
_HONORED = {0x08, 0x09, 0x0A, 0x0D}
# The safe display alphabet for box / reveal: printable ASCII + the honored
# editing controls. (A reveal <U+XXXX> badge is itself ASCII.)
SAFE = frozenset(_HONORED | set(range(0x20, 0x7F)))

# Code points that must NEVER survive sanitization, in ANY mode: they are
# invisible, deceptive, or an active terminal/injection primitive.
DANGEROUS_CPS = frozenset(
    [c for c in range(0x00, 0x20) if c not in _HONORED]      # C0 controls incl ESC
    + [0x7F]                                                  # DEL
    + list(range(0x80, 0xA0))                                # C1 controls
    + [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF]  # zero-width / BOM
    + list(range(0x202A, 0x202F))                            # bidi embed/override
    + list(range(0x2066, 0x206A))                            # bidi isolates
    + [0x2028, 0x2029])                                      # line / paragraph sep


# ---------------------------------------------------------------------------
# Corpus 1: the dangerous corpus (mirrors stdisplay's dangerous_corpus()).
# ---------------------------------------------------------------------------
def dangerous_corpus():
    return {
        'csi-clear-screen': '\x1b[2J',
        'csi-cursor-home': '\x1b[H',
        'csi-cursor-up': '\x1b[10A',
        'csi-cursor-pos': '\x1b[5;9H',
        'csi-erase-line': '\x1b[2K',
        'csi-hide-cursor': '\x1b[?25l',
        'csi-alt-screen': '\x1b[?1049h',
        'csi-mouse-on': '\x1b[?1000h',
        'csi-dsr': '\x1b[6n',            # device status report -> writes to stdin
        'csi-da': '\x1b[c',              # device attributes -> writes to stdin
        'csi-private': '\x1b[>4;2m',     # private-param prefix (capable-TERM apps)
        'osc-title-bel': '\x1b]0;pwned\x07',
        'osc-title-st': '\x1b]0;pwned\x1b\\',
        'osc8-hyperlink': '\x1b]8;;http://evil\x1b\\link\x1b]8;;\x1b\\',
        'osc52-clipboard': '\x1b]52;c;cGF5bG9hZA==\x07',
        'ris-reset': '\x1bc',
        'charset-g0': '\x1b(0',
        'dcs': '\x1bP0;1|17/ab\x1b\\',
        'apc': '\x1b_payload\x1b\\',
        'pm': '\x1b^message\x1b\\',
        'bare-esc': 'a\x1bb',
        'c1-csi': 'a\x9b31mb',
        'c1-osc': 'a\x9d0;pwned\x07b',
        'c1-dcs': 'a\x90payload\x1b\\b',
        'c1-nel': 'a\x85b',
        'bell': 'a\x07b',
        'vtab': 'a\x0bb',
        'formfeed': 'a\x0cb',
        'nul': 'a\x00b',
        'del': 'a\x7fb',
        'rlo': 'a\u202eb',
        'lri': 'a\u2066b',
        'zwsp': 'a\u200bb',
        'zwnj': 'a\u200cb',
        'bom': 'a\ufeffb',
        'homoglyph': 'p\u0430ypal',      # Cyrillic a
        'line-sep': 'a\u2028b',
        'para-sep': 'a\u2029b',
        'c1-as-unicode': 'a\u009bb',
    }


# ---------------------------------------------------------------------------
# Corpus 2: Trojan-Source paper techniques (bidi reordering, homoglyph,
# invisible characters in source), https://trojansource.codes / CVE-2021-42574.
# ---------------------------------------------------------------------------
def trojan_source_corpus():
    return {
        # "commenting-out": an RLO makes a real statement read as a comment.
        'trojan-commenting-out':
            'access_level = "user\u202e \u2066// Check if admin\u2069'
            ' \u2066"\u2069;',
        # "stretched string": PDI/LRI hide code inside what looks like a string.
        'trojan-stretched-string':
            'if access_level != "user\u2066 admin\u2069":',
        # homoglyph function name (Cyrillic o) shadowing an ASCII one.
        'trojan-homoglyph': 'def is_admin(): return sfe_m\u043ede()',
        # invisible zero-width joiner splitting an identifier.
        'trojan-invisible': 'is\u200dadmin = True',
    }


# ---------------------------------------------------------------------------
# Corpus 3: the git-diffs-lie fixtures, vendored verbatim (bytes) from the
# adversarial-diff corpus branches (github.com/output-lies/git-diffs-lie).
# ---------------------------------------------------------------------------
def git_diffs_lie_fixtures():
    return {
        'ansi-escape': b'STATUS=FAIL\x1b[1A\x1b[2KSTATUS=PASS',
        'lone-cr': b'DELETE_EVERYTHING=yes\rDELETE_EVERYTHING=no',
        'bidi-trojan-source':
            b'    /* return \xe2\x80\xaenimda\xe2\x80\xac */ '
            b'return admin ? "user" : "admin";',
        'zero-width': b'ADMIN\xe2\x80\x8bTOKEN=granted',
        'homoglyph-identifier': b'    return v\xd0\xb0lidate("role");',
        'nul-byte': b'value=secret\x00 rm --recursive --force -- /',
        'invalid-utf8': b'checksum=\xff\xfe not valid utf-8',
        'overlong-line': b'payload=' + b'A' * 5000,
        'unicode-whitespace': b'RETRY_LIMIT\xc2\xa0=\xc2\xa00',
    }


# ---------------------------------------------------------------------------
# The shared assertion: `text` is safely sanitized in every mode.
# ---------------------------------------------------------------------------
def assert_safe(name, text):
    for mode in MODES:
        out = S.render_output(text, mode)
        # (1) no dangerous code point survives, in any mode.
        bad = [ch for ch in out if ord(ch) in DANGEROUS_CPS]
        ok(not bad, '%s/%s: a dangerous code point survived: %r'
           % (name, mode, bad[:4]))
        # (2) idempotence.
        ok(S.render_output(out, mode) == out, '%s/%s: not idempotent' % (name, mode))
    strip = S.render_output(text, 'box')
    ok(all(ord(ch) in SAFE for ch in strip),
       '%s: box left a non-safe char' % name)
    reveal = S.render_output(text, 'reveal')
    ok(all(ord(ch) in SAFE for ch in reveal),
       '%s: reveal left a non-safe char' % name)
    show = S.render_output(text, 'show')
    ok(all(ch in '\x08\t\n\r' or ch.isprintable() for ch in show),
       '%s: show left a non-printable char' % name)


# --- run the three text corpora -----------------------------------------------
for _name, _raw in dangerous_corpus().items():
    assert_safe('dangerous:' + _name, _raw)
for _name, _raw in trojan_source_corpus().items():
    assert_safe('trojan:' + _name, _raw)

# --- git-diffs-lie fixtures: decode like the pty does (UTF-8, replace) --------
for _name, _rawbytes in git_diffs_lie_fixtures().items():
    _text = _rawbytes.decode('utf-8', 'replace')
    assert_safe('git-diffs-lie:' + _name, _text)
    # also the raw-byte path (latin-1 1:1, as sanitize_bytes uses)
    ok(all(ord(ch) in SAFE for ch in S.sanitize_bytes(_rawbytes, 'box')),
       'git-diffs-lie:%s: sanitize_bytes(box) is safe' % _name)

# the escape/CR forgeries must not HIDE the real value: the neutralized render
# still contains the honest text a naive terminal would have painted over.
_ansi = S.render_output(
    git_diffs_lie_fixtures()['ansi-escape'].decode('utf-8'), 'box')
ok('STATUS=FAIL' in _ansi and '\x1b' not in _ansi,
   'ansi-escape: the erased "FAIL" survives and the escape is gone')

# the forgeries are also bounded to their own line in the widget's line model:
# the cursor-up escape cannot reach an earlier line (it is stripped, not honored).
_comp, _cells, _col, _sgr, _w = S.feed_line_edits(
    [], 0, {}, git_diffs_lie_fixtures()['ansi-escape'].decode('utf-8'))
ok(_comp == [] and all(c != '\x1b' for c, _ in _cells),
   'ansi-escape: stays on one line, no escape reaches a cell')

# --- Corpus 4: EVERY Unicode code point, sanitized in one pass ----------------
# (surrogates are not scalar values; skip them. This is the exhaustive analogue
# of stdisplay's random-codepoint fuzz.)
_all = ''.join(chr(c) for c in range(0x00, 0x110000)
               if not 0xD800 <= c <= 0xDFFF)
_strip_all = S.render_output(_all, 'box')
ok(all(ord(ch) in SAFE for ch in _strip_all),
   'all-unicode: box emits only safe ASCII + honored controls')
ok(S.render_output(_strip_all, 'box') == _strip_all,
   'all-unicode: box is idempotent')
_reveal_all = S.render_output(_all, 'reveal')
ok(all(ord(ch) in SAFE for ch in _reveal_all),
   'all-unicode: reveal emits only safe ASCII (badges are ASCII)')
_show_all = S.render_output(_all, 'show')
ok(not any(ord(ch) in DANGEROUS_CPS for ch in _show_all),
   'all-unicode: show neutralizes every dangerous code point')
ok(all(ch in '\x08\t\n\r' or ch.isprintable() for ch in _show_all),
   'all-unicode: show emits only printable + honored controls')

# --- result -------------------------------------------------------------------
sys.stdout.write('secure-terminal-tests(corpus): %d passed, %d failed\n'
                 % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
