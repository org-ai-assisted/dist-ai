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
import unicodedata

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


# Every display mode, INCLUDING detail -- which is the shipped default
# (unicode_mode=detail, and render_output's own default). Omitting it meant no
# corpus payload was ever asserted against the mode users actually run.
MODES = S.DISPLAY_MODES

# controls the terminal HONORS as line-local editing (a program may use them, but
# the widget's line model bounds them to the current line -- see the fuzz tests);
# everything else in the control range must be neutralized.
_HONORED = {0x08, 0x09, 0x0A, 0x0D}
# The safe display alphabet for box / reveal: printable ASCII + the honored
# editing controls. (A reveal <U+XXXX> badge is itself ASCII.)
SAFE = frozenset(_HONORED | set(range(0x20, 0x7F)))

# Code points that must NEVER survive sanitization, in ANY mode: they are
# invisible, deceptive, or an active terminal/injection primitive.
#
# DERIVED from the Unicode general categories, never enumerated. A hand-written
# blocklist is the wrong shape for an ORACLE: a missing member silently WEAKENS
# every assertion that consumes it rather than failing one, so the hole cannot
# announce itself. That is exactly how U+061C, U+2061..2064 and U+180E went
# missing here, and how they then stayed missing in the two sibling copies long
# after being fixed in this one.
#   Cc  control (C0, DEL, C1)
#   Cf  format: every bidi control, the zero-widths, the invisible math
#       operators, the BOM/word joiner, the soft hyphen, the Mongolian separator
#   Zl/Zp  line and paragraph separators
# Plus the default-ignorables, the one class no general category exposes: they
# report as printable yet render as nothing.
_DANGEROUS_CATEGORIES = frozenset(('Cc', 'Cf', 'Zl', 'Zp'))
DANGEROUS_CPS = frozenset(
    cp for cp in range(0x110000)
    if cp not in _HONORED
    and (unicodedata.category(chr(cp)) in _DANGEROUS_CATEGORIES
         or S.is_default_ignorable(chr(cp))))

# Canary for the derivation itself. The default-ignorable arm above borrows a
# PRODUCT predicate, so a gutted is_default_ignorable (or a narrowed category
# set) would shrink this oracle silently. Naming the members makes that a
# failure. Includes the three historical holes, so they cannot reopen.
for _cp in (0x00, 0x1B, 0x7F, 0x9B,                     # C0 / ESC / DEL / C1
            0x061C, 0x180E, 0x200B, 0x200D, 0x200E,     # bidi + zero-width
            0x202E, 0x2066, 0x2028, 0x2029, 0xFEFF,
            0x2061, 0x2062, 0x2063, 0x2064,             # invisible math ops
            0xFE0F, 0x3164, 0x115F, 0x034F):            # default-ignorables
    ok(_cp in DANGEROUS_CPS,
       'DANGEROUS_CPS is derived wide enough to include U+%04X' % _cp)
ok(not (DANGEROUS_CPS & SAFE),
   'the safe display alphabet and the dangerous set are disjoint')


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
        # Default-ignorable INVISIBLES that str.isprintable() reports as printable,
        # so a predicate based on it alone lets them through show unmarked. These
        # are real spoofing primitives (U+3164 is the classic invisible "letter").
        'vs16-variation-selector': 'ad\ufe0fmin',
        'hangul-filler': 'ad\u3164min',
        'choseong-filler': 'ad\u115fmin',
        'combining-grapheme-joiner': 'ad\u034fmin',
        'arabic-letter-mark': 'a\u061cb',
        'invisible-times': 'a\u2062b',
        'invisible-separator': 'a\u2063b',
        'mongolian-vowel-sep': 'a\u180eb',
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
        # "early return": an RLI (U+2067) reorders a comment so a live `return`
        # renders as part of it, cutting the function short. Taken from the
        # paper's own C sample (trojan-source/C/early-return.c).
        'trojan-early-return':
            '    /* Say hello; newline\u2067 /*/ return 0 ;',
    }


# ---------------------------------------------------------------------------
# Corpus 3: the git-diffs-lie fixtures, vendored VERBATIM (bytes) from the
# content/* payload branches of github.com/output-lies/git-diffs-lie.
#
# Scope is deliberately the content/* class only. Upstream also carries path/*,
# type/* and refname branches (bidi filenames, gitattributes hiding a diff, mode
# and symlink flips, gitlink mimics). Those are git-METADATA attacks on a diff
# viewer, not byte-stream attacks on a terminal, so they are out of scope here --
# git-meld-tests drives the full corpus from the real checkout.
#
# The bytes below are the exact file contents on each branch, so they can be
# checked against upstream. This suite does exactly that wherever a git-diffs-lie
# checkout resolves (see git_diffs_lie_dir below): upstream wins, every in-tree copy
# is asserted to match the branch it stands in for, and a NEW content/* branch is
# picked up automatically -- an inline copy that silently diverges is worse than no
# copy.
# ---------------------------------------------------------------------------
def git_diffs_lie_fixtures():
    return {
        # ansi-escape (data/config.env, 31 bytes)
        'ansi-escape': b'STATUS=FAIL\x1b[1A\x1b[2KSTATUS=PASS\n',
        # bidi-trojan-source (src/hello.c, 121 bytes)
        'bidi-trojan-source':
            b'#include <stdio.h>\n\nconst char *access_l'
            b'evel(int admin) {\n   /* return \xe2\x80\xaenimda\xe2'
            b'\x80\xac */ return admin ? "user" : "admin";\n}'
            b'\n',
        # homoglyph-identifier (src/hello.c, 68 bytes)
        'homoglyph-identifier':
            b'#include <stdio.h>\n\nint main(void) {\n   '
            b'return v\xd0\xb0lidate("role");\n}\n',
        # invalid-utf8 (data/config.env, 28 bytes)
        'invalid-utf8': b'checksum=\xff\xfe not valid utf-8\n',
        # lone-cr (data/config.env, 43 bytes)
        'lone-cr': b'DELETE_EVERYTHING=yes\rDELETE_EVERYTHING=no\n',
        # nul-byte (data/config.env, 13 bytes)
        'nul-byte': b'before\x00after\n',
        # overlong-line (data/config.env, 6009 bytes)
        'overlong-line': b'payload=' + b'A' * 6000 + b'\n',
        # unicode-whitespace (data/config.env, 18 bytes)
        'unicode-whitespace': b'RETRY_LIMIT\xc2\xa0=\xc2\xa00\n',
        # zero-width (data/config.env, 22 bytes)
        'zero-width': b'ADMIN\xe2\x80\x8bTOKEN=granted\n',
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
    # str.isprintable() is TRUE for the default-ignorable set (variation selectors,
    # the Hangul fillers), which render as NOTHING. Checking only isprintable() let
    # an invisible character through show unmarked -- the one thing every mode is
    # supposed to prevent -- and the exhaustive Unicode sweep passed it too.
    ok(not any(S.is_default_ignorable(ch) for ch in show),
       '%s: show left an invisible default-ignorable char' % name)


def assert_all_paths(name, text):
    """Throw the payload at every sanitizer ENTRY POINT, not just render_output.

    Measured before this existed, by stubbing each function and counting which corpus
    assertions noticed: render_output 299 of 504, sanitize_bytes 7, feed_line_edits 2,
    and sanitize_paste / sanitize_clipboard / sanitize_title / paste_findings /
    classify_paste / tui_cell ZERO. The corpora were a render_output test wearing a
    corpus's name, so a regression on the paste, clipboard, title or LIVE display path
    would not have failed a single assertion here.
    """
    # the raw-BYTE path, in every mode (was box only)
    raw_bytes = text.encode('utf-8', 'surrogatepass')
    for mode in MODES:
        out = S.sanitize_bytes(raw_bytes, mode)
        ok(not any(ord(ch) in DANGEROUS_CPS for ch in out),
           '%s/%s: sanitize_bytes let a dangerous code point through' % (name, mode))

    # the LIVE display path: feed_line_edits + cells_to_runs, which is what the
    # widget actually runs. render_output has no cursor model, so it cannot see this.
    _c, cells, col, sgr, wraps = S.feed_line_edits([], 0, {}, text)
    ok(all(ch != '\x1b' for ch, _ in cells),
       '%s: an ESC reached a cell on the live path' % name)
    ok(0 <= col <= len(cells), '%s: live cursor left the cell range' % name)
    runs, _prefix = S.cells_to_runs([], cells, 'box', False)
    joined = ''.join(run_text for run_text, _key in runs)
    ok(not any(ord(ch) in DANGEROUS_CPS for ch in joined),
       '%s: a dangerous code point survived into a rendered run' % name)

    # the PASTE path (text coming IN) -- both directions of the send choice
    for fn_name, fn in (('sanitize_paste', S.sanitize_paste),
                        ('sanitize_paste_unicode', S.sanitize_paste_unicode)):
        out = fn(text)
        ok(not any(ord(ch) in DANGEROUS_CPS for ch in out),
           '%s: %s let a dangerous code point through' % (name, fn_name))
        ok(not any(S.is_default_ignorable(ch) for ch in out),
           '%s: %s left an invisible default-ignorable char' % (name, fn_name))

    # the CLIPBOARD path (text going OUT)
    for fn_name, fn in (('sanitize_clipboard', S.sanitize_clipboard),
                        ('sanitize_clipboard_unicode', S.sanitize_clipboard_unicode)):
        out = fn(text)
        ok(not any(ord(ch) in DANGEROUS_CPS for ch in out),
           '%s: %s let a dangerous code point through' % (name, fn_name))

    # the TITLE path (a program setting the window title)
    title = S.sanitize_title(text)
    ok(not any(ord(ch) in DANGEROUS_CPS for ch in title),
       '%s: sanitize_title let a dangerous code point through' % name)
    ok(len(title) <= 80, '%s: sanitize_title exceeded its limit' % name)

    # the CLASSIFIERS must not crash, and must NAME what is hidden rather than
    # shrugging -- a hostile payload reported as clean is a silent failure.
    # paste_findings -> (has_unicode, has_control); classify_paste -> [(label, count)]
    has_unicode, has_control = S.paste_findings(text)
    classes = S.classify_paste(text)
    ok(isinstance(classes, list), '%s: classify_paste returned %r, want a list'
       % (name, type(classes).__name__))
    # A payload carrying a dangerous code point must be REPORTED, not shrugged at:
    # a hostile paste described as clean is a silent failure of the review bar.
    if any(ord(ch) in DANGEROUS_CPS for ch in text):
        ok(has_unicode or has_control or bool(classes),
           '%s: the classifiers reported nothing for a payload carrying a '
           'dangerous code point' % name)

    # the TUI cell path (pyte grid), per character
    for ch in text:
        cell = S.tui_cell(ch, 'box')
        ok(cell is not None, '%s: tui_cell returned None for %r' % (name, ch))


def assert_actually_hostile(name, text):
    """POSITIVE CONTROL. assert_safe() only checks the OUTPUT is clean, which plain
    ASCII satisfies trivially -- so without this, replacing every fixture with the
    word "harmless" still passed 504/504 (measured). Assert the INPUT really carries
    something the sanitizer must act on, so a gutted or silently-emptied fixture
    fails instead of quietly proving nothing."""
    hostile = any(ord(ch) in DANGEROUS_CPS or ord(ch) > 0x7F for ch in text)
    ok(hostile, '%s: fixture carries no dangerous or non-ASCII char (gutted?)' % name)
    # and sanitization must visibly CHANGE it in the strictest mode
    ok(S.render_output(text, 'box') != text,
       '%s: box mode left the payload byte-identical (nothing was neutralized)' % name)


# --- run the three text corpora -----------------------------------------------
# Count floors: losing fixtures silently shrinks the assertion total, which no
# summary line flags. Gutting dangerous_corpus to one entry dropped 504 -> 162
# assertions and still reported 0 failed (measured).
_dang = dangerous_corpus()
_troj = trojan_source_corpus()
ok(len(_dang) >= 30, 'dangerous corpus is populated (%d fixtures)' % len(_dang))
ok(len(_troj) >= 5, 'trojan-source corpus is populated (%d fixtures)' % len(_troj))
for _name, _raw in _dang.items():
    assert_actually_hostile('dangerous:' + _name, _raw)
    assert_safe('dangerous:' + _name, _raw)
    assert_all_paths('dangerous:' + _name, _raw)
for _name, _raw in _troj.items():
    assert_actually_hostile('trojan:' + _name, _raw)
    assert_safe('trojan:' + _name, _raw)
    assert_all_paths('trojan:' + _name, _raw)

# --- git-diffs-lie: prefer the REAL corpus on disk, fall back to the copy ------
# Reading the checkout is strictly better than checking a copy for staleness: a
# fixture added upstream is picked up and asserted automatically instead of being
# reported as drift for someone to hand-sync. Resolution matches the established
# pattern (git-meld-tests/corpus-lib.sh): $GIT_DIFFS_LIE_DIR, then
# ~/private-sources/git-diffs-lie, then a sibling checkout.
#
# The vendored copy above is the FLOOR, not the source of truth: the reusable CI
# workflow checks out only the code under test plus dist-ai, so without a floor the
# assertions would silently cover nothing there (exit 77 counts as green in
# dist-ai-tests-all -- the false-green shape this suite exists to prevent). The
# local-adversarial-corpus workflow supplies a real checkout, so the disk path is
# genuinely exercised in CI rather than only on a developer box.
import os                                            # noqa: E402
import subprocess                                    # noqa: E402


def git_diffs_lie_dir():
    """The git-diffs-lie checkout, or None."""
    candidates = [os.environ.get('GIT_DIFFS_LIE_DIR') or '']
    home = os.environ.get('HOME') or os.path.expanduser('~')
    candidates.append(os.path.join(home, 'private-sources', 'git-diffs-lie'))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, '..', '..', '..', '..', 'git-diffs-lie'))
    for path in candidates:
        if path and os.path.isdir(os.path.join(path, '.git')):
            return os.path.abspath(path)
    return None


def git_diffs_lie_upstream(repo):
    """{name: payload bytes} for every content/* branch in the checkout."""
    listing = subprocess.run(('git', '-C', repo, 'branch', '-a',
                              '--format=%(refname:short)'),
                             capture_output=True, check=False)
    refs = {}
    for ref in listing.stdout.decode('utf-8', 'replace').split():
        short = ref.split('origin/', 1)[1] if ref.startswith('origin/') else ref
        if not short.startswith('content/'):
            continue
        name = short.split('/', 1)[1]
        if name not in refs or ref.startswith('origin/'):
            refs[name] = ref              # prefer the remote-tracking ref
    found = {}
    for name, ref in refs.items():
        stat = subprocess.run(('git', '-C', repo, 'show', '--stat', '--format=', ref),
                              capture_output=True, check=False)
        lines = [ln for ln in stat.stdout.decode('utf-8', 'replace').splitlines()
                 if '|' in ln]
        if not lines:
            continue
        blob = subprocess.run(('git', '-C', repo, 'show',
                               '%s:%s' % (ref, lines[0].split('|')[0].strip())),
                              capture_output=True, check=False)
        if blob.returncode == 0:
            found[name] = blob.stdout
    return found


_gdl_repo = git_diffs_lie_dir()
_gdl = dict(git_diffs_lie_fixtures())
if _gdl_repo:
    _upstream = git_diffs_lie_upstream(_gdl_repo)
    ok(len(_upstream) > 0,
       'git-diffs-lie: content/* payload branches readable in %s (a shallow or '
       'single-branch clone cannot serve the corpus)' % _gdl_repo)
    # Every vendored fixture must still match the branch it claims to copy, so the
    # floor cannot quietly diverge from the corpus it stands in for.
    for _name, _bytes in sorted(_gdl.items()):
        if _name in _upstream:
            ok(_upstream[_name] == _bytes,
               'git-diffs-lie:%s: in-tree copy matches upstream (%d vs %d bytes)'
               % (_name, len(_bytes), len(_upstream[_name])))
        else:
            ok(False, 'git-diffs-lie:%s: copied but no upstream content/* branch'
               % _name)
    _gdl.update(_upstream)                # upstream wins, and adds any new fixture
    print('secure-terminal-tests(corpus): git-diffs-lie read from %s (%d fixtures)'
          % (_gdl_repo, len(_upstream)))
else:
    print('secure-terminal-tests(corpus): no git-diffs-lie checkout; using the %d '
          'in-tree fixtures (set GIT_DIFFS_LIE_DIR for the full corpus)'
          % len(_gdl))

for _name, _rawbytes in sorted(_gdl.items()):
    _text = _rawbytes.decode('utf-8', 'replace')
    assert_safe('git-diffs-lie:' + _name, _text)
    assert_all_paths('git-diffs-lie:' + _name, _text)
    # also the raw-byte path (latin-1 1:1, as sanitize_bytes uses)
    ok(all(ord(ch) in SAFE for ch in S.sanitize_bytes(_rawbytes, 'box')),
       'git-diffs-lie:%s: sanitize_bytes(box) is safe' % _name)

# On the RE-RENDER path (render_output, used for a mode change / transcript) the
# escape is neutralized rather than honored, so the value a naive terminal would
# have painted over is still there.
_ansi = S.render_output(
    git_diffs_lie_fixtures()['ansi-escape'].decode('utf-8'), 'box')
ok('STATUS=FAIL' in _ansi and '\x1b' not in _ansi,
   'ansi-escape: render_output keeps the erased "FAIL" and drops the escape')

# The LIVE path (feed_line_edits) is a line editor, so WITHIN the current line a
# later write overwrites an earlier one -- exactly as `\r` does, which has to keep
# working for progress bars. So the honest guarantee is NOT "FAIL always survives"
# here; it is containment:
#   - no ESC ever reaches a cell, and
#   - the cursor cannot escape the current line, so an EARLIER line is untouchable.
# Asserting the stronger claim on this path would be a false assurance: the widget
# really does display STATUS=PASS for a single-line payload.
_prev, _cells0, _col0, _sgr0, _w0 = S.feed_line_edits(
    [], 0, {}, 'line1: REAL\n')
_comp, _cells, _col, _sgr, _w = S.feed_line_edits(
    _cells0, _col0, _sgr0,
    git_diffs_lie_fixtures()['ansi-escape'].decode('utf-8'))
ok(all(c != '\x1b' for c, _ in _cells)
   and all(c != '\x1b' for _line in _comp for c, _ in _line),
   'ansi-escape: no escape reaches a cell on the live path')
# NOT asserted here, deliberately: an earlier-line containment claim is a property
# of the widget DOCUMENT, and feed_line_edits copies its input (cells = list(cells))
# and is handed an empty current line after a newline -- so the previous line is not
# even an input to the call. An assertion on it here could not fail for any input,
# which is worse than no assertion. The real test drives the live widget:
# test_widget.py, "the cursor-UP is stripped, so the forgery cannot reach the EARLIER
# line".

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
# isprintable() is TRUE for the default-ignorable set (variation selectors, Hangul
# fillers, the combining grapheme joiner), which render as NOTHING -- so the sweep
# above passed an INVISIBLE character through show, unmarked, for every one of them.
# This is the assertion that covers the whole class rather than one fixture.
ok(not any(S.is_default_ignorable(ch) for ch in _show_all),
   'all-unicode: show neutralizes every invisible default-ignorable code point')
# Cf (FORMAT) is the whole class of invisible controls -- bidi overrides, the
# zero-widths, the Arabic letter mark, the invisible math operators. Asserted as a
# CLASS, independently of DANGEROUS_CPS, so a newly assigned format character is
# covered the day Python's unicodedata knows it and neither check can be the
# other's only witness.
for _mode in MODES:
    _out = S.render_output(_all, _mode)
    _fmt = sorted({ord(ch) for ch in _out if unicodedata.category(ch) == 'Cf'})
    ok(not _fmt, 'all-unicode/%s: an invisible FORMAT (Cf) char survived: %s'
       % (_mode, ['U+%04X' % c for c in _fmt[:6]]))

# --- #43 perf refactors: BYTE-IDENTICAL differential --------------------------
# Two hot-path optimizations must not change a single output byte:
#   (1) feed_line_edits caches the SGR state tuple instead of rebuilding
#       tuple(sorted(sgr.items())) per printable char;
#   (2) render_output guards the escape strip with `if '\x1b' in text`.
# Both are proven byte-identical against a reference over the whole corpus plus
# payloads chosen to stress the exact sites (SGR-heavy, colour transitions, a
# cursor-pad AFTER an SGR change -- the cache-sensitive path -- bidi, homoglyph,
# combining runs, invisibles, split escapes).


def _ref_feed_line_edits(cells, col, sgr, raw, max_line=0, line_edits=True):
    """Reference oracle: feed_line_edits WITHOUT the SGR-tuple cache -- it rebuilds
    tuple(sorted(sgr.items())) at every append/pad site, the pre-optimization form.
    All parsing internals come from the real module, so only the cache placement
    differs; if the live cache ever goes stale, a cell tuple diverges here."""
    completed = []
    wraps = []
    cells = list(cells)
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == '\x1b':
            m = S._LINE_CSI_RE.match(raw, i) if line_edits else None
            if m:
                num = S._safe_int(m.group(1), None) if m.group(1) else None
                op = m.group(2)
                if op == 'C':
                    col = col + (num or 1)
                    col = (min(col, max_line - 1) if max_line
                           else min(col, S._UNBOUNDED_MAX_COL))
                    while len(cells) < col:
                        cells.append((' ', tuple(sorted(sgr.items()))))
                elif op == 'D':
                    col = max(0, col - (num or 1))
                elif op == 'G':
                    col = max(0, (num or 1) - 1)
                    col = (min(col, max_line - 1) if max_line
                           else min(col, S._UNBOUNDED_MAX_COL))
                    while len(cells) < col:
                        cells.append((' ', tuple(sorted(sgr.items()))))
                else:
                    if num in (None, 0):
                        del cells[col:]
                    elif num == 1:
                        for j in range(0, min(col + 1, len(cells))):
                            cells[j] = (' ', tuple(sorted(sgr.items())))
                    elif num == 2:                       # erase whole line;
                        # cursor unchanged (ECMA-48): blank to col cells, keep col
                        cells = [(' ', tuple(sorted(sgr.items())))] * col
                if max_line and col >= max_line:
                    col = max_line - 1
                i = m.end()
                continue
            m = S._SGR_ONLY_RE.match(raw, i)
            if m:
                sgr = dict(sgr)
                S.parse_sgr(m.group(1), sgr)
                i = m.end()
                continue
            if raw.startswith(S.PROMPT_START, i):
                j = i + len(S.PROMPT_START)
                if col != 0 and S._printable_follows(raw, j):
                    completed.append(cells)
                    wraps.append(bool(max_line) and col >= max_line)
                    cells, col = [], 0
                i = j
                continue
            m = S.ANSI_RE.match(raw, i)
            if m:
                i = m.end()
                continue
            i += 1
            continue
        if ch == '\n':
            completed.append(cells)
            wraps.append(False)
            cells, col = [], 0
        elif ch == '\r':
            col = 0
        elif ch == '\x08':
            if col > 0:
                col -= 1
        elif ch == '\x07':
            pass
        else:
            if max_line and col >= max_line:
                completed.append(cells)
                wraps.append(True)
                cells, col = [], 0
            if ord(ch) >= 0x0300 and S._is_mark(ch):
                left = 0
                j = col - 1
                while 0 <= j < len(cells) and S._is_mark(cells[j][0]):
                    left += 1
                    if left >= S._COMBINING_RUN_MAX:
                        break
                    j -= 1
                right = 0
                j = col + 1
                while j < len(cells) and S._is_mark(cells[j][0]):
                    right += 1
                    if right >= S._COMBINING_RUN_MAX:
                        break
                    j += 1
                if left + 1 + right > S._COMBINING_RUN_MAX:
                    i += 1
                    continue
            state = tuple(sorted(sgr.items()))
            if col < len(cells):
                cells[col] = (ch, state)
            else:
                cells.append((ch, state))
            col += 1
        i += 1
    return completed, cells, col, sgr, wraps


# the differential corpus: every text fixture above, plus site-stressing payloads
_diff_payloads = {}
for _src, _prefix in ((_dang, 'dangerous'), (_troj, 'trojan')):
    for _n, _t in _src.items():
        _diff_payloads['%s:%s' % (_prefix, _n)] = _t
for _n, _b in _gdl.items():
    _diff_payloads['gdl:' + _n] = _b.decode('utf-8', 'replace')
_diff_payloads.update({
    'sgr-heavy': '\x1b[31mA\x1b[1;32mB\x1b[4;33;44mC\x1b[0mD\x1b[7mE\x1b[27mF',
    'sgr-transitions': ''.join('\x1b[3%dm%d' % (k % 8, k) for k in range(20)),
    # a cursor pad AFTER an SGR change: the padded blank cells must carry the NEW
    # state -- the exact site the cache could serve stale.
    'sgr-then-C-pad': '\x1b[31m\x1b[6Cx\x1b[32m\x1b[3Cy',
    'sgr-then-G-pad': '\x1b[45m\x1b[9Gz\x1b[0m\x1b[2Gw',
    'sgr-then-erase': '\x1b[31mabc\x1b[1K\x1b[32mdef\x1b[0K',
    'colour-then-text': '\x1b[38;5;208msunset\x1b[48;5;19mnavy\x1b[0mplain',
    'combining-under-cap': 'e' + '\u0301' * 8 + 'x',
    'combining-over-cap': 'e' + '\u0301' * 60 + 'x',
    'split-escape-tail': 'abc\x1b[3',
    'lone-esc-tail': 'abc\x1b',
    'bidi-run': 'a\u202eBODY\u202cb',
    'homoglyph-run': 'p\u0430ss\u043erd',       # Cyrillic a, o
    'invisibles-run': 'ad\u200b\u200c\ufe0fmin',
})

_line_diff = 0
for _name, _text in _diff_payloads.items():
    # (1) feed_line_edits cells (chars AND state tuples) byte-identical, for
    # line_edits on/off and wrap off/on.
    for _le in (True, False):
        for _ml in (0, 20):
            _got = S.feed_line_edits([], 0, {}, _text, _ml, _le)
            _ref = _ref_feed_line_edits([], 0, {}, _text, _ml, _le)
            if _got != _ref:
                _line_diff += 1
            ok(_got == _ref,
               'feed_line_edits differs from the pre-cache reference (%s, '
               'line_edits=%s, max_line=%d)' % (_name, _le, _ml))
    # (2) render_output byte-identical to the forced-strip reference, every mode.
    # render_output(pre-stripped) forces the sub the guard may skip, so an unequal
    # result would mean the guard wrongly skipped a needed strip.
    _stripped = S.ANSI_RE.sub('', _text)
    for _mode in MODES:
        ok(S.render_output(_text, _mode) == S.render_output(_stripped, _mode),
           'render_output differs from the forced-strip reference (%s/%s)'
           % (_name, _mode))
    # (3) the downstream cell render is unaffected too, colours/markings on+off.
    _cells = S.feed_line_edits([], 0, {}, _text)[1]
    _rcells = _ref_feed_line_edits([], 0, {}, _text)[1]
    for _colors in (True, False):
        for _markings in (True, False):
            ok(S.cells_to_runs([], _cells, 'show', _colors, _markings)
               == S.cells_to_runs([], _rcells, 'show', _colors, _markings),
               'cells_to_runs differs from the reference (%s, colors=%s, '
               'markings=%s)' % (_name, _colors, _markings))

# CANARY: the reference must be able to DISAGREE with a stale cache -- a payload
# that changes SGR then pads blanks (a cursor-forward past end-of-line) forces the
# padded cells to carry the post-change state. Prove the live path puts the NEW
# state on those blanks (a stale/empty cache would leave them state ()), so this
# differential is not vacuously green. A small max_line keeps the pad short and
# deterministic (unbounded mode pads too, up to _UNBOUNDED_MAX_COL).
_can = S.feed_line_edits([], 0, {}, '\x1b[31m\x1b[4Cx', 20, True)[1]
ok(len(_can) == 5 and _can[0][1] == _can[4][1] and _can[0][1] != (),
   'cache canary: SGR-set blanks from a cursor pad carry the live SGR state '
   '(got %r)' % (_can[:1],))

ok(_line_diff == 0, 'feed_line_edits matched the reference on every payload '
   '(%d mismatches)' % _line_diff)

# --- result -------------------------------------------------------------------
sys.stdout.write('secure-terminal-tests(corpus): %d passed, %d failed\n'
                 % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
