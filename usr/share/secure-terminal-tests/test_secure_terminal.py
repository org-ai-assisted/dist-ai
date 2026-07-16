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

# --- escapes are always stripped; editing controls always pass ----------------
ESC = '\x1b[31mRED\x1b[0m'
for mode in ('strip', 'show', 'reveal'):
    eq(S.render_output(ESC, mode), 'RED', 'escape stripped in %s' % mode)
    eq(S.render_output('ab\x08\r\t\nX', mode), 'ab\x08\r\t\nX',
       'editing controls pass in %s' % mode)

# CSI cursor moves, OSC hyperlink and bare escapes all vanish
eq(S.render_output('a\x1b[2Jb', 'strip'), 'ab', 'strip CSI clear')
eq(S.render_output('a\x1b]8;;http://evil\x07b', 'strip'), 'ab', 'strip OSC link')

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
# reveal must NOT expand a cell (badge would break the grid): collapses to glyph
eq(S.tui_cell(CAFE[-1], 'reveal'), CAFE[-1], 'tui reveal keeps one-wide glyph')
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

# --- sanitize_title: program-supplied title / notification -> safe ASCII ------
eq(S.sanitize_title('My Build'), 'My Build', 'title plain ascii')
eq(S.sanitize_title('ev' + BIDI + 'il'), 'evil', 'title strips bidi')
eq(S.sanitize_title('a\tb\nc'), 'a b c', 'title collapses whitespace')
eq(S.sanitize_title(CAFE), 'caf', 'title drops non-ascii')
eq(S.sanitize_title('x' * 200)[:5], 'xxxxx', 'title capped')
ok(len(S.sanitize_title('x' * 200)) <= 80, 'title length limit')
eq(S.sanitize_title(''), '', 'title empty')
eq(S.sanitize_title(None), '', 'title none-safe')

# --- constants ----------------------------------------------------------------
ok(len(S.ANSI_PALETTE) == 16, '16-colour palette')
ok(S.DISPLAY_MODES == ('strip', 'show', 'reveal'), 'display modes')
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
SET.config_dirs = lambda: [_sysd, _usrd]           # low -> high precedence
SET._user_config_dir = lambda: _usrd
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

# --- CLI: the sanitizing pty wrapper shares the sanitize core ------------------
import subprocess                                   # noqa: E402
_cli_code = (
    'import sys\n'
    'from secure_terminal.cli import main\n'
    "sys.exit(main(['--mode', 'strip', '--', 'printf',"
    " 'X\\033[31mRED\\033[0m Y\\342\\200\\256Z']))\n")
_env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
_cli = subprocess.run([sys.executable, '-c', _cli_code], env=_env,
                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                      stderr=subprocess.DEVNULL, timeout=30)
_cli_out = _cli.stdout.decode('utf-8', 'replace')
ok('\x1b' not in _cli_out and 'RED' in _cli_out,
   'cli strips escape sequences, keeps the text')
ok('_' in _cli_out and chr(0x202E) not in _cli_out,
   'cli neutralizes bidi to _ in strip mode')

# --- result -------------------------------------------------------------------
sys.stdout.write('secure-terminal-tests: %d passed, %d failed\n' % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
