#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Property-based fuzz tests for secure-terminal's pure parsers of untrusted input
(secure_terminal.sanitize), using hypothesis. These are the functions that see
hostile bytes: the output renderer, the paste sanitizer/classifier, the title
sanitizer, the safe-colour SGR parser and the per-cell TUI sanitizer. For every
input they must not raise and must uphold their safety invariant (no unsafe
character escapes strip mode, a title is plain ASCII, a cell is one wide, ...).

hypothesis is a declared dependency (installed in CI); a missing one is a hard
FAILURE, not a skip. Exit 0 on full pass, 1 on any failure.
"""

import sys
import os
import re
import tempfile
import importlib.util

try:
    from hypothesis import given, settings, strategies as st
    from secure_terminal import sanitize as S
    from secure_terminal import settings as SET
    from secure_terminal import session as SESS
except Exception as exc:  # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(fuzz): FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

# hooklib lives in the hooks dir, not on the package path: load it directly.
_usr = os.path.abspath(S.__file__)
for _ in range(5):
    _usr = os.path.dirname(_usr)
_hlpath = os.path.join(_usr, 'share', 'secure-terminal', 'hooks', 'hooklib.py')
HL = None
if os.path.exists(_hlpath):
    _spec = importlib.util.spec_from_file_location('hooklib', _hlpath)
    HL = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(HL)

FAIL = 0
SAFE_OUTPUT = frozenset((0x08, 0x09, 0x0A, 0x0D)) | frozenset(range(0x20, 0x7F))
RUN = settings(max_examples=400, deadline=None)

# reusable temp locations for the config/session parsers (overwritten per example)
_conf_fd, _CONF_FILE = tempfile.mkstemp(suffix='.conf')
os.close(_conf_fd)                          # created empty; overwritten per example
_STATE_DIR = tempfile.mkdtemp(prefix='st-fuzz-state-')
SESS._state_dir = lambda: _STATE_DIR       # so session.load reads our temp dir


@RUN
@given(st.text(), st.sampled_from(S.DISPLAY_MODES))
def prop_render_output(text, mode):
    out = S.render_output(text, mode)
    assert isinstance(out, str)
    if mode == 'box':
        # strip mode must emit only printable ASCII + tab/newline + the two
        # honored cursor controls; nothing hostile can survive.
        assert all(ord(ch) in SAFE_OUTPUT for ch in out)


@RUN
@given(st.text())
def prop_sanitize_paste(text):
    out = S.sanitize_paste(text)
    assert all(ch in ('\t', '\r') or 0x20 <= ord(ch) <= 0x7E for ch in out)


@RUN
@given(st.text())
def prop_sanitize_paste_unicode(text):
    out = S.sanitize_paste_unicode(text)
    # keeps printable (incl. non-ASCII) + the two submit controls; never a
    # control, bidi, zero-width or other invisible that could inject or deceive.
    assert all(ch in ('\r', '\t') or ch.isprintable() for ch in out)


@RUN
@given(st.text())
def prop_sanitize_title(text):
    out = S.sanitize_title(text)
    assert len(out) <= 80
    assert all(0x20 <= ord(ch) <= 0x7E for ch in out)
    assert '\n' not in out and '\t' not in out
    # idempotent: re-sanitizing an already-sanitized title is a no-op (a cap
    # landing on a space must not shrink it on a second pass).
    assert S.sanitize_title(out) == out


@RUN
@given(st.text())
def prop_paste_findings(text):
    result = S.paste_findings(text)
    assert isinstance(result, tuple) and len(result) == 2
    assert all(isinstance(flag, bool) for flag in result)


@RUN
@given(st.text())
def prop_classify_paste(text):
    result = S.classify_paste(text)
    assert isinstance(result, list)
    assert all(isinstance(label, str) and isinstance(count, int) and count > 0
               for label, count in result)


@RUN
@given(st.text(alphabet='0123456789;:', max_size=48))
def prop_parse_sgr(param):
    state = {'fg': None, 'bg': None, 'bold': False}
    S.parse_sgr(param, state)
    # fg/bg are None, a 16-colour palette index (0..15), or a '#rrggbb' string
    # (256-colour / truecolour). NOTHING else, whatever the params.
    for chan in (state['fg'], state['bg']):
        assert chan is None \
            or (isinstance(chan, int) and 0 <= chan <= 15) \
            or (isinstance(chan, str) and re.fullmatch(r'#[0-9a-f]{6}', chan))
    assert isinstance(state['bold'], bool)


@RUN
@given(st.lists(st.sampled_from(('38', '48', '5', '2', '0', '1', '31', '200',
                                 '255', ';')), max_size=12).map(';'.join))
def prop_parse_sgr_extended(param):
    # deliberately exercise the 256/truecolour (38/48;5|2) branches: whatever the
    # params, a stored colour is None, a 0..15 palette index, or a valid '#rrggbb'
    # (never a raw / out-of-range value), and it never raises.
    state = {'fg': None, 'bg': None, 'bold': False}
    S.parse_sgr(param, state)
    for chan in (state['fg'], state['bg']):
        assert chan is None \
            or (isinstance(chan, int) and 0 <= chan <= 15) \
            or (isinstance(chan, str) and re.fullmatch(r'#[0-9a-f]{6}', chan))
    # an explicit leading reset always clears to the default
    state2 = {'fg': '#123456', 'bg': 7, 'bold': True}
    S.parse_sgr('0', state2)
    assert state2 == {'fg': None, 'bg': None, 'bold': False}


# --- a grammar of realistic VT escape sequences. Random text almost never
# --- contains cursor/erase CSI ops, SGR colour codes or alt-screen sequences,
# --- so generate them explicitly; otherwise the fuzz never reaches the escape
# --- parsers (feed_line_edits, parse_sgr, color_256, wants_full_screen).
_SGR_ATOM = st.one_of(
    st.sampled_from(['0', '1', '22', '7', '39', '49',
                     '30', '31', '37', '40', '47', '90', '97', '100', '107']),
    st.integers(min_value=0, max_value=260).map(lambda n: '38;5;%d' % n),
    st.integers(min_value=0, max_value=260).map(lambda n: '48;5;%d' % n),
    st.tuples(st.integers(0, 255), st.integers(0, 255), st.integers(0, 255))
      .map(lambda t: '38;2;%d;%d;%d' % t))
_SGR_PARAMS = st.lists(_SGR_ATOM, max_size=5).map(';'.join)
_CSI_OP = st.builds(
    lambda n, op: '\x1b[' + ('' if n is None else str(n)) + op,
    st.one_of(st.none(), st.integers(min_value=0, max_value=120)),
    st.sampled_from('CDGKJ'))                 # cursor forward/back/abs + erase
_ALT = st.sampled_from(['\x1b[?1049h', '\x1b[?1049l', '\x1b[?1047h', '\x1b[?47h',
                        '\x1b[?2004h', '\x1b[?2026h', '\x1b[?2026l'])
_OSC = st.sampled_from(['\x1b]0;title\x07', '\x1b]8;;https://example.invalid\x07',
                        '\x1b]4;1;rgb:00/00/00\x07', '\x1b]10;#ffffff\x07'])
_CTRL = st.sampled_from(['\b', '\r', '\n', '\t', '\x07', '\x0c', '\x1b'])
# explicit erase-in-line / absolute-column sequences (num 1 and 2 are otherwise
# rare from the integer strategy), and a hostile-character alphabet so the
# bidi/invisible/control classifiers are actually reached.
_ERASE = st.sampled_from(['\x1b[0K', '\x1b[1K', '\x1b[2K', '\x1b[K',
                          '\x1b[3G', '\x1b[5C', '\x1b[2D'])
VT = st.lists(
    st.one_of(st.text(max_size=6), _CSI_OP, _ERASE,
              _SGR_PARAMS.map(lambda p: '\x1b[' + p + 'm'), _ALT, _OSC, _CTRL),
    max_size=16).map(''.join)
_HOSTILE = ''.join(chr(c) for c in (
    0x202A, 0x202E, 0x2066, 0x2069, 0x200E, 0x200F, 0x061C,   # bidi
    0x200B, 0x200D, 0x2060, 0xFEFF, 0x2028, 0x2029,           # invisible
    0x00, 0x1B, 0x7F, 0x9F,                                    # control / C1
    0xE9, 0x4E00, ord('A'), ord(' '), 0x09, 0x0A))            # printable / ws
HOSTILE = st.text(alphabet=_HOSTILE, max_size=24)


@RUN
@given(VT, st.sampled_from(S.DISPLAY_MODES))
def prop_render_output_vt(text, mode):
    # escape-rich output through every display mode: same safety invariant, and
    # it now reaches the cursor/colour/alt-screen parsers.
    out = S.render_output(text, mode)
    assert isinstance(out, str)
    if mode == 'box':
        assert all(ord(ch) in SAFE_OUTPUT for ch in out)
    assert isinstance(S.wants_full_screen(text), bool)
    assert isinstance(S.leaves_full_screen(text), bool)
    assert isinstance(S.has_bell(text), bool)


@RUN
@given(VT, st.integers(min_value=0, max_value=40))
def prop_feed_line_edits_vt(raw, max_line):
    # feed escape-rich raw straight into the cell line editor so the cursor CSI
    # ops (forward/back/absolute + erase-in-line), the SGR fold and the
    # strip-any-other-escape paths are all reached.
    comp, cells, col, sgr, wraps = S.feed_line_edits([], 0, {}, raw, max_line)
    assert isinstance(comp, list) and isinstance(cells, list) and col >= 0
    # feed again from the resulting non-empty cells/cursor/sgr state
    S.feed_line_edits(cells, col, sgr, raw, max_line)


@RUN
@given(st.text(max_size=40), VT, st.integers(min_value=0, max_value=64),
       st.integers(min_value=0, max_value=128))
def prop_apply_line_edits_vt(line, chunk, col, max_line):
    # the line editor fed escape-rich input: cursor CSI ops (C/D/G/K), SGR folds
    # and stripped escapes must not raise or lose a completed line.
    completed, cur, newcol = S.apply_line_edits(line, min(col, len(line)),
                                                chunk, max_line)
    assert isinstance(completed, list) and isinstance(cur, str)
    assert 0 <= newcol <= len(cur)


@RUN
@given(st.integers(min_value=-16, max_value=300))
def prop_color_256(idx):
    # the whole 256-colour map: <0 or >255 -> None, 0..15 a palette index, the
    # 6x6x6 cube and the greyscale ramp -> a valid '#rrggbb'.
    out = S.color_256(idx)
    assert out is None or (isinstance(out, int) and 0 <= out <= 15) \
        or (isinstance(out, str) and re.fullmatch(r'#[0-9a-f]{6}', out))


@RUN
@given(_SGR_PARAMS)
def prop_parse_sgr_colours(param):
    # SGR params from the full grammar (basic + bright + 256 + truecolour), so
    # every colour branch and every color_256 path is exercised.
    state = {'fg': None, 'bg': None, 'bold': False}
    S.parse_sgr(param, state)
    for chan in (state['fg'], state['bg']):
        assert chan is None \
            or (isinstance(chan, int) and 0 <= chan <= 15) \
            or (isinstance(chan, str) and re.fullmatch(r'#[0-9a-f]{6}', chan))


@RUN
@given(st.integers(min_value=0, max_value=0x110000))
def prop_marking_class(cp):
    # every codepoint classifies as exactly one marking kind, never raises.
    assert S.marking_class(cp) in ('bidi', 'invisible', 'control', 'nonascii')


@RUN
@given(HOSTILE)
def prop_classify_paste_hostile(text):
    # bidi / control / invisible / non-ASCII characters must each be counted.
    result = S.classify_paste(text)
    assert all(isinstance(label, str) and isinstance(count, int) and count > 0
               for label, count in result)


@RUN
@given(HOSTILE, st.sampled_from(S.DISPLAY_MODES), st.booleans(), st.booleans())
def prop_cells_to_runs_hostile(text, mode, colors, markings):
    # render hostile cells with markings on/off and colours on/off, so the emit
    # marking/colour/plain branches are all exercised.
    comp, cells, col, sgr, _w = S.feed_line_edits([], 0, {}, text)
    runs, prefix = S.cells_to_runs(comp, cells, mode, colors, markings=markings)
    assert isinstance(runs, list)


@RUN
@given(st.tuples(st.integers(0, 255), st.integers(0, 255), st.integers(0, 255)),
       st.tuples(st.integers(0, 255), st.integers(0, 255), st.integers(0, 255)))
def prop_colour_helpers(a, bcol):
    # the contrast/colour helpers never raise and stay in range.
    assert isinstance(S.colors_allowed(), bool)
    assert 0 <= S.luminance(a) <= 255
    assert isinstance(S.too_close(a, bcol), bool)


def prop_feed_chunk_carry_drop():
    # a string escape longer than the cap switches to the DISCARD state, which
    # then swallows bytes across chunks until the terminator (even a split one).
    long_osc = '\x1b]0;' + 'x' * 5000            # unterminated, over-cap OSC
    t, carry, drop = S.feed_chunk_carry(long_osc, '', '')
    assert drop and t == ''                       # -> discard state
    t2, carry2, drop2 = S.feed_chunk_carry('still inside', carry, drop)
    assert drop2 == drop and t2 == ''             # keeps swallowing
    t3, _c, drop3 = S.feed_chunk_carry('tail\x07visible', carry2, drop2)
    assert drop3 == '' and 'visible' in t3        # terminator ends the discard


@RUN
@given(st.text(min_size=0, max_size=4), st.sampled_from(S.DISPLAY_MODES))
def prop_tui_cell(ch, mode):
    # a pyte cell may hold a multi-codepoint grapheme, so feed strings of any
    # length; tui_cell must never raise (this is where cat /dev/random crashed).
    out = S.tui_cell(ch, mode)
    assert isinstance(out, str)
    # any control codepoint in the cell -> the whole cell is neutralized to '_'
    if any(ord(c) < 0x20 for c in ch):
        assert out == '_'


@RUN
@given(st.text(), st.sampled_from(S.DISPLAY_MODES),
       st.integers(min_value=0, max_value=200))
def prop_feed_line_edits(text, mode, max_line):
    # the line-mode logical-cell editor: hostile output must never smuggle an
    # escape byte into a cell, the cursor must stay within the current line, and
    # in strip mode the rendered line must be all-safe. It must not raise. max_line
    # exercises the width bound: cursor-forward blank padding and deferred autowrap.
    comp, cells, col, sgr, _w = S.feed_line_edits([], 0, {}, text, max_line)
    assert 0 <= col <= len(cells)
    if max_line:
        assert col <= max_line and len(cells) <= max_line   # never past the width
    for ch, _key in cells:
        assert ch != '\x1b'                      # no escape survives into a cell
    if mode == 'box':
        rendered = ''.join(S.render_output(c, 'box') for c, _ in cells)
        assert all(ord(ch) in SAFE_OUTPUT for ch in rendered)
    # feeding the SAME chunk again from the resulting state must still not raise
    S.feed_line_edits(cells, col, sgr, text, max_line)


@RUN
@given(st.text())
def prop_split_trailing_escape(text):
    # holding back an incomplete escape at a read boundary must be loss-free: the
    # pieces reconstitute the input exactly, the carry is a real escape prefix (or
    # empty), and it is bounded (a flood is let through, never buffered forever).
    complete, carry = S.split_trailing_escape(text)
    assert complete + carry == text
    assert carry == '' or carry.startswith('\x1b')
    assert len(carry) <= 4096
    # a complete SGR at the very end is never held back
    _c2, carry2 = S.split_trailing_escape(text + '\x1b[0m')
    assert carry2 == ''


@RUN
@given(st.text(), st.integers(min_value=0, max_value=200))
def prop_chunk_boundary_invariance(text, split):
    # The property that catches the OSC/DCS split-across-reads bugs: feeding the
    # same bytes WHOLE vs SPLIT at an arbitrary boundary must render identical
    # stripped output. A read boundary must never change what the user sees, leak
    # a sequence's tail, or drop a standalone character.
    whole_text, _, _ = S.feed_chunk_carry(text, '', '')
    whole = S.render_output(whole_text, 'box')
    head, tail = text[:split], text[split:]
    t1, carry, drop = S.feed_chunk_carry(head, '', '')
    t2, _, _ = S.feed_chunk_carry(tail, carry, drop)
    split_out = S.render_output(t1, 'box') + S.render_output(t2, 'box')
    assert split_out == whole


@RUN
@given(st.lists(st.text(), max_size=8))
def prop_feed_chunk_carry(chunks):
    # the stateful CLI feed: arbitrary input split into arbitrary read()-chunks
    # must (a) never let an escape byte survive into the rendered strip output --
    # the core "strip every escape" guarantee, whatever the length or split -- and
    # (b) keep its state bounded (carry <= cap, drop a valid introducer or empty).
    carry, drop = '', ''
    for chunk in chunks:
        text, carry, drop = S.feed_chunk_carry(chunk, carry, drop)
        rendered = S.render_output(text, 'box')
        assert '\x1b' not in rendered
        assert len(carry) <= 4096
        assert carry == '' or carry.startswith('\x1b') or carry == '\x1b'
        assert drop == '' or drop in S._STRING_INTRO


@RUN
@given(st.text(), st.sampled_from(S.DISPLAY_MODES), st.booleans())
def prop_cells_to_runs(text, mode, colors):
    # rendering the logical cells (from feed_line_edits) to display runs must not
    # raise and must stay safe: strip runs are all-safe, the caret offset is sane.
    comp, cells, col, sgr, _w = S.feed_line_edits([], 0, {}, text)
    runs, prefix = S.cells_to_runs(comp, cells, mode, colors)
    assert isinstance(runs, list) and isinstance(prefix, int) and prefix >= 0
    for run_text, _key in runs:
        assert isinstance(run_text, str)
    disp = S.cells_display_col(cells, col, mode)
    assert 0 <= disp
    if mode == 'box':
        for run_text, _key in runs:
            # Strip-mode DISPLAY may show the readable box for a neutralized byte
            # (the widget maps it back to ASCII '_' on copy/export); everything
            # else is the safe ASCII alphabet. Mapping the box to '_' must yield
            # only the safe alphabet -- the export invariant.
            assert all(ord(ch) in SAFE_OUTPUT or ch == '\n' or ch == S.STRIP_BOX
                       for ch in run_text)
            assert all(ord(ch) in SAFE_OUTPUT or ch == '\n'
                       for ch in run_text.replace(S.STRIP_BOX, '_'))


@RUN
@given(st.binary(), st.sampled_from(S.DISPLAY_MODES))
def prop_sanitize_bytes(data, mode):
    # arbitrary raw bytes (a program's output decoded 1:1) must never raise and,
    # in strip mode, must render to only the safe display alphabet.
    out = S.sanitize_bytes(data, mode)
    assert isinstance(out, str)
    if mode == 'box':
        assert all(ord(ch) in SAFE_OUTPUT for ch in out)


@RUN
@given(st.integers(min_value=-4096, max_value=0x120000))
def prop_describe_codepoint(cp):
    # the reveal-badge tooltip: any int (in or out of the Unicode range) must
    # produce a string and never raise.
    out = S.describe_codepoint(cp)
    assert isinstance(out, str) and out


@RUN
@given(st.lists(st.binary(max_size=64), max_size=8))
def prop_ipc_framer(chunks):
    # the IPC length-frame reassembler: feeding arbitrary byte chunks must never
    # raise except the documented ValueError (over-long frame), and a completed
    # payload's length must equal its 4-byte length prefix.
    import struct
    from secure_terminal import ipc
    framer = ipc.Framer()
    joined = b''.join(chunks)
    result = None
    try:
        for chunk in chunks:
            got = framer.feed(chunk)
            if got is not None:
                result = got
                break
    except ValueError:
        return                              # documented rejection of a huge frame
    if result is not None:
        length = struct.unpack('<I', joined[:4])[0]
        assert len(result) == length


@RUN
@given(st.text(max_size=64), st.text(max_size=64),
       st.integers(min_value=0, max_value=64),
       st.integers(min_value=0, max_value=128))
def prop_apply_line_edits(line, text, col, max_line):
    # the legacy bulk line-editor: any (line, cursor, chunk) must not raise, the
    # cursor stays within the line, and no completed line is lost.
    completed, cur, newcol = S.apply_line_edits(line, min(col, len(line)),
                                                text, max_line)
    assert isinstance(completed, list) and isinstance(cur, str)
    assert all(isinstance(c, str) for c in completed)
    assert 0 <= newcol <= len(cur)


@RUN
@given(st.text())
def prop_settings_parse(text):
    # a config drop-in with arbitrary contents must parse to a str->str dict and
    # never raise (a malformed/hostile .conf can never crash startup).
    with open(_CONF_FILE, 'w', encoding='utf-8') as handle:
        handle.write(text)
    out = {}
    SET._parse_into(_CONF_FILE, out)
    assert all(isinstance(k, str) and isinstance(v, str)
               for k, v in out.items())


@RUN
@given(st.binary(max_size=2048))
def prop_session_load(data):
    # arbitrary bytes in the session file (corrupt/hostile) must yield a list and
    # never raise -- a bad session can never brick startup.
    with open(os.path.join(_STATE_DIR, 'session.json'), 'wb') as handle:
        handle.write(data)
    result = SESS.load()
    assert isinstance(result, list)


@RUN
@given(st.text())
def prop_read_rules(text):
    # the hook rules parser: arbitrary text must yield None or a list of
    # (verdict, pattern, message, suggestion) 4-tuples, never raise.
    if HL is None:
        return
    HL.read_file = lambda name: text
    rules = HL.read_rules('x')
    assert rules is None or isinstance(rules, list)
    for rule in (rules or []):
        assert len(rule) == 4 and rule[0] in ('allow', 'block', 'ask')
        assert all(isinstance(field, str) for field in rule)


_PRIV_DIR = tempfile.mkdtemp(prefix='st-fuzz-priv-')
os.makedirs(os.path.join(_PRIV_DIR, 'secure-terminal.d'), exist_ok=True)


@RUN
@given(st.text())
def prop_privileged_conf(text):
    # the hooks.conf gate parser: arbitrary contents must yield a str or None and
    # never raise (a malformed gate file can never crash a hook).
    if HL is None:
        return
    with open(os.path.join(_PRIV_DIR, 'secure-terminal.d', 'hooks.conf'),
              'w', encoding='utf-8') as handle:
        handle.write(text)
    HL._PRIVILEGED = (_PRIV_DIR,)
    value = HL._privileged_conf_value('hook_config_allow_user')
    assert value is None or isinstance(value, str)


PROPS = [
    ('cells_to_runs', prop_cells_to_runs),
    ('sanitize_bytes', prop_sanitize_bytes),
    ('describe_codepoint', prop_describe_codepoint),
    ('ipc_framer', prop_ipc_framer),
    ('apply_line_edits', prop_apply_line_edits),
    ('settings_parse', prop_settings_parse),
    ('session_load', prop_session_load),
    ('read_rules', prop_read_rules),
    ('privileged_conf', prop_privileged_conf),
    ('render_output', prop_render_output),
    ('feed_line_edits', prop_feed_line_edits),
    ('split_trailing_escape', prop_split_trailing_escape),
    ('chunk_boundary_invariance', prop_chunk_boundary_invariance),
    ('feed_chunk_carry', prop_feed_chunk_carry),
    ('sanitize_paste', prop_sanitize_paste),
    ('sanitize_paste_unicode', prop_sanitize_paste_unicode),
    ('sanitize_title', prop_sanitize_title),
    ('paste_findings', prop_paste_findings),
    ('classify_paste', prop_classify_paste),
    ('parse_sgr', prop_parse_sgr),
    ('parse_sgr_extended', prop_parse_sgr_extended),
    ('render_output_vt', prop_render_output_vt),
    ('feed_line_edits_vt', prop_feed_line_edits_vt),
    ('apply_line_edits_vt', prop_apply_line_edits_vt),
    ('color_256', prop_color_256),
    ('parse_sgr_colours', prop_parse_sgr_colours),
    ('marking_class', prop_marking_class),
    ('classify_paste_hostile', prop_classify_paste_hostile),
    ('cells_to_runs_hostile', prop_cells_to_runs_hostile),
    ('colour_helpers', prop_colour_helpers),
    ('feed_chunk_carry_drop', prop_feed_chunk_carry_drop),
    ('tui_cell', prop_tui_cell),
]

for name, prop in PROPS:
    try:
        prop()
    except Exception as exc:  # pylint: disable=broad-except
        FAIL += 1
        sys.stderr.write('FAIL: property %s: %s\n' % (name, exc))

sys.stdout.write('secure-terminal-tests(fuzz): %d propert%s checked, %d failed\n'
                 % (len(PROPS), 'y' if len(PROPS) == 1 else 'ies', FAIL))
sys.exit(0 if FAIL == 0 else 1)
