#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Tests for the deterministic terminal-state dump (secure_terminal.state_dump +
SecureTerminal.dump_state). Two layers:

  1. Pure state_dump functions over a synthetic pyte screen (no widget) -- the format,
     determinism, mode-name mapping, and the blank-cell/row elision (incl. the
     coloured-space canary: an elision must drop only truly-default cells).
  2. The live widget path: dump_state in TUI vs CLI mode and across an alternate-screen
     enter/leave, driven with the shared feed_output harness; plus the IPC frame-safety
     helper _fit_dump_reply.

Uses the shared widget harness (feed_output, ok/eq, finish, SecureTerminal) so it gets
the headless-Wayland setup, PyQt6 import-or-fail, and pty cleanup for free.
"""

from test_widget_common import *   # noqa: F401,F403  (shared harness)

import json as _json
import pyte

from secure_terminal import state_dump as sd
from secure_terminal.main import _fit_dump_reply
from secure_terminal import ipc as _ipc
from secure_terminal.terminal import _BRACKETED_PASTE_MODE as _BPM  # noqa: F401


def _synthetic_screen(cols=20, lines=5):
    s = pyte.HistoryScreen(cols, lines, history=50)
    pyte.Stream(s).feed(
        'hi \x1b[1;31mERR\x1b[0m ok\r\n'      # row 0: red bold ERR run
        '\x1b[44m   \x1b[0m done')            # row 1: blue-bg spaces (coloured blanks)
    return s


# --- 1. Pure state_dump ------------------------------------------------------------
_s = _synthetic_screen()
_snap = sd.collect(_s, mode='tui', columns=20, alt_screen=False, saved_primary=None,
                   mouse_modes={1000, 1006}, title='vim')
_text = sd.dump_text(_snap)
_jobj = _json.loads(sd.dump_json(_snap))

ok(_text.startswith('# secure-terminal state dump v%d' % sd.FORMAT_VERSION),
   'dump_text is headed and versioned')
ok('fg=red' in _text and 'bold' in _text,
   'dump_text names the pyte model attributes of a coloured/bold run')
ok('1000 1006 (button-track sgr-ext)' in _text,
   'dump_text names mouse modes both numerically and by role')

# Determinism: an idle screen dumps byte-identically on repeat, text AND json.
_snap2 = sd.collect(_s, mode='tui', columns=20, alt_screen=False, saved_primary=None,
                    mouse_modes={1000, 1006}, title='vim')
ok(sd.dump_text(_snap2) == _text and sd.dump_json(_snap2) == sd.dump_json(_snap),
   'dump is deterministic: two idle dumps are byte-identical')

# Coloured-space CANARY: row 1 is spaces only, but bg=blue -> it is NOT default, so it
# must survive the blank-row/blank-cell elision (a naive rstrip would drop it).
_row1 = [r for r in _jobj['rows'] if r['y'] == 1]
ok(len(_row1) == 1 and any(run['attrs'].get('bg') == 'blue' for run in _row1[0]['runs']),
   'canary: a coloured space (bg set, glyph == space) survives cell/row elision')
# ... while a genuinely all-default row IS elided (row 2 was never written).
ok(all(r['y'] != 2 for r in _jobj['rows']),
   'a fully-default (never-written) row is elided from the dump')

# Mode-name mapping + cursor visibility from screen.mode.
_hid = pyte.HistoryScreen(10, 3, history=10)
pyte.Stream(_hid).feed('\x1b[?25l\x1b[?2004h')     # hide cursor + bracketed paste on
_hsnap = sd.collect(_hid, mode='tui', columns=10, alt_screen=False, saved_primary=None,
                    mouse_modes=set(), title='')
ok('DECTCEM' not in _hsnap['dec_modes'] and _hsnap['cursor']['visible'] is False,
   'hidden cursor (DECTCEM cleared) is reported as visible=false')
ok('BRACKETED_PASTE' in _hsnap['dec_modes'],
   'the widget bracketed-paste bit (2004<<5) is named, not left as a raw int')

# CLI-mode snapshot: no grid, a pen + document instead.
_csnap = sd.collect(None, mode='cli', columns=80, alt_screen=True, saved_primary=None,
                    mouse_modes=set(), title='',
                    cli_pen={'fg': 1, 'bg': None, 'bold': True}, document='a line')
_ctext = sd.dump_text(_csnap)
ok('mode: cli' in _ctext and 'a line' in _ctext and 'pen: fg=1 bold' in _ctext,
   'CLI-mode dump carries mode, document text and the SGR pen (int palette index kept)')
ok('alt-screen: yes' in _ctext,
   'alt-screen flag is reported in CLI mode too')


# --- 1b. Pure format edge branches (full coverage of the rendering paths) ----------
ok(sd._mode_name(999999) == 'mode:999999',
   'an unmapped mode int renders as mode:<n>, never crashes')
ok(sd._charset_id('x' * 256) == 'custom',
   'an unrecognized G0/G1 charset table is named custom')

# scroll region (margins) + an explicit, non-default tab-stop set.
_mar = pyte.HistoryScreen(20, 6, history=10)
pyte.Stream(_mar).feed('\x1b[2;4r')          # DECSTBM: top=1 bottom=3 (0-based)
_mar.tabstops = {3}
_msnap = sd.collect(_mar, mode='tui', columns=20, alt_screen=False, saved_primary=None,
                    mouse_modes=set(), title='')
_mtext = sd.dump_text(_msnap)
ok('scroll-region: top=1 bottom=3' in _mtext,
   'a set scroll region (DECSTBM) is dumped as top/bottom')
ok('tabstops: 3' in _mtext,
   'a non-default tab-stop set is dumped as an explicit column list')

# empty tab-stop set -> (none); and the saved-primary line when a primary is frozen.
_emp = pyte.HistoryScreen(10, 3, history=10)
_emp.tabstops = set()
_esnap = sd.collect(_emp, mode='tui', columns=10, alt_screen=True,
                    saved_primary=(10, 3), mouse_modes=set(), title='')
_etext = sd.dump_text(_esnap)
ok('tabstops: (none)' in _etext and 'saved-primary: 10x3' in _etext,
   'an empty tab-stop set reads (none); a frozen primary reports its size')

# _cli_pen variants: empty pen, and a bg-only pen with fg unset.
ok(sd._cli_pen(None) == {} and sd._cli_pen({'fg': None, 'bg': None, 'bold': False}) == {},
   'an empty / all-default CLI pen normalizes to no attributes')
_bgpen = sd.collect(None, mode='cli', columns=40, alt_screen=False, saved_primary=None,
                    mouse_modes={1002}, title='t',
                    cli_pen={'fg': None, 'bg': '#0000ff', 'bold': False}, document='x')
ok('pen: bg=#0000ff' in sd.dump_text(_bgpen),
   'a bg-only CLI pen (fg unset) dumps just the background')


# --- 1c. JSON size-budget truncation stays VALID JSON (ST ai-review regression) ----
# A large dump that exceeds a transport frame must be shrunk at the SNAPSHOT level
# (whole rows / document), never byte-sliced into an unparseable fragment.
_big = pyte.HistoryScreen(60, 40, history=10)
_bst = pyte.Stream(_big)
for _y in range(40):
    _bst.feed('\r\n')
    for _x in range(0, 60, 3):
        _bst.feed('\x1b[3%dmXYZ' % (_x % 8))     # non-coalescing colour runs
_bsnap = sd.collect(_big, mode='tui', columns=60, alt_screen=False, saved_primary=None,
                    mouse_modes=set(), title='big')
_full = sd.dump_json(_bsnap)
ok(len(_full.encode()) > 5000, 'the big grid json is large enough to force truncation')
# no-op budget: a budget above the size returns the dump unchanged.
ok(sd.dump_json(_bsnap, max_bytes=10_000_000) == _full,
   'a budget above the dump size leaves it unchanged')
# tight budget: TUI row-drop keeps it valid + records how many rows went.
_bounded = sd.dump_json(_bsnap, max_bytes=3000)
_bobj = _json.loads(_bounded)          # MUST parse -- the whole point of the fix
ok(len(_bounded.encode()) <= 3000 and _bobj.get('truncated_rows', 0) > 0,
   'an over-budget TUI json dump is row-truncated to valid JSON under the budget')
# canary: byte-slicing the SAME dump (the old _fit_dump_reply behaviour) is invalid JSON,
# which is exactly the bug structural truncation avoids.
_sliced_ok = True
try:
    _json.loads(_full.encode()[:3000])
except ValueError:
    _sliced_ok = False
ok(not _sliced_ok,
   'canary: byte-slicing a json dump yields invalid JSON -- structural truncation required')
# CLI document truncation path stays valid too.
_cbudget = sd.collect(None, mode='cli', columns=80, alt_screen=False, saved_primary=None,
                      mouse_modes=set(), title='', cli_pen={}, document='D' * 20000)
_ctrunc = sd.dump_json(_cbudget, max_bytes=2000)
_cobj = _json.loads(_ctrunc)
ok(len(_ctrunc.encode()) <= 2000 and _cobj.get('document_truncated') is True,
   'an over-budget CLI json dump truncates the document to valid JSON under the budget')
# CLI truncation must keep the TAIL (the current screen), like the text path -- not the
# oldest prefix. (ST ai-review finding 1.)
_tailsnap = sd.collect(None, mode='cli', columns=80, alt_screen=False, saved_primary=None,
                       mouse_modes=set(), title='', cli_pen={},
                       document=('old line\n' * 5000) + 'UNIQUE_TAIL_MARKER')
_tobj = _json.loads(sd.dump_json(_tailsnap, max_bytes=2000))
ok('UNIQUE_TAIL_MARKER' in _tobj['document'],
   'CLI json truncation keeps the live tail (current screen), not the oldest prefix')
# A field other than rows/document (a HTS-every-column tab-stop flood) must not leave the
# JSON over budget; it collapses to a count and the bound still holds. (ST ai-review #2.)
_floodrows = pyte.HistoryScreen(20, 3, history=5)
_flood = sd.collect(_floodrows, mode='tui', columns=20, alt_screen=False,
                    saved_primary=None, mouse_modes=set(), title='')
_flood['tabstops'] = list(range(65535))
_fobj = _json.loads(sd.dump_json(_flood, max_bytes=4000))    # must parse
ok(len(sd.dump_json(_flood, max_bytes=4000).encode()) <= 4000
   and str(_fobj.get('tabstops', '')).startswith('truncated('),
   'a tab-stop flood collapses to a count so the json budget still holds')
# Final backstop: an oversized field that is neither rows/document/tabstops (a huge title)
# still yields minimal VALID JSON under budget, marked truncated. (ST ai-review #2.)
_hugetitle = sd.collect(pyte.HistoryScreen(5, 2, history=2), mode='tui', columns=5,
                        alt_screen=False, saved_primary=None, mouse_modes=set(),
                        title='T' * 500000)
_hobj = _json.loads(sd.dump_json(_hugetitle, max_bytes=2000))
ok(len(sd.dump_json(_hugetitle, max_bytes=2000).encode()) <= 2000
   and _hobj.get('truncated') is True,
   'an un-shrinkable oversized field falls back to minimal valid JSON under budget')


# --- 2. Live widget path -----------------------------------------------------------
# TUI mode: the full pyte grid dumps with per-cell attributes.
_tui = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
feed_output(_tui, b'plain\r\n\x1b[1;31mRED\x1b[0m tail')
_tui._render_tui()
APP.processEvents()
_d1 = _tui.dump_state('text')
ok(_d1.startswith('# secure-terminal state dump') and 'mode: tui' in _d1,
   'dump_state(text) on a TUI tab is a headed tui dump')
ok('RED' in _d1 and 'fg=red' in _d1,
   'a TUI tab dump carries the coloured run text + attributes')
ok(_tui.dump_state('text') == _d1,
   'dump_state on an idle TUI tab is deterministic')
ok(_json.loads(_tui.dump_state('json')).get('version') == sd.FORMAT_VERSION,
   'dump_state(json) on a TUI tab is parseable')

# Alt-screen: the flag flips on enter and back on leave (answers the cat-enables-alt
# question: alt-screen is a dumped variable, not lost).
feed_output(_tui, b'\x1b[?1049hALTGRID')
_tui._render_tui()
APP.processEvents()
_da = _tui.dump_state('text')
ok('alt-screen: yes' in _da and 'ALTGRID' in _da,
   'in the alternate screen the dump reports alt-screen: yes and the live alt grid')
feed_output(_tui, b'\x1b[?1049l')
_tui._render_tui()
APP.processEvents()
ok('alt-screen: no' in _tui.dump_state('text'),
   'after the program leaves the alternate screen the dump reports alt-screen: no')
_tui.close()

# A frozen primary is held across a TUI->CLI switch (apply_tui does not leave the alt
# screen), so a CLI dump must still report saved-primary, not null. (ST ai-review #3.)
_sw = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
feed_output(_sw, b'PRIMARY\r\n\x1b[?1049hALT')          # enter alt -> _alt_saved set
_sw._render_tui()
APP.processEvents()
if not _sw._grid_mode():                                 # pragma: no cover - tui was requested
    ok(False, 'setup: _sw should be in TUI mode after tui=True')
_sw.apply_tui(False)                                     # switch to CLI while alt still held
APP.processEvents()
# The switch must take effect for this to exercise the CLI branch (the regression: old
# code returned saved_primary null there). Fail loud if it did not, rather than pass
# vacuously in TUI mode where saved_primary was non-null on the old code too.
ok(not _sw._grid_mode() and _sw._alt_saved is not None,
   'setup: the tab is now in CLI mode with the alt primary still held')
_swobj = _json.loads(_sw.dump_state('json'))
ok(_swobj['alt_screen'] is True and _swobj['saved_primary'] is not None,
   'a TUI->CLI switch with alt held still reports saved_primary in the dump')
_sw.close()

# CLI (line) mode: no pyte grid; the dump is the line document + pen.
_cli = SecureTerminal(command='/bin/cat')
APP.processEvents()
feed_output(_cli, b'hello cli world\r\n')
APP.processEvents()
_dc = _cli.dump_state('text')
ok('mode: cli' in _dc and 'hello cli world' in _dc,
   'dump_state on a CLI tab reports cli mode and the line document')
ok(_cli.dump_state('text') == _dc,
   'dump_state on an idle CLI tab is deterministic')
_cli.close()

# IPC frame safety: a huge grid dump, after _fit_dump_reply, always fits the frame cap
# (else the client silently drops the reply). Build a payload larger than the cap.
_big = 'x' * (_ipc._MAX_REQUEST + 4096)
_fitted = _fit_dump_reply(_big)
ok(len(_json.dumps({'ok': True, 'text': _fitted}).encode('utf-8')) <= _ipc._MAX_REQUEST,
   '_fit_dump_reply trims an over-cap dump so its JSON frame fits the IPC limit')
# A non-ASCII payload (json.dumps expands each to a 6-byte escape) still fits.
_big_u = chr(0x2588) * _ipc._MAX_REQUEST     # U+2588 FULL BLOCK; no raw non-ASCII in source
ok(len(_json.dumps({'ok': True, 'text': _fit_dump_reply(_big_u)}).encode('utf-8'))
   <= _ipc._MAX_REQUEST,
   '_fit_dump_reply accounts for json ensure_ascii expansion of non-ASCII output')

finish('state_dump')
