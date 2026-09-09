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


# is_baseline oracle (shared by the reset sweep, INV-7 and the T10 formal check): a fresh
# screen reads baseline; any single leaked dimension reads non-baseline; CLI keys only on
# mouse/palette/pen.
_fresh_snap = sd.collect(pyte.HistoryScreen(10, 3, history=10), mode='tui', columns=10,
                         alt_screen=False, saved_primary=None, mouse_modes=set(),
                         palette={}, title='')
ok(sd.is_baseline(_fresh_snap), 'is_baseline: a fresh screen with no wrapper state is baseline')
ok(not sd.is_baseline(dict(_fresh_snap, mouse_modes=[1000])),
   'is_baseline: a leaked mouse mode is non-baseline')
ok(not sd.is_baseline(dict(_fresh_snap, palette_overrides={'1': '#ff0000'})),
   'is_baseline: a leaked palette override is non-baseline')
_hidden = pyte.HistoryScreen(10, 3, history=10)
pyte.Stream(_hidden).feed('\x1b[?25l')             # hide the cursor (DECTCEM)
ok(not sd.is_baseline(sd.collect(_hidden, mode='tui', columns=10, alt_screen=False,
                                 saved_primary=None, mouse_modes=set(), palette={}, title='')),
   'is_baseline: a hidden cursor (DECTCEM) is non-baseline')
ok(sd.is_baseline({'mode': 'cli', 'mouse_modes': [], 'palette_overrides': {}, 'pen': {}}),
   'is_baseline: a CLI dump with no mouse/palette/pen is baseline')
ok(not sd.is_baseline({'mode': 'cli', 'mouse_modes': [], 'palette_overrides': {},
                       'pen': {'bold': True}}),
   'is_baseline: a CLI dump with a non-default pen is non-baseline')


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

# --- 3. Committed golden dumps ------------------------------------------------------
# A curated, review-readable set of dumps (synthetic pyte screens, deterministic + grid-
# geometry independent) is committed under state-dumps/; drift fails loud. state_dump_goldens
# single-sources the scenarios so the test and the regenerator cannot diverge.
import os                                          # noqa: E402
from state_dump_goldens import SCENARIOS as _GOLDENS   # noqa: E402

_GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'state-dumps')
for _gname, _gbuild in sorted(_GOLDENS.items()):
    _gpath = os.path.join(_GOLDEN_DIR, _gname)
    _committed = ''
    _present = os.path.exists(_gpath)
    if _present:
        with open(_gpath, encoding='utf-8') as _gh:
            _committed = _gh.read()
    ok(_present and _committed == _gbuild(),
       "committed golden %s matches (regenerate if intended: python3 -c "
       "'import state_dump_goldens as g; g.write_all()')" % _gname)


# --- 4. Reset-to-prompt baseline (the fix): nothing leaks except scrollback ----------
# Property under test: after a foreground program exits (the fg-edge in _read_and_render)
# OR a restart_as_shell, the terminal returns to ONE canonical clean baseline -- no leaked
# mouse tracking, charset, scroll region, palette, SGR, hidden cursor or stray DEC mode.
# _reset_vt_to_prompt_baseline() is the single shared reset both call; dump_state is the
# oracle. (Fixes the exit-vs-restart reset asymmetry, plus two restart bugs: the scroll
# region was never reset, and a direct screen.mode assignment left cursor.hidden stuck.)
from test_fuzz_harnesses import _repo_root as _st_root, _load_seeds as _st_seeds  # noqa: E402

# sd.is_baseline is the shared clean-baseline oracle (also used by INV-7 + the T10 formal
# check), so 'clean' is defined once against the dump schema, not re-spelled per suite.

# A payload arming every leak-prone bit the widget tracks (mouse, hidden cursor, bracketed
# paste, origin mode, DEC special-graphics G0, scroll region, OSC-4 palette, stuck SGR).
_ARM = (b'\x1b[?1000h\x1b[?1006h'     # mouse: button-track + sgr-ext
        b'\x1b[?25l'                   # hide cursor (DECTCEM)
        b'\x1b[?2004h'                 # bracketed paste (DEC 2004)
        b'\x1b[?6h'                    # origin mode (DECOM)
        b'\x1b(0'                      # G0 -> DEC special graphics
        b'\x1b[2;10r'                  # scroll region (DECSTBM)
        b'\x1b]4;1;#ff0000\x07'        # OSC 4 palette override (needs osc_colors on)
        b'\x1b[1;31mSTUCK')            # bold red SGR, left stuck


def _arm_terminal(tui):
    term = SecureTerminal(command='/bin/cat', tui=tui)
    term._osc['osc_colors'] = True               # so OSC 4/10/11/12 palette is tracked
    APP.processEvents()
    feed_output(term, _ARM)
    if tui:
        term._render_tui()
    APP.processEvents()
    return term


# Canary: the arm payload MUST reach non-baseline state, else the resets below prove nothing.
_ct = _arm_terminal(True)
_armed = _json.loads(_ct.dump_state('json'))
ok(_armed['mouse_modes'] == [1000, 1006]
   and _armed['palette_overrides'].get('1') == '#ff0000'
   and _armed['cursor']['visible'] is False
   and _armed['scroll_region'] is not None
   and _armed['charset']['g0'] != 'LAT1'
   and 'BRACKETED_PASTE' in _armed['dec_modes'],
   'canary: the arm payload set mouse/palette/hidden-cursor/scroll/charset/paste (armed)')

# Direct helper: clears every armed bit to the baseline, scrollback untouched.
_before_doc = _json.loads(_ct.dump_state('json'))['rows']
_ct._reset_vt_to_prompt_baseline()
_reset = _json.loads(_ct.dump_state('json'))
ok(sd.is_baseline(_reset) and _reset['alt_screen'] is False,
   'TUI: _reset_vt_to_prompt_baseline clears every armed VT bit to the clean baseline')
ok(_reset['rows'] == _before_doc,
   'reset preserves the grid/scrollback content (only VT state changes, not the buffer)')
_ct.close()

# restart_as_shell lands the SAME baseline, and specifically fixes the two regressions.
_rs = _arm_terminal(True)
_rs.restart_as_shell()
APP.processEvents()
_ra = _json.loads(_rs.dump_state('json'))
ok(_ra['scroll_region'] is None,
   'restart_as_shell resets the scroll region (regression: margins were never reset)')
ok(_ra['cursor']['visible'] is True,
   'restart_as_shell shows the cursor (regression: direct mode-set left cursor.hidden)')
ok(sd.is_baseline(_ra),
   'restart_as_shell lands the same clean baseline as the fg-exit edge')
_rs.close()

# The ordinary-exit fg-edge (in _read_and_render) calls the same reset when the foreground
# program exits and the shell prompt returns. Drive the True->False edge deterministically.
_fe = _arm_terminal(True)
_fe._bracket_had_fg = True                        # a foreground program was present
_fe.has_foreground_program = lambda: False        # ... and has now exited (prompt returning)
feed_output(_fe, b'\r\nplain-prompt$ ')           # neutral prompt bytes (re-arm nothing)
_fe._render_tui()
APP.processEvents()
_fo = _json.loads(_fe.dump_state('json'))
ok(sd.is_baseline(_fo) and _fo['alt_screen'] is False,
   'ordinary-exit fg-edge restores the clean baseline (nothing leaks into the prompt)')
_fe.close()

# fg-edge where the EXITED program held the alt screen: alt-leave restores the primary
# (owner gone, not a suspended app) AND the baseline reset runs -- both on the one edge.
_fa = _arm_terminal(True)
feed_output(_fa, b'\x1b[?1049hALTFRAME')          # enter the alt screen
_fa._render_tui()
APP.processEvents()
_fa._bracket_had_fg = True
_fa._alt_owner_pgrp = None                        # unknown owner -> treated as dead (gone)
_fa.has_foreground_program = lambda: False        # program exited, prompt returning
feed_output(_fa, b'\r\nplain-prompt$ ')
_fa._render_tui()
APP.processEvents()
_fa_snap = _json.loads(_fa.dump_state('json'))
ok(_fa_snap['alt_screen'] is False and sd.is_baseline(_fa_snap),
   'fg-edge with alt held: alt-leave restores the primary AND the reset lands baseline')
_fa.close()

# Extended leak dimensions the reset also clears: tab stops (TBC), a DECSC savepoint (ESC 7
# -- a later ESC 8 would re-select the saved charset/DECOM), and a DECCOLM (?3h) grid width
# (the bare mode reassignment drops the bit but not the 132-column width).
_dim = _arm_terminal(True)
feed_output(_dim, b'\x1b[3g'           # clear every tab stop
                  b'\x1b(0\x1b7'        # G0 special-graphics, then DECSC saves it
                  b'\x1b[?3h')          # DECCOLM -> 132 columns
_dim._render_tui()
APP.processEvents()
ok(_dim._screen.saved_columns is not None and len(_dim._screen.savepoints) > 0
   and _dim._screen.tabstops != set(range(8, _dim._screen.columns, 8)),
   'canary: tab-clear + DECSC savepoint + DECCOLM armed on the screen')
_dim_prev_cols = _dim._screen.saved_columns
_dim._reset_vt_to_prompt_baseline()
ok(_json.loads(_dim.dump_state('json'))['tabstops'] == 'default'
   and len(_dim._screen.savepoints) == 0
   and _dim._screen.saved_columns is None
   and _dim._screen.columns == _dim_prev_cols,
   'reset restores tab stops, clears DECSC savepoints, and undoes the DECCOLM width')
_dim.close()

# finding: a Ctrl-Z SUSPENDED program (its alt owner still ALIVE) keeps its held frame AND
# its modes for resume -- the fg-edge reset is gated on _alt_owner_dead(), so a live owner
# is left untouched (only a program that truly exited is baselined).
_sus = SecureTerminal(command='/bin/cat', tui=True)
APP.processEvents()
feed_output(_sus, b'\x1b[?1049hALT\x1b[?1000h')    # enter alt + arm mouse tracking (1000 only)
_sus._render_tui()
APP.processEvents()
_sus._alt_owner_pgrp = os.getpgrp()                # a LIVE pgrp -> _alt_owner_dead() is False
_sus._bracket_had_fg = True
_sus.has_foreground_program = lambda: False        # shell has the tty (suspended), owner alive
feed_output(_sus, b'more output')
_sus._render_tui()
APP.processEvents()
_sus_snap = _json.loads(_sus.dump_state('json'))
ok(_sus_snap['alt_screen'] is True and _sus_snap['mouse_modes'] == [1000],
   'a suspended program (live owner) keeps its alt frame and mouse modes -- NOT reset')
_sus.close()

# finding: a mouse DECSET and the fg-exit in ONE coalesced read. The reset runs AFTER the
# chunk is fed, so scan_mouse_modes re-arming mouse from that same chunk cannot survive it
# (a pre-feed reset would clear then be re-armed, leaking an input channel to the prompt).
_sr = _arm_terminal(True)
_sr._reset_vt_to_prompt_baseline()                 # start from a clean baseline
_sr._bracket_had_fg = True
_sr.has_foreground_program = lambda: False
feed_output(_sr, b'\x1b[?1000h\x1b[?1006htail before exit')   # re-arm mouse in the exit read
_sr._render_tui()
APP.processEvents()
ok(sd.is_baseline(_json.loads(_sr.dump_state('json'))),
   'a mouse DECSET in the same read as the fg-exit does not survive the post-feed reset')
_sr.close()

# Full-corpus sweep: EVERY shared fuzz seed, in BOTH modes, must land the baseline after a
# reset -- the reset is total against the whole adversarial corpus, not just the armed bits.
_seeds = _st_seeds(os.path.join(_st_root(), 'fuzz', 'corpus', 'seeds.txt'))
ok(len(_seeds) >= 100, 'reset sweep loaded the shared seed corpus (%d seeds)' % len(_seeds))
_sweep_fail = None
for _tui in (True, False):
    _sw = SecureTerminal(command='/bin/cat', tui=_tui)
    _sw._osc['osc_colors'] = True
    APP.processEvents()
    for _sname, _blob in _seeds:
        feed_output(_sw, _blob)
        if _tui:
            _sw._render_tui()
        _sw._reset_vt_to_prompt_baseline()
        if not sd.is_baseline(_json.loads(_sw.dump_state('json'))):
            _sweep_fail = (_sname, 'tui' if _tui else 'cli')
            break
    _sw.close()
    if _sweep_fail:
        break
ok(_sweep_fail is None,
   'reset sweep: every seed x mode lands the baseline (first offender: %r)' % (_sweep_fail,))


finish('state_dump')
