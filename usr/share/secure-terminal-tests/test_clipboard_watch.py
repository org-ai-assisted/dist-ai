#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.clipboard_watch: the reusable ClipboardWatcher core,
## the standalone tray daemon (ClipboardWatchApp) and its SINGLETON IPC server, the
## autostart / warn-any helpers, and the deceptive/any-non-ASCII triggers. Driven
## offscreen. Fails closed (exit 1) when PyQt6 is unavailable -- a security-relevant
## suite must not skip. Source stays pure ASCII: deceptive fixtures are \\u escapes.

import builtins
import contextlib
import io
import json
import os
import signal
import struct
import sys
import tempfile
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtNetwork import QLocalSocket
    from secure_terminal import clipboard_watch as CW
    from secure_terminal import ipc
    from secure_terminal.sanitize import (
        sanitize_clipboard, sanitize_clipboard_unicode,
    )
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: %s\n' % exc)
    sys.exit(1)

APP = QApplication.instance() or QApplication([])

_failures = 0


def ok(cond, msg):
    global _failures
    if cond:
        print('ok   %s' % msg)
    else:
        _failures += 1
        print('FAIL: %s' % msg)


def eq(got, want, msg):
    ok(got == want, '%s (got %r, want %r)' % (msg, got, want))


ZWSP = '\u200b'     # zero-width space (invisible)
RLO = '\u202e'      # right-to-left override (bidi)
CYR_A = '\u0430'    # Cyrillic a -- a homoglyph posing as ASCII 'a'


class _FakeTray:
    """Stand-in for QSystemTrayIcon so the tray/run lifecycle is deterministic
    offscreen -- exercises every _build_tray line without a real desktop tray."""
    available = True

    @staticmethod
    def isSystemTrayAvailable():
        return _FakeTray.available

    def __init__(self, *_args):
        pass

    def setToolTip(self, *_args):
        pass

    def setContextMenu(self, *_args):
        pass

    def show(self):
        pass


def _test_predicates():
    ok(CW._deceptive('a' + ZWSP), 'deceptive: zero-width space')
    ok(CW._deceptive('a' + RLO + 'b'), 'deceptive: bidi override')
    ok(CW._deceptive('p' + CYR_A + 'ypal'), 'deceptive: homoglyph posing as ASCII')
    ok(not CW._deceptive('caf\u00e9'), 'not deceptive: an honest accent')
    ok(not CW._deceptive('\u65e5\u672c\u8a9e'), 'not deceptive: honest CJK')
    ok(not CW._deceptive(''), 'not deceptive: empty string')
    ok(CW._any_nonascii('caf\u00e9'), 'any-non-ascii: fires on an accent')
    ok(not CW._any_nonascii('plain ascii'), 'any-non-ascii: silent on ASCII')


def _test_autostart():
    with tempfile.TemporaryDirectory() as cfg:
        old = os.environ.get('XDG_CONFIG_HOME')
        os.environ['XDG_CONFIG_HOME'] = cfg
        try:
            path = CW._user_autostart_path()
            ok(CW.autostart_enabled(),
               'autostart: enabled by default when no user override exists')
            CW.set_autostart(False)
            ok(os.path.isfile(path), 'autostart: disable writes a per-user override')
            ok(not CW.autostart_enabled(),
               'autostart: a disabling override reports disabled')
            CW.set_autostart(True)
            ok(not os.path.isfile(path), 'autostart: enable removes the override')
            ok(CW.autostart_enabled(), 'autostart: enabled again after removal')
            CW.set_autostart(True)     # idempotent remove of an absent file (OSError path)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('x')

            def _raise_oserror(*_a, **_k):
                raise OSError('unreadable')

            _real_open = builtins.open
            builtins.open = _raise_oserror
            try:
                ok(CW.autostart_enabled(),
                   'autostart: an unreadable override is treated as enabled')
            finally:
                builtins.open = _real_open
            os.remove(path)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('[Desktop Entry]\nX-GNOME-Autostart-enabled=true\n')
            ok(CW.autostart_enabled(),
               'autostart: a non-disabling override reports enabled')
        finally:
            if old is None:
                os.environ.pop('XDG_CONFIG_HOME', None)
            else:
                os.environ['XDG_CONFIG_HOME'] = old


def _test_warn_any_default():
    with tempfile.TemporaryDirectory() as cfg:
        old = os.environ.get('XDG_CONFIG_HOME')
        os.environ['XDG_CONFIG_HOME'] = cfg
        try:
            ok(not CW.warn_any_default(),
               'warn-any default: off when unset in settings')
            confd = os.path.join(cfg, 'secure-terminal.d')
            os.makedirs(confd)
            with open(os.path.join(confd, '50_user.conf'), 'w', encoding='utf-8') as h:
                h.write('clip_warn_any=true\n')
            ok(CW.warn_any_default(),
               'warn-any default: on when clip_warn_any=true is persisted')
        finally:
            if old is None:
                os.environ.pop('XDG_CONFIG_HOME', None)
            else:
                os.environ['XDG_CONFIG_HOME'] = old


def _test_watcher():
    # theme=None exercises _load_theme (invalid theme -> loaded default)
    w = CW.ClipboardWatcher(APP, theme=None, any_mode=False, watch=True)
    # Drive _on_change deterministically: detach the auto-signal.
    w._clipboard.dataChanged.disconnect(w._on_change)
    cb = APP.clipboard()

    w.set_enabled(False)
    cb.setText('a' + ZWSP + 'b')
    w._on_change()
    ok(not w._popup.isVisible(), 'watcher: disabled -> no popup')
    w.set_enabled(True)

    cb.setText('')
    w._on_change()
    ok(not w._popup.isVisible(), 'watcher: empty clipboard -> no popup')

    cb.setText('hello world')
    w._on_change()
    ok(not w._popup.isVisible(), 'watcher: clean ASCII -> no popup')

    cb.setText('caf\u00e9')
    w._on_change()
    ok(not w._popup.isVisible(), 'watcher: honest accent in default mode -> no popup')
    w.set_any_mode(True)
    cb.setText('caf\u00e9')
    w._on_change()
    ok(w._popup.isVisible(), 'watcher: accent in any-non-ASCII mode -> popup')
    w.resolve('caf\u00e9', 'reject')
    w.set_any_mode(False)

    payload = 'a' + ZWSP + 'b' + RLO + 'c' + CYR_A + 'd'
    cb.setText(payload)
    w._on_change()
    ok(w._popup.isVisible(), 'watcher: deceptive text -> popup')

    # Drive the choice THROUGH the reused ReviewBar (covers _ClipboardReview.dispatch
    # and the review 'clipboard' kind).
    w._popup.bar._choose('stripped')
    eq(cb.text(), sanitize_clipboard(payload),
       'watcher: bar Replace(ASCII) dispatches to the clipboard')
    ok(not w._popup.isVisible(), 'watcher: resolving hides the popup')

    cb.setText(w._last_written)
    w._on_change()
    ok(not w._popup.isVisible(), 'watcher: our own write is ignored (feedback guard)')

    cb.setText(payload)
    w._on_change()
    ok(w._popup.isVisible(), 'watcher: deceptive re-pops before it is dismissed')
    w.resolve(payload, 'reject')
    cb.setText(payload)
    w._on_change()
    ok(not w._popup.isVisible(), 'watcher: dismissed text does not re-prompt')

    homo = 'p' + CYR_A + 'ypal'
    cb.setText(homo)
    w.resolve(homo, 'unicode')
    eq(cb.text(), sanitize_clipboard_unicode(homo),
       'watcher: Replace(keep unicode) keeps the printable homoglyph')

    # TOCTOU guard: a Replace must NOT clobber content copied after the popup opened.
    a_text = 'x' + RLO + 'y'
    cb.setText(a_text)
    w._on_change()
    ok(w._popup.isVisible(), 'watcher: deceptive A -> popup')
    cb.setText('newer clean text')
    w.resolve(a_text, 'stripped')
    eq(cb.text(), 'newer clean text',
       'watcher: Replace does not clobber content copied after the popup (TOCTOU)')
    ok(not w._popup.isVisible(), 'watcher: the stale review still closes')

    # review_now: nothing when empty, a popup even for clean text
    cb.setText('')
    w.review_now()
    ok(not w._popup.isVisible(), 'review_now: empty clipboard -> nothing')
    cb.setText('plain text')
    w.review_now()
    ok(w._popup.isVisible(), 'review_now: shows even clean text on demand')
    w.resolve('plain text', 'reject')


def _roundtrip(req):
    """Send one framed request to the running singleton server and read its reply,
    driving both sides on the main thread with processEvents (no thread -> no
    Qt-native/settrace segfault class)."""
    client = QLocalSocket()
    client.connectToServer(ipc.socket_path(CW.INSTANCE_GROUP))
    ok(client.waitForConnected(1000), 'ipc: client connects to the singleton socket')
    client.write(ipc.frame(json.dumps(req).encode('utf-8')))
    client.flush()
    framer = ipc.Framer()
    payload = None
    deadline = time.monotonic() + 3.0
    while payload is None and time.monotonic() < deadline:
        APP.processEvents()
        if client.bytesAvailable():
            payload = framer.feed(bytes(client.readAll()))
        else:
            client.waitForReadyRead(50)
    client.disconnectFromServer()
    return json.loads(payload.decode('utf-8')) if payload is not None else {}


def _test_daemon_ipc():
    with tempfile.TemporaryDirectory() as runtime:
        old = os.environ.get('XDG_RUNTIME_DIR')
        os.environ['XDG_RUNTIME_DIR'] = runtime
        try:
            app = CW.ClipboardWatchApp(APP)

            # _dispatch directly: every op + the malformed/unknown paths
            eq(app._dispatch(json.dumps({'op': 'ping'}).encode('utf-8')).get('ok'),
               True, 'dispatch: ping ok')
            r = app._dispatch(json.dumps({'op': 'set-warn-any',
                                          'value': True}).encode('utf-8'))
            eq(r.get('ok'), True, 'dispatch: set-warn-any ok')
            ok(app._watcher._any_mode is True, 'dispatch: set-warn-any updates watcher')
            eq(app._dispatch(json.dumps({'op': 'quit'}).encode('utf-8')).get('ok'),
               True, 'dispatch: quit ok (schedules app.quit)')
            eq(app._dispatch(b'not json').get('ok'), False,
               'dispatch: malformed JSON rejected')
            eq(app._dispatch(json.dumps(['a']).encode('utf-8')).get('ok'), False,
               'dispatch: a non-dict request rejected')
            eq(app._dispatch(json.dumps({'op': 'bogus'}).encode('utf-8')).get('ok'),
               False, 'dispatch: unknown op rejected')

            # claim the free singleton socket (real QLocalServer.listen)
            ok(app._claim_singleton() is True, 'singleton: claims the free socket')
            ok(app._server is not None, 'singleton: server is listening')
            ok(CW.is_running(), 'is_running: True once the socket is bound')

            # a full round-trip drives _on_ipc_connection + on_ready
            reply = _roundtrip({'op': 'ping'})
            eq(reply.get('ok'), True, 'ipc: ping round-trips through the server')
            eq(reply.get('pid'), os.getpid(), 'ipc: ping returns our pid')

            # a malformed (over-long) frame -> the server ABORTS the connection
            # (defensive), without crashing
            bad = QLocalSocket()
            bad.connectToServer(ipc.socket_path(CW.INSTANCE_GROUP))
            ok(bad.waitForConnected(1000), 'ipc: over-long-frame client connects')
            bad.write(struct.pack('<I', (1 << 20) + 1))   # claims a >1 MiB frame
            bad.flush()
            deadline = time.monotonic() + 3.0
            unconnected = QLocalSocket.LocalSocketState.UnconnectedState
            while bad.state() != unconnected and time.monotonic() < deadline:
                APP.processEvents()
                bad.waitForDisconnected(50)
            ok(bad.state() == unconnected,
               'ipc: an over-long frame is aborted by the server')

            # a second instance finds the socket live -> declines
            other = CW.ClipboardWatchApp(APP)
            ok(other._claim_singleton() is False,
               'singleton: a second instance sees it live and declines')

            # ensure_socket_dir failure -> proceed without a singleton
            _real = ipc.ensure_socket_dir

            def _boom():
                raise OSError('no runtime dir')

            ipc.ensure_socket_dir = _boom
            try:
                nrt = CW.ClipboardWatchApp(APP)
                ok(nrt._claim_singleton() is True,
                   'singleton: no runtime dir -> proceed (True)')
            finally:
                ipc.ensure_socket_dir = _real

            app._server.close()
        finally:
            if old is None:
                os.environ.pop('XDG_RUNTIME_DIR', None)
            else:
                os.environ['XDG_RUNTIME_DIR'] = old


def _test_module_ipc_helpers():
    calls = {}
    _real_send = ipc.send_request
    _real_live = ipc.socket_is_live

    def _fake_send(group, req, *_a, **_k):
        calls['send'] = (group, req)
        return {'ok': True}                 # a live daemon answered

    def _fake_live(group='default', **_k):
        calls['live'] = group
        return True

    ipc.send_request = _fake_send
    ipc.socket_is_live = _fake_live
    try:
        ok(CW.is_running(), 'is_running delegates to socket_is_live')
        eq(calls['live'], CW.INSTANCE_GROUP, 'is_running uses the clipboard group')
        ok(CW.stop_running(), 'stop_running: True when a daemon answered')
        eq(calls['send'][1], {'op': 'quit'}, 'stop_running sends the quit op')
        CW.push_warn_any(True)
        eq(calls['send'][1], {'op': 'set-warn-any', 'value': True},
           'push_warn_any sends the set-warn-any op')
    finally:
        ipc.send_request = _real_send
        ipc.socket_is_live = _real_live

    # stop_running False when nothing answered
    def _none_send(*_a, **_k):
        return None

    ipc.send_request = _none_send
    try:
        ok(not CW.stop_running(), 'stop_running: False when no daemon answered')
    finally:
        ipc.send_request = _real_send


def _test_tray_and_run():
    orig_tray = CW.QSystemTrayIcon
    o_exec = QApplication.exec
    o_term = signal.getsignal(signal.SIGTERM)
    o_int = signal.getsignal(signal.SIGINT)
    o_qlwc = APP.quitOnLastWindowClosed()
    CW.QSystemTrayIcon = _FakeTray
    try:
        app = CW.ClipboardWatchApp(APP)
        _FakeTray.available = True
        ok(app._build_tray() is not None, 'tray: built when available')
        _FakeTray.available = False
        ok(app._build_tray() is None, 'tray: None when unavailable')

        # run(): a singleton already running -> exit 0 (not an error)
        app2 = CW.ClipboardWatchApp(APP)
        app2._claim_singleton = lambda: False
        eq(app2.run(), 0, 'run: another watcher already runs -> exit 0')

        # run(): claimed but no tray -> exit 1
        _FakeTray.available = False
        app3 = CW.ClipboardWatchApp(APP)
        app3._claim_singleton = lambda: True
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            eq(app3.run(), 1, 'run: claimed but no tray -> exit 1')
        ok('no system tray' in err.getvalue(), 'run: reports the missing tray')

        # run(): claimed + tray -> installs signals + enters the (stubbed) loop
        _FakeTray.available = True
        QApplication.exec = lambda _self: 0
        app4 = CW.ClipboardWatchApp(APP)
        app4._claim_singleton = lambda: True
        eq(app4.run(), 0, 'run: with a tray it enters the event loop (stubbed exec)')
    finally:
        CW.QSystemTrayIcon = orig_tray
        QApplication.exec = o_exec
        signal.signal(signal.SIGTERM, o_term)
        signal.signal(signal.SIGINT, o_int)
        APP.setQuitOnLastWindowClosed(o_qlwc)


def run():
    _test_predicates()
    _test_autostart()
    _test_warn_any_default()
    _test_watcher()
    _test_daemon_ipc()
    _test_module_ipc_helpers()
    _test_tray_and_run()
    print('\n%s' % ('PASS' if _failures == 0 else 'FAIL'))
    return 1 if _failures else 0


if __name__ == '__main__':
    sys.exit(run())
