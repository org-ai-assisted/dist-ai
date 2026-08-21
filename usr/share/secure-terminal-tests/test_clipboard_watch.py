#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.clipboard_watch -- the tray-only clipboard sanitizer.
## Driven offscreen: the deceptive/any-non-ASCII triggers, the autostart on-login
## override, the watch that raises the reused ReviewBar only on deceptive text, the
## feedback-loop and dismissed guards, that a bar choice replaces the clipboard
## (flag-and-offer, never auto-swap), and the tray/run lifecycle. Fails closed
## (exit 1) when PyQt6 is unavailable -- a security-relevant suite must not skip.
##
## Source stays pure ASCII: deceptive fixtures are \\u escapes only.

import builtins
import contextlib
import io
import os
import signal
import sys
import tempfile

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication
    from secure_terminal import clipboard_watch as CW
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
            # an override that EXISTS but cannot be read -> treated as enabled. Force
            # the read to fail deterministically (root would defeat a chmod 000).
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


def _test_watch():
    w = CW.ClipboardWatchApp(APP)
    # Drive _on_change deterministically: detach the auto-signal so setText does not
    # race a second handler into the assertions.
    w._clipboard.dataChanged.disconnect(w._on_change)
    cb = APP.clipboard()

    w._enabled = False
    cb.setText('a' + ZWSP + 'b')
    w._on_change()
    ok(not w._popup.isVisible(), 'watch: disabled -> no popup')
    w._enabled = True

    cb.setText('')
    w._on_change()
    ok(not w._popup.isVisible(), 'watch: empty clipboard -> no popup')

    cb.setText('hello world')
    w._on_change()
    ok(not w._popup.isVisible(), 'watch: clean ASCII -> no popup')

    cb.setText('caf\u00e9')
    w._on_change()
    ok(not w._popup.isVisible(), 'watch: an honest accent in default mode -> no popup')
    w._any_mode = True
    cb.setText('caf\u00e9')
    w._on_change()
    ok(w._popup.isVisible(), 'watch: an accent in any-non-ASCII mode -> popup')
    w.resolve('caf\u00e9', 'reject')
    w._any_mode = False

    payload = 'a' + ZWSP + 'b' + RLO + 'c' + CYR_A + 'd'
    cb.setText(payload)
    w._on_change()
    ok(w._popup.isVisible(), 'watch: deceptive text -> popup')

    # Drive the choice THROUGH the reused ReviewBar (covers _ClipboardReview.dispatch
    # and the review 'clipboard' kind), not resolve() directly.
    w._popup.bar._choose('stripped')
    eq(cb.text(), sanitize_clipboard(payload),
       'watch: bar Replace(ASCII) dispatches through _ClipboardReview to the clipboard')
    ok(not w._popup.isVisible(), 'watch: resolving hides the popup')

    # feedback-loop guard: our own sanitized write must not re-trigger a review
    cb.setText(w._last_written)
    w._on_change()
    ok(not w._popup.isVisible(), 'watch: our own write is ignored (feedback guard)')

    # dismissed guard: text the user chose to keep must not re-prompt
    cb.setText(payload)
    w._on_change()
    ok(w._popup.isVisible(), 'watch: deceptive re-pops before it is dismissed')
    w.resolve(payload, 'reject')
    cb.setText(payload)
    w._on_change()
    ok(not w._popup.isVisible(), 'watch: dismissed text does not re-prompt')

    # unicode replace keeps the printable homoglyph
    w.resolve('p' + CYR_A + 'ypal', 'unicode')
    eq(cb.text(), sanitize_clipboard_unicode('p' + CYR_A + 'ypal'),
       'watch: Replace(keep unicode) keeps the printable homoglyph')

    # review-on-demand: nothing when empty, a popup even for clean text
    cb.setText('')
    w._review_now()
    ok(not w._popup.isVisible(), 'review-now: empty clipboard -> nothing')
    cb.setText('plain text')
    w._review_now()
    ok(w._popup.isVisible(), 'review-now: shows even clean text on demand')
    w.resolve('plain text', 'reject')

    # the tray-menu callbacks
    w._set_enabled(False)
    ok(w._enabled is False, 'menu: Watch-clipboard toggle sets enabled')
    w._set_enabled(True)
    w._set_any_mode(True)
    ok(w._any_mode is True, 'menu: any-non-ASCII toggle sets the mode')
    w._set_any_mode(False)


def _test_tray_and_run():
    orig = CW.QSystemTrayIcon
    o_exec = QApplication.exec
    o_term = signal.getsignal(signal.SIGTERM)
    o_int = signal.getsignal(signal.SIGINT)
    o_qlwc = APP.quitOnLastWindowClosed()
    CW.QSystemTrayIcon = _FakeTray
    try:
        w = CW.ClipboardWatchApp(APP)
        _FakeTray.available = True
        tray = w._build_tray()
        ok(tray is not None, 'tray: built when a system tray is available')
        _FakeTray.available = False
        ok(w._build_tray() is None, 'tray: None when no system tray is available')

        # the autostart menu toggle, isolated to a temp XDG so it never touches ~
        with tempfile.TemporaryDirectory() as cfg:
            old = os.environ.get('XDG_CONFIG_HOME')
            os.environ['XDG_CONFIG_HOME'] = cfg
            try:
                w._set_autostart(False)
                ok(os.path.isfile(CW._user_autostart_path()),
                   'menu: Start-on-login toggle writes the override')
            finally:
                if old is None:
                    os.environ.pop('XDG_CONFIG_HOME', None)
                else:
                    os.environ['XDG_CONFIG_HOME'] = old

        # run(): no tray -> exit 1 with a message
        _FakeTray.available = False
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = CW.ClipboardWatchApp(APP).run()
        eq(rc, 1, 'run: no system tray -> exit 1')
        ok('no system tray' in err.getvalue(), 'run: reports the missing tray')

        # run(): a tray is available -> installs signals + enters the (stubbed) loop
        _FakeTray.available = True
        QApplication.exec = lambda _self: 0
        eq(CW.ClipboardWatchApp(APP).run(), 0,
           'run: with a tray it enters the event loop (stubbed exec)')
    finally:
        CW.QSystemTrayIcon = orig
        QApplication.exec = o_exec
        signal.signal(signal.SIGTERM, o_term)
        signal.signal(signal.SIGINT, o_int)
        APP.setQuitOnLastWindowClosed(o_qlwc)


def run():
    _test_predicates()
    _test_autostart()
    _test_watch()
    _test_tray_and_run()
    print('\n%s' % ('PASS' if _failures == 0 else 'FAIL'))
    return 1 if _failures else 0


if __name__ == '__main__':
    sys.exit(run())
