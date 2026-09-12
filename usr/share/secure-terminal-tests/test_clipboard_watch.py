#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.clipboard_watch: the reusable ClipboardWatcher core (the
## main window embeds it in-process -- there is no standalone daemon), the autostart
## helpers + their --tray Exec line, and the deceptive/any-non-ASCII triggers. Driven
## offscreen. Fails closed (exit 1) when PyQt6 is unavailable -- a security-relevant
## suite must not skip. Source stays pure ASCII: deceptive fixtures are \\u escapes.

import builtins
import os
import sys
import tempfile

from st_qt_platform import require_wayland
require_wayland('secure-terminal-tests(clipboard-watch)')

try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import QThreadPool
    from secure_terminal import clipboard_watch as CW
    from secure_terminal.sanitize import (
        sanitize_clipboard, sanitize_clipboard_unicode,
    )
    from secure_terminal.review import _BOX_MAX
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


def _settle():
    # The deceptive / non-ASCII scan is offloaded to a worker thread (S3) and reports
    # back via a queued signal. Wait for the pool, then pump the event loop so the queued
    # _on_scan_done (which pops the review) runs before we assert. A no-op when _on_change
    # took an early return (disabled / empty / feedback / dismissed) and queued no scan.
    QThreadPool.globalInstance().waitForDone(3000)
    APP.processEvents()


ZWSP = '\u200b'     # zero-width space (invisible)
RLO = '\u202e'      # right-to-left override (bidi)
CYR_A = '\u0430'    # Cyrillic a -- a homoglyph posing as ASCII 'a'


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
            with open(path, 'r', encoding='utf-8') as handle:
                override = handle.read()
            ok('Exec=secure-terminal --tray' in override,
               'autostart: the override Exec launches the app with --tray, '
               'not the retired --clipboard-watch')
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
            # A raw whole-file substring match false-reports 'disabled' when a Comment=/
            # Name= VALUE merely CONTAINS the literal, or when a [Desktop Action] section
            # (not [Desktop Entry]) carries the key. The section-aware parse reads only the
            # actual [Desktop Entry] keys. (canary: the old substring code returned False
            # -- disabled -- for the Comment case below.)
            os.remove(path)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('[Desktop Entry]\nName=x\n'
                             'Comment=Do not set Hidden=true here\n')
            ok(CW.autostart_enabled(),
               'autostart: Hidden=true inside a Comment= VALUE does not disable (canary)')
            os.remove(path)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('[Desktop Entry]\nName=x\n'
                             '[Desktop Action foo]\nHidden=true\n')
            ok(CW.autostart_enabled(),
               'autostart: Hidden=true in a [Desktop Action] section does not disable')
            os.remove(path)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('[Desktop Entry]\nExec=secure-terminal --tray %F\n'
                             'Hidden=true\n')
            ok(not CW.autostart_enabled(),
               'autostart: a real Hidden=true under [Desktop Entry] disables '
               '(an Exec %-code does not crash the parse)')
            # A file with no [Desktop Entry] section (KeyError) or no section header at
            # all (configparser.Error) is not a valid disabling override -> fail-safe
            # enabled, exercising the parse-failure branch.
            os.remove(path)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('[Other]\nHidden=true\n')
            ok(CW.autostart_enabled(),
               'autostart: no [Desktop Entry] section -> enabled (fail-safe)')
            os.remove(path)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('not a desktop file at all\n')
            ok(CW.autostart_enabled(),
               'autostart: a file with no section header -> enabled (fail-safe)')
            # a non-UTF-8 override (a hand edit / a Latin-1 tool / a crash mid-write) must
            # not crash the callers (clipboard menu, set_systray, settings dialog): read
            # fails with UnicodeDecodeError -> treated as enabled, like an unreadable file.
            with open(path, 'wb') as raw:
                raw.write(b'[Desktop Entry]\nName=\xff\xfe not utf8\n')
            ok(CW.autostart_enabled(),
               'autostart: a non-UTF-8 override is treated as enabled, not a crash')
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
    _settle()
    ok(not w._popup.isVisible(), 'watcher: disabled -> no popup')
    w.set_enabled(True)

    cb.setText('')
    w._on_change()
    _settle()
    ok(not w._popup.isVisible(), 'watcher: empty clipboard -> no popup')

    cb.setText('hello world')
    w._on_change()
    _settle()
    ok(not w._popup.isVisible(), 'watcher: clean ASCII -> no popup')

    cb.setText('caf\u00e9')
    w._on_change()
    _settle()
    ok(not w._popup.isVisible(), 'watcher: honest accent in default mode -> no popup')
    w.set_any_mode(True)
    cb.setText('caf\u00e9')
    w._on_change()
    _settle()
    ok(w._popup.isVisible(), 'watcher: accent in any-non-ASCII mode -> popup')
    w.resolve('caf\u00e9', 'reject')
    w.set_any_mode(False)

    payload = 'a' + ZWSP + 'b' + RLO + 'c' + CYR_A + 'd'
    cb.setText(payload)
    w._on_change()
    _settle()
    ok(w._popup.isVisible(), 'watcher: deceptive text -> popup')

    # Drive the choice THROUGH the reused ReviewBar (covers _ClipboardReview.dispatch
    # and the review 'clipboard' kind): [Strip unicode] then Deliver replaces with the
    # ASCII-only box.
    w._popup.bar._do_strip()
    w._popup.bar._deliver_clicked()
    eq(cb.text(), sanitize_clipboard(payload),
       'watcher: bar Strip + Replace dispatches the ASCII form to the clipboard')
    ok(not w._popup.isVisible(), 'watcher: resolving hides the popup')

    # Set our own-last-write to a DANGEROUS payload: WITHOUT the feedback guard this
    # deceptive text WOULD pop, so 'no popup' now proves the guard recognizes our own
    # write and skips it -- not merely that clean ASCII never pops (a tautology).
    w._last_written = payload
    cb.setText(w._last_written)
    w._on_change()
    _settle()
    ok(not w._popup.isVisible(), 'watcher: our own write is ignored (feedback guard)')
    w._last_written = ''             # reset so the next sub-test's payload is not seen as ours

    cb.setText(payload)
    w._on_change()
    _settle()
    ok(w._popup.isVisible(), 'watcher: deceptive re-pops before it is dismissed')
    w.resolve(payload, 'reject')
    cb.setText(payload)
    w._on_change()
    _settle()
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
    _settle()
    ok(w._popup.isVisible(), 'watcher: deceptive A -> popup')
    cb.setText('newer clean text')
    w.resolve(a_text, 'stripped')
    eq(cb.text(), 'newer clean text',
       'watcher: Replace does not clobber content copied after the popup (TOCTOU)')
    ok(not w._popup.isVisible(), 'watcher: the stale review still closes')

    # #1: an EDITED clipboard value must be WRITTEN on Replace. The old resolve compared
    # the clipboard against the edited value, so any edit made the compare miss and the
    # unsafe clipboard was left in place (a silently-failing security action).
    orig = 'p' + CYR_A + 'ypal'                     # homoglyph 'paypal'
    # Clear the dedup state a prior unicode-Replace left ( _last_written == this same
    # homoglyph), else _on_change treats orig as our own write echoing back and shows
    # no popup.
    w._last_written = None
    w._dismissed = None
    cb.setText(orig)
    w._on_change()
    _settle()
    ok(w._popup.isVisible(), 'watcher: homoglyph -> popup (edit case)')
    w._popup.bar._editor.set_source('paypal')        # user edits to the safe spelling
    w._popup.bar._deliver_clicked()                  # Replace
    eq(cb.text(), sanitize_clipboard('paypal'),
       '#1: an edited Replace writes the sanitized EDITED value, not a silent no-op')

    # #2: a huge clipboard must NOT load the whole thing into the editable box (an
    # unbounded rebuild freeze). Under the evidence-first model the box opens FULLY
    # REVEALED, so while a hidden char is present Replace is BLOCKED (nothing crosses
    # unreviewed); once a transform cleans the box, Replace sanitizes the FULL clipboard
    # -- the box PLUS its un-reviewed tail, both neutralized to the chosen tier.
    big = 'a' * 100 + ZWSP + 'b' * (_BOX_MAX + 5000)  # hidden char early, then > the box cap
    cb.setText(big)
    w._on_change()
    _settle()
    ok(w._popup.isVisible(), 'watcher: huge deceptive clipboard -> popup')
    _bar = w._popup.bar
    ok(len(_bar._editor.source()) <= _BOX_MAX,
       '#2: the editable box is bounded to _BOX_MAX (no unbounded rebuild DoS)')
    ok(not _bar._deliver.isEnabled(),
       '#2: Replace is BLOCKED while the revealed box still holds the hidden char')
    w._popup.bar._deliver_clicked()                  # blocked -> a no-op, clipboard untouched
    ok(cb.text() == big,
       '#2: a blocked Replace is a no-op (the raw clipboard is left as-is, not delivered)')
    _bar._do_strip()                                 # clean the box -> Replace enabled
    ok(_bar._deliver.isEnabled(),
       '#2: Replace enables once a transform removes the hidden char')
    w._popup.bar._deliver_clicked()                  # writes the FULL sanitized text (box + tail)
    # Compare with ok(), NOT eq(): eq() formats both ~1M-char strings via %r into the
    # message and prints it even on success -- a ~2M-char line that bloats the suite's
    # stdout past the sandbox transport size and TRUNCATES the coverage report that runs
    # after this last suite. Assert equality; report only the (bounded) lengths.
    _delivered_full = cb.text()
    _expected_full = sanitize_clipboard(big)
    ok(_delivered_full == _expected_full,
       '#2: a cleaned Replace sanitizes the FULL clipboard (box PLUS its un-reviewed '
       'tail); delivered %d chars, expected %d'
       % (len(_delivered_full), len(_expected_full)))

    # F2 (trigger scan cap removed): a deceptive char living PAST the old 1M trigger cap
    # must still raise the review. The trigger now scans the FULL clipboard with an
    # allocation-free early-exit predicate, so there is no >1M blind spot. (canary: the old
    # code scanned only text[:1_000_000] and would NOT pop for a hidden char at ~1.05M.)
    w._last_written = None
    w._dismissed = None
    past_cap = 'a' * 1_050_000 + ZWSP + 'b'
    cb.setText(past_cap)
    w._on_change()
    _settle()
    ok(w._popup.isVisible(),
       'watcher: a deceptive char PAST the old 1M cap still pops the review (no blind spot)')
    w.resolve(past_cap, 'reject')
    # A clean multi-MB clipboard (larger than the old cap) must still stay silent -- the
    # full-text scan neither false-pops nor allocates a copy of it.
    cb.setText('c' * 1_050_000)
    w._on_change()
    _settle()
    ok(not w._popup.isVisible(),
       'watcher: a clean multi-MB clipboard stays silent (full-text scan, no false pop)')

    # review_now: nothing when empty, a popup even for clean text
    cb.setText('')
    w.review_now()
    ok(not w._popup.isVisible(), 'review_now: empty clipboard -> nothing')
    cb.setText('plain text')
    w.review_now()
    ok(w._popup.isVisible(), 'review_now: shows even clean text on demand')
    w.resolve('plain text', 'reject')

    # REGRESSION (finding #2): review_is_open() tracks an UNRESOLVED popup, so a second
    # 'Review clipboard now' can re-raise it instead of reassigning the holder and silently
    # GC'ing the first, still-open review. raise_popup() re-fronts it without crashing.
    cb.setText('plain again')
    w.review_now()
    ok(w.review_is_open(), 'review_is_open: True while a popup is showing')
    w.raise_popup()                        # must not raise
    ok(w.review_is_open(), 'raise_popup: leaves the popup open')
    w.resolve('plain again', 'reject')
    ok(not w.review_is_open(), 'review_is_open: False once the review is resolved')

    # --- offloaded-scan branches (S3): supersession, TOCTOU, disable-during-scan -------
    # The scan runs on a worker thread and its result is applied on the GUI thread only
    # after a re-check. These exercise the drop branches. (canary: pre-fix _on_change
    # scanned synchronously and popped the review inline, so none of these branches existed
    # and a large scan froze the GUI thread.)
    # offload canary (deterministic, no wall-clock): the scan runs on a worker and reports
    # back via a QUEUED cross-thread signal, so the review CANNOT pop inline in _on_change
    # -- it appears only once the event loop is pumped (_settle). No processEvents runs
    # between the call and the check, so the queued result is still undelivered. (canary:
    # pre-fix _on_change scanned synchronously and popped the review inline -- freezing the
    # GUI thread for the whole scan -- so it was visible immediately here.)
    w._last_written = None
    w._dismissed = None
    _asy = 'v' + RLO + 'w'                 # deceptive -> would pop, but only after the worker
    cb.setText(_asy)
    w._on_change()
    _inline = w._popup.isVisible()         # post-fix: False (offloaded); pre-fix: True (inline)
    _settle()
    ok(not _inline and w._popup.isVisible(),
       'S3: _on_change offloads the scan -- the review pops only after the worker settles, '
       'never inline (GUI thread not blocked)')
    w.resolve(_asy, 'reject')

    w._last_written = None
    w._dismissed = None
    _sup = 'q' + RLO + 'z'
    cb.setText(_sup)
    w._on_change()                         # gen N   -- superseded below
    w._on_change()                         # gen N+1 -- the survivor
    _settle()
    ok(w._popup.isVisible(),
       'watcher: a superseded scan is dropped; the latest scan still pops the review')
    w.resolve(_sup, 'reject')

    w._last_written = None
    w._dismissed = None
    _toc = 'r' + ZWSP + 's'
    cb.setText(_toc)
    w._on_change()                         # queues a scan of the deceptive _toc
    cb.setText('clean-now')                # clipboard changes under the in-flight scan
    _settle()                              # (dataChanged is disconnected -> no re-trigger)
    ok(not w._popup.isVisible(),
       'watcher: a scan whose text left the clipboard mid-scan is dropped (TOCTOU)')

    w._last_written = None
    w._dismissed = None
    _dis = 't' + RLO + 'u'
    cb.setText(_dis)
    w._on_change()
    w.set_enabled(False)                   # disabled before the scan result lands
    _settle()
    ok(not w._popup.isVisible(),
       'watcher: disabling the watcher mid-scan drops the pending scan result')
    w.set_enabled(True)


def _test_shipped_autostart_exec():
    ## The shipped login-autostart entry must launch the app hidden-to-tray (--tray),
    ## the single-process sanitizer -- NOT the retired --clipboard-watch daemon. Located
    ## relative to the imported package so it checks the working tree under test.
    pkg = os.path.dirname(CW.__file__)                     # .../secure_terminal
    repo = os.path.normpath(os.path.join(pkg, *(['..'] * 5)))  # up: pkg->dist-packages->python3->lib->usr->repo
    desktop = os.path.join(
        repo, 'etc', 'xdg', 'autostart', 'sclip-clipboard-watch.desktop')
    ok(os.path.isfile(desktop),
       'shipped autostart: the .desktop entry exists in the tree')
    with open(desktop, 'r', encoding='utf-8') as handle:
        body = handle.read()
    ok('Exec=secure-terminal --tray' in body,
       'shipped autostart: Exec launches --tray (hidden-to-tray single process)')
    ok('--clipboard-watch' not in body,
       'shipped autostart: the retired --clipboard-watch flag is gone')


def run():
    _test_predicates()
    _test_autostart()
    _test_shipped_autostart_exec()
    _test_watcher()
    print('\n%s' % ('PASS' if _failures == 0 else 'FAIL'))
    return 1 if _failures else 0


if __name__ == '__main__':
    sys.exit(run())
