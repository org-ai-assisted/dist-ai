#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.dialog -- the paste-warning dialog shown when a
## paste carries unicode or control characters. Built and driven offscreen: the
## four preview panes, the three result buttons, the countdown that gates the
## risky "paste with unicode" button, and the confirm() entry point (both exec()
## outcomes). Kept as its own small suite -- rather than folded into the large
## widget suite -- so the few QObjects it creates are torn down cleanly and do
## not perturb the coverage run. SKIPs (exit 77) when PyQt6 is unavailable.

import os
import sys

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PyQt6.QtWidgets import QApplication, QDialog
    from secure_terminal import dialog as st_dialog
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: '
                     '%s\n' % exc)
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


def _destroy(dlg):
    """Tear a dialog down deterministically so nothing lingers into shutdown."""
    if hasattr(dlg, '_countdown'):
        dlg._countdown.stop()
    dlg.close()
    dlg.setParent(None)
    dlg.deleteLater()
    APP.processEvents()


_dtext = 'rm ' + chr(0x202E) + 'x' + chr(0x0430) + '\n'      # bidi + homoglyph

# --- construction: a modal warning that defaults to reject --------------------
_dlg = st_dialog.PasteWarningDialog(_dtext, 0)
ok(_dlg.windowTitle() == 'Paste warning' and _dlg.isModal(),
   'a modal "Paste warning" dialog is built')
eq(_dlg._result, 'reject', 'the dialog defaults to reject')
ok(_dlg._unicode_btn.isEnabled(),
   'with no delay the risky unicode button is enabled immediately')
# a button click records the corresponding result (via _done)
_dlg._done('stripped')
eq(_dlg._result, 'stripped', 'a button click records its result')
_destroy(_dlg)

# --- a paste with nothing classifiable still builds (generic headline) --------
_dlg_plain = st_dialog.PasteWarningDialog('plain ascii text', 0)
ok(_dlg_plain is not None, 'the dialog builds even when classify_paste finds nothing')
_destroy(_dlg_plain)

# --- the countdown gate: the risky button is disabled until the timer elapses -
_dlgc = st_dialog.PasteWarningDialog(_dtext, 2)
ok(not _dlgc._unicode_btn.isEnabled(),
   'a countdown delay starts the unicode button disabled')
ok('(2)' in _dlgc._unicode_btn.text(),
   'the unicode button shows the remaining seconds')
_dlgc._tick()                               # 2 -> 1
_dlgc._tick()                               # 1 -> 0
_dlgc._tick()                               # 0 -> re-enable + stop the timer
ok(_dlgc._unicode_btn.isEnabled(),
   'the unicode button is enabled once the countdown elapses')
eq(_dlgc._unicode_btn.text(), 'Paste with unicode',
   'the countdown suffix is dropped when the button unlocks')
_destroy(_dlgc)

# --- confirm(): exec() Accepted returns the chosen result; Rejected -> reject --
_orig_exec = st_dialog.PasteWarningDialog.exec


def _exec_accept(self):
    self._result = 'unicode'
    return int(QDialog.DialogCode.Accepted)


def _exec_reject(self):
    return int(QDialog.DialogCode.Rejected)


st_dialog.PasteWarningDialog.exec = _exec_accept
try:
    eq(st_dialog.PasteWarningDialog.confirm(_dtext, 0), 'unicode',
       'confirm returns the accepted result')
    st_dialog.PasteWarningDialog.exec = _exec_reject
    eq(st_dialog.PasteWarningDialog.confirm(_dtext, 0), 'reject',
       'confirm maps a rejected dialog to reject')
finally:
    st_dialog.PasteWarningDialog.exec = _orig_exec

APP.processEvents()

print('secure-terminal-tests(dialog): all passed' if not _failures else
      'secure-terminal-tests(dialog): %d failed' % _failures)
sys.exit(1 if _failures else 0)
