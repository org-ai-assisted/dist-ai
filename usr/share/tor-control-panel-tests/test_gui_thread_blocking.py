#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Two properties of the privileged call sites in both front-ends.

1. No GUI entry point may let privilege.NoPrivilegeMethod escape. The escalators
   (leaprun, pkexec, passwordless sudo) can all be absent on plain Debian, and
   privilege.command() raises there. An unguarded call site raises straight out
   of a clicked slot as a traceback -- and in __init__ it took the whole window
   down before it appeared. This is enforced by DRIVING the entry points rather
   than by grepping for try/except, so a call site added later is caught.

2. Blocking privileged work does not run on the GUI thread. The stop/restart
   path used a synchronous wait(), and the wizard's back/cancel restore called
   set_enabled()/set_disabled() inline, so the window froze for the duration --
   under pkexec including the authentication prompt.
"""

import contextlib
import threading
import time
import unittest

import tcp_testlib as T

T.require_app()
from PyQt5.QtWidgets import QApplication
from tor_control_panel import anon_connection_wizard as acw
from tor_control_panel import privilege
from tor_control_panel import tor_control_panel as tcp
from tor_control_panel import tor_status


class NoPrivilegeMethodEscapesTest(unittest.TestCase):
    """privilege.command() raising must never reach the user as a traceback."""

    @contextlib.contextmanager
    def _command_raises(self):
        """Make privilege.command() raise -- INSIDE the sandbox, not before it.

        Two traps, both hit while writing this:

        * tcp_testlib.sandbox() replaces privilege.command with a stub
          returning ['true'], so patching in setUp is undone on entry and every
          assertion here would pass without the raise ever happening.
        * restoring via addCleanup runs AFTER the sandbox has put the real
          function back, so it would reinstate the sandbox's stub globally and
          break every later test that uses privilege.command. Hence a context
          manager that unwinds inside the sandbox, not test-level cleanup.
        """
        saved = privilege.command

        def _raise(*_args, **_kwargs):
            raise privilege.NoPrivilegeMethod('no escalation method')

        privilege.command = _raise
        try:
            ## Prove the stub is live, so this cannot go quietly vacuous again.
            with self.assertRaises(privilege.NoPrivilegeMethod):
                privilege.command('acw-tor-control-stop')
            yield
        finally:
            privilege.command = saved

    def test_panel_constructs_and_drives_without_escaping(self):
        with T.sandbox(), T.no_modal(), self._command_raises():
            ## __init__ itself probes for the journal helper.
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)

            ## The journal source must degrade, not blow up on Popen(None).
            self.assertIsNone(panel.journal_command)
            panel.journal_button.setChecked(True)
            panel.refresh_logs()

            ## Every privileged action reachable from a click.
            for name in ('stop_tor', 'restart_tor'):
                with self.subTest(action=name):
                    try:
                        getattr(panel, name)()
                    except privilege.NoPrivilegeMethod as exc:
                        self.fail(f'{name}() let NoPrivilegeMethod escape: {exc}')

    def test_wizard_cancel_and_back_do_not_escape(self):
        with T.sandbox(), T.no_modal(), self._command_raises():
            wizard = acw.AnonConnectionWizard()
            self.addCleanup(wizard.deleteLater)
            for name in ('back_button_clicked', 'cancel_button_clicked'):
                with self.subTest(action=name):
                    try:
                        getattr(wizard, name)()
                    except privilege.NoPrivilegeMethod as exc:
                        self.fail(f'{name}() let NoPrivilegeMethod escape: {exc}')


class OffGuiThreadTest(unittest.TestCase):
    """The blocking privileged work must not execute on the GUI thread."""

    def _record_thread(self, box):
        gui_thread = threading.current_thread().ident

        def _work(*_args, **_kwargs):
            box.append(threading.current_thread().ident)
            return ('tor_disabled', 0)

        return gui_thread, _work

    def test_wizard_cancel_restore_runs_off_the_gui_thread(self):
        """Cancel must not block the GUI thread -- but must still COMPLETE.

        Cancel closes the wizard, so a detached restore can be lost when the
        process exits. The requirement is therefore both: off-thread, and
        finished by the time the handler returns.
        """
        box = []
        gui_thread, work = self._record_thread(box)
        saved = tor_status.set_disabled
        tor_status.set_disabled = work
        self.addCleanup(lambda: setattr(tor_status, 'set_disabled', saved))

        with T.sandbox(), T.no_modal():
            wizard = acw.AnonConnectionWizard()
            self.addCleanup(wizard.deleteLater)
            acw.Common.init_tor_status = 'tor_disabled'
            ## Stand in for "a bootstrap ran", which is what arms the restore.
            wizard.bootstrap_thread = _FakeThread()

            wizard.cancel_button_clicked()

            self.assertEqual(len(box), 1,
                             'restore did not complete before cancel returned')
            self.assertNotEqual(
                box[0], gui_thread,
                'restore ran on the GUI thread, so the window froze for the '
                'whole privileged call')

    def test_panel_stop_tor_runs_off_the_gui_thread(self):
        box = []
        gui_thread = threading.current_thread().ident
        done = []

        with T.sandbox(), T.no_modal():
            panel = tcp.TorControlPanel()
            self.addCleanup(panel.deleteLater)

            def _work():
                box.append(threading.current_thread().ident)

            ## Drive run_async directly with the same shape stop_tor uses: the
            ## point under test is that the blocking call is handed to a worker
            ## thread, not that Popen itself is stubbed.
            panel.run_async(_work, lambda _r: done.append(True))
            deadline = 5.0
            step = 0.02
            waited = 0.0
            while not done and waited < deadline:
                QApplication.processEvents()
                time.sleep(step)
                waited += step

            self.assertTrue(done, 'run_async never completed')
            self.assertEqual(len(box), 1)
            self.assertNotEqual(box[0], gui_thread,
                                'blocking work ran on the GUI thread')


class _FakeThread:
    """Stands in for a live TorBootstrap; terminate() is all the handlers call."""

    def terminate(self):
        return None


if __name__ == '__main__':
    unittest.main()
