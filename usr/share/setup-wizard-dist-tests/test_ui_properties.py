#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Window chrome, button state, and the button slots.

Covers the window title per environment (Kicksecure vs Whonix), the renamed
Finish button ("OK"), set_next_button_state()'s inverted enable logic, done()
recording a normal finish, the finish page widgets, and that the Back/Next
slots run without raising on their live pages.
"""

import unittest

from PyQt5.QtWidgets import QLabel, QTextBrowser

import swd_testlib as T


class WindowTitleTestCase(unittest.TestCase):
    def test_machine_title_is_kicksecure(self):
        wizard = T.make_wizard(
            self, False, T.FINISH_ONLY_STEPS, environment="machine"
        )
        self.assertEqual(wizard.windowTitle(), "Kicksecure Setup Wizard")

    def test_gateway_title_is_whonix(self):
        wizard = T.make_wizard(
            self, False, T.FINISH_ONLY_STEPS, environment="gateway"
        )
        self.assertEqual(wizard.windowTitle(), "Whonix Setup Wizard")

    def test_workstation_title_is_whonix(self):
        wizard = T.make_wizard(
            self, False, T.FINISH_ONLY_STEPS, environment="workstation"
        )
        self.assertEqual(wizard.windowTitle(), "Whonix Setup Wizard")


class FinishButtonTestCase(unittest.TestCase):
    def test_finish_button_relabelled_ok(self):
        wizard = T.make_wizard(self, False, T.FINISH_ONLY_STEPS)
        self.assertEqual(
            wizard.button(T.QWizard.FinishButton).text(), "OK"
        )


class NextButtonStateTestCase(unittest.TestCase):
    ## set_next_button_state inverts its argument: a truthy "disclaimer not
    ## understood" state disables Next.
    def setUp(self):
        self.wizard = T.make_wizard(self, False, T.FINISH_ONLY_STEPS)
        self.next_button = self.wizard.button(T.QWizard.NextButton)

    def test_true_disables_next(self):
        self.wizard.set_next_button_state(True)
        self.assertFalse(self.next_button.isEnabled())

    def test_false_enables_next(self):
        self.wizard.set_next_button_state(True)
        self.wizard.set_next_button_state(False)
        self.assertTrue(self.next_button.isEnabled())


class DoneTestCase(unittest.TestCase):
    def test_accepted_marks_finished_normally(self):
        wizard = T.make_wizard(self, False, T.FINISH_ONLY_STEPS)
        self.assertFalse(wizard.finished_normally)
        wizard.done(T.QWizard.Accepted)
        self.assertTrue(wizard.finished_normally)

    def test_rejected_leaves_not_finished(self):
        wizard = T.make_wizard(self, False, T.FINISH_ONLY_STEPS)
        wizard.done(T.QWizard.Rejected)
        self.assertFalse(wizard.finished_normally)


class FinishPageWidgetsTestCase(unittest.TestCase):
    def test_finish_page_has_icon_and_text(self):
        wizard = T.make_wizard(self, False, T.FINISH_ONLY_STEPS)
        self.assertIsInstance(wizard.finish_page.icon, QLabel)
        self.assertIsInstance(wizard.finish_page.text, QTextBrowser)
        ## setupUi() fills the finish page text at construction.
        self.assertTrue(wizard.finish_page.text.toPlainText().strip())
        ## External links stay clickable in the finish page (documentation URLs).
        self.assertTrue(wizard.finish_page.text.openExternalLinks())


class ButtonSlotSmokeTestCase(unittest.TestCase):
    ## The slots run for their side effects (window resize, pixmap swap); assert
    ## they do not raise on the pages where they are reachable.
    def test_next_slot_on_finish_page(self):
        wizard = T.make_wizard(
            self, False, T.FINISH_ONLY_STEPS, environment="workstation"
        )
        wizard.show()
        T.APP.processEvents()
        wizard.next_button_clicked()  ## must not raise

    def test_back_slot_on_disclaimer(self):
        wizard = T.make_wizard(self, True, T.DISCLAIMER_STEPS)
        wizard.show()
        T.APP.processEvents()
        wizard.back_button_clicked()  ## must not raise


if __name__ == "__main__":
    unittest.main()
