#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
The Back button visibility contract.

A single-page wizard (the finish page, the default once the disclaimer is
disabled) must hide the Back button because there is nowhere to go back to. A
plain QWidget.hide() does not survive QWizard rebuilding its button layout on
show(), so the wizard must set NoBackButtonOnStartPage. A multi-page
(disclaimer-enabled) wizard must keep the Back button available past the start
page.
"""

import unittest

import swd_testlib as T


class SinglePageTestCase(unittest.TestCase):
    def setUp(self):
        self.wizard = T.make_wizard(self, False, T.FINISH_ONLY_STEPS)

    def test_exactly_one_page(self):
        self.assertEqual(len(self.wizard.pageIds()), 1)

    def test_option_is_set(self):
        self.assertTrue(
            self.wizard.testOption(T.QWizard.NoBackButtonOnStartPage),
            "single-page wizard must set NoBackButtonOnStartPage",
        )

    def test_back_not_visible_after_show(self):
        self.wizard.show()
        T.APP.processEvents()
        self.assertFalse(
            self.wizard.button(T.QWizard.BackButton).isVisible(),
            "Back button must not be visible on a single-page wizard",
        )


class MultiPageTestCase(unittest.TestCase):
    def setUp(self):
        self.wizard = T.make_wizard(self, True, T.DISCLAIMER_STEPS)

    def test_three_pages(self):
        self.assertEqual(len(self.wizard.pageIds()), 3)

    def test_option_not_set(self):
        self.assertFalse(
            self.wizard.testOption(T.QWizard.NoBackButtonOnStartPage),
            "multi-page wizard must not suppress the Back button",
        )

    def test_back_available_past_start_page(self):
        self.wizard.show()
        T.APP.processEvents()
        ## Accept page 1 so nextId() routes to disclaimer 2 (a non-start page).
        self.wizard.disclaimer_1.yes_button.setChecked(True)
        self.wizard.next()
        T.APP.processEvents()
        self.assertTrue(
            self.wizard.button(T.QWizard.BackButton).isVisible(),
            "Back button must be available past the start page",
        )


if __name__ == "__main__":
    unittest.main()
