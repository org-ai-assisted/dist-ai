#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Wizard page routing (nextId).

DisclaimerPage1 routes accept -> disclaimer 2 and reject -> finish page (the
"not understood" exit). DisclaimerPage2 always routes to the finish page. Both
resolve targets by name through Common.wizard_steps, so the routing is checked
against the step list rather than hard-coded indices.
"""

import unittest

import swd_testlib as T


class DisclaimerPage1RoutingTestCase(unittest.TestCase):
    def setUp(self):
        T.swd.Common.wizard_steps = list(T.DISCLAIMER_STEPS)
        self.page = T.swd.DisclaimerPage1()
        self.addCleanup(self.page.deleteLater)

    def test_accept_routes_to_disclaimer_2(self):
        self.page.yes_button.setChecked(True)
        self.assertEqual(
            self.page.nextId(), T.DISCLAIMER_STEPS.index("disclaimer_2")
        )

    def test_reject_routes_to_finish_page(self):
        self.page.no_button.setChecked(True)
        self.assertEqual(
            self.page.nextId(), T.DISCLAIMER_STEPS.index("finish_page")
        )

    def test_reject_is_the_default(self):
        ## The wizard constructs with no_button pre-checked; a user who clicks
        ## Next without choosing is routed out to the finish page.
        self.assertTrue(self.page.no_button.isChecked())
        self.assertEqual(
            self.page.nextId(), T.DISCLAIMER_STEPS.index("finish_page")
        )


class DisclaimerPage2RoutingTestCase(unittest.TestCase):
    def setUp(self):
        T.swd.Common.wizard_steps = list(T.DISCLAIMER_STEPS)
        self.page = T.swd.DisclaimerPage2()
        self.addCleanup(self.page.deleteLater)

    def test_always_routes_to_finish_page(self):
        self.assertEqual(
            self.page.nextId(), T.DISCLAIMER_STEPS.index("finish_page")
        )
        ## Independent of the radio state.
        self.page.yes_button.setChecked(True)
        self.assertEqual(
            self.page.nextId(), T.DISCLAIMER_STEPS.index("finish_page")
        )


if __name__ == "__main__":
    unittest.main()
