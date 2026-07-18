#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
get_finish_page_text() assembly.

The finish page body is start + optional browser-choice + sysmaint-or-not +
end. The browser-choice paragraph appears only on 'machine' (Kicksecure host),
never on a gateway/workstation (Whonix). The sysmaint variant is chosen by
user_sysmaint_split_installed. Each fragment is fetched through the wizard's own
translator so the assertions do not hard-code English text.
"""

import unittest

import swd_testlib as T


class FinishPageTextTestCase(unittest.TestCase):
    def _text_for(self, environment, sysmaint):
        wizard = T.make_wizard(
            self, False, T.FINISH_ONLY_STEPS, environment=environment
        )
        wizard.user_sysmaint_split_installed = sysmaint
        return wizard, wizard.get_finish_page_text()

    def _assert_common(self, wizard, text):
        self.assertIsInstance(text, str)
        self.assertIn(wizard._("finish_page_start"), text)
        self.assertIn(wizard._("finish_page_end"), text)

    def test_machine_sysmaint(self):
        wizard, text = self._text_for("machine", True)
        self._assert_common(wizard, text)
        self.assertIn(
            wizard._("finish_page_middle_browser_choice_sysmaint"), text
        )
        self.assertIn(wizard._("finish_page_middle_sysmaint"), text)
        self.assertNotIn(wizard._("finish_page_middle_no_sysmaint"), text)

    def test_machine_no_sysmaint(self):
        wizard, text = self._text_for("machine", False)
        self._assert_common(wizard, text)
        self.assertIn(
            wizard._("finish_page_middle_browser_choice_no_sysmaint"), text
        )
        self.assertIn(wizard._("finish_page_middle_no_sysmaint"), text)
        self.assertNotIn(wizard._("finish_page_middle_sysmaint"), text)

    def test_gateway_omits_browser_choice(self):
        wizard, text = self._text_for("gateway", False)
        self._assert_common(wizard, text)
        self.assertNotIn(
            wizard._("finish_page_middle_browser_choice_sysmaint"), text
        )
        self.assertNotIn(
            wizard._("finish_page_middle_browser_choice_no_sysmaint"), text
        )
        self.assertIn(wizard._("finish_page_middle_no_sysmaint"), text)

    def test_workstation_omits_browser_choice(self):
        wizard, text = self._text_for("workstation", True)
        self._assert_common(wizard, text)
        self.assertNotIn(
            wizard._("finish_page_middle_browser_choice_sysmaint"), text
        )
        self.assertIn(wizard._("finish_page_middle_sysmaint"), text)


if __name__ == "__main__":
    unittest.main()
