#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
info.py returns Qt rich-text (HTML) strings shown in the GUI. A missing closing
tag renders wrong; set_disabled() previously left its last <p> unclosed. Assert
the paragraph tags balance in the user-facing messages.
"""

import unittest

import tcp_testlib as T  # noqa: F401  (sets up sys.path / offscreen Qt)
from tor_control_panel import info


## Zero-argument functions in info that return a rich-text string.
_TEXT_FUNCS = [
    "tor_stopped", "tor_disabled", "tor_disabled_no_controller",
    "tor_acquiring", "set_disabled", "no_controller", "cookie_error",
    "invalid_ip_port", "newnym_text",
]


class ParagraphBalanceTest(unittest.TestCase):
    def test_p_tags_balance(self):
        for name in _TEXT_FUNCS:
            func = getattr(info, name, None)
            if func is None:
                continue
            with self.subTest(func=name):
                text = func()
                self.assertEqual(
                    text.count("<p>"), text.count("</p>"),
                    "{0}(): <p> and </p> counts differ".format(name))


if __name__ == "__main__":
    unittest.main()
