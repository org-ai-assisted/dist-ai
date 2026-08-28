#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Source hygiene: the shipped wizard module must stay pure ASCII (R-001).
"""

import unittest

import swd_testlib as T


class SourceHygieneTestCase(unittest.TestCase):
    def test_module_is_ascii(self):
        source_path = T.swd.__file__
        with open(source_path, 'rb') as handle:
            data = handle.read()
        try:
            data.decode('ascii')
        except UnicodeDecodeError as exc:  # pragma: no cover
            self.fail(f"{source_path} contains non-ASCII bytes: {exc}")

    def test_extract_keys_handles_embedded_other_quote(self):
        # A single-quoted key may legally contain " (and a double-quoted key ');
        # a [^'"] key-body class drops the WHOLE key, so its missing translation
        # silently escapes the coverage check. The body must run up to the CLOSING
        # quote only.
        src = 'self._(\'Click "Next"\')\nself._("it\'s here")\nself._(\'plain\')'
        keys = T.extract_source_keys(src)
        self.assertIn('Click "Next"', keys)
        self.assertIn("it's here", keys)
        self.assertIn('plain', keys)


if __name__ == '__main__':
    unittest.main()
