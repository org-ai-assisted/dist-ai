#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression: config.allowed_failures_config must not crash the daemon at startup
on a malformed /etc/sdwdate.d conf file.

A "MAX_FAILURE_RATIO" line with no "=" leaves re.search None (an AttributeError
on .group), and a non-numeric value crashes float() one level up in
allowed_failures_calculate. Both must fall back to the default ratio. Found in
ai-review of the parser-hardening change.

The conf directory is faked by patching config.os.path.exists + config.glob so
the real parser runs against a temp file, never /etc.
"""

import os
import tempfile
import unittest

import fuzz_sdwdate


class AllowedFailuresConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = fuzz_sdwdate._load_config()

    def _ratio_for(self, conf_text):
        handle, path = tempfile.mkstemp(suffix='.conf')
        os.close(handle)
        self.addCleanup(os.unlink, path)
        with open(path, 'w', encoding='utf-8') as conf:
            conf.write(conf_text)
        cfg = self.config
        saved_exists, saved_glob = cfg.os.path.exists, cfg.glob.glob
        cfg.os.path.exists = lambda target: True
        cfg.glob.glob = lambda pattern: [path]
        try:
            return cfg.allowed_failures_config()
        finally:
            cfg.os.path.exists = saved_exists
            cfg.glob.glob = saved_glob

    def test_max_failure_ratio_without_equals_uses_default(self):
        self.assertEqual(self._ratio_for('MAX_FAILURE_RATIO\n'), 0.34)

    def test_non_numeric_ratio_uses_default(self):
        self.assertEqual(self._ratio_for('MAX_FAILURE_RATIO=abc\n'), 0.34)

    def test_valid_ratio_is_parsed(self):
        self.assertEqual(self._ratio_for('MAX_FAILURE_RATIO=0.5\n'), 0.5)

    def test_calculate_survives_with_the_parsed_ratio(self):
        ## The value feeds allowed_failures_calculate(ratio, total, members);
        ## a float ratio must compute without raising.
        ratio = self._ratio_for('MAX_FAILURE_RATIO=abc\n')
        result = self.config.allowed_failures_calculate(ratio, 3, 9)
        self.assertIsInstance(result, int)


if __name__ == '__main__':
    unittest.main()
