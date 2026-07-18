#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Translation coverage.

Every key the wizard resolves via self._('...') must exist in the shipped
translations YAML, or the wizard would display a raw key to the user. This
guards against a code/translation drift where a new message is referenced but
never translated (or a key is renamed on one side only).
"""

import unittest

import yaml

import swd_testlib as T


def _load_en_keys():
    with open(T.TRANSLATIONS_YAML, encoding="ascii") as handle:
        data = yaml.safe_load(handle)
    return data["setup-dist"]["en"]


class TranslationCoverageTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.en = _load_en_keys()

    def test_yaml_has_the_expected_shape(self):
        self.assertIsInstance(self.en, dict)
        self.assertTrue(self.en)

    def test_every_referenced_key_is_translated(self):
        self.assertTrue(T.SOURCE_KEYS, "no self._() keys found in the source")
        missing = sorted(k for k in T.SOURCE_KEYS if k not in self.en)
        self.assertEqual(
            missing, [], f"translation keys referenced but not defined: {missing}"
        )

    def test_translated_values_are_nonempty_strings(self):
        for key in sorted(T.SOURCE_KEYS):
            with self.subTest(key=key):
                value = self.en[key]
                self.assertIsInstance(value, str)
                self.assertTrue(value.strip())

    def test_yaml_is_ascii(self):
        with open(T.TRANSLATIONS_YAML, "rb") as handle:
            data = handle.read()
        try:
            data.decode("ascii")
        except UnicodeDecodeError as exc:  # pragma: no cover
            self.fail(f"{T.TRANSLATIONS_YAML} contains non-ASCII bytes: {exc}")


if __name__ == "__main__":
    unittest.main()
