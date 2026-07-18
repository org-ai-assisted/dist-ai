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

import contextlib
import io
import unittest

import yaml

from guimessages.translations import _translations

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


class UnknownLocaleFallbackTestCase(unittest.TestCase):
    """Regression guard for the guimessages chatter.

    The YAML ships only an 'en' section, so any non-English locale (or an unset
    C locale, as in the CI containers) must resolve to English SILENTLY. A
    guimessages bug used to make gettext() print
    'ERROR: No translation for language ...' on the first lookup of every
    translator; this asserts the wizard's translator no longer does.
    """

    def _text_and_stdout(self, language):
        translator = _translations(T.TRANSLATIONS_YAML, "setup-dist")
        translator.language = language
        translator.result = None
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            text = translator.gettext("finish_page_start")
        return text, buffer.getvalue()

    def test_unknown_language_is_silent(self):
        text, out = self._text_and_stdout("de")
        self.assertNotIn(
            "No translation",
            out,
            "guimessages emitted chatter for an unknown locale",
        )
        self.assertIsInstance(text, str)
        self.assertTrue(text.strip())

    def test_unknown_language_resolves_to_english(self):
        text, _ = self._text_and_stdout("de")
        english, _ = self._text_and_stdout("en")
        self.assertEqual(text, english)


if __name__ == "__main__":
    unittest.main()
