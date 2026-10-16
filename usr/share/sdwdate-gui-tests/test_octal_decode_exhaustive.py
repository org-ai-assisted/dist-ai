#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Exhaustive verification of the sdwdate status octal-escape decoder.

The subject decodes status messages with `re.compile(r"\\\\\\d{3}")` + a per-match
`__octal_decode`, so every escape the decoder can ever see is a backslash
followed by exactly three DECIMAL digits -- a finite domain of 1000 values
(000..999). This drives the REAL `__set_sdwdate_status` (which applies the
subject's own regex and decoder) over all 1000 and checks each against an
independent oracle. A finite, total proof the CrossHair budget cannot give; it
also pins the accept/reject boundary (0x20..0x7E plus 0x0A, octal digits only).

Drives the real subject -- no vendored copy of the pattern or the decoder.
"""

# pylint: disable=invalid-name,protected-access,no-name-in-module
# pylint: disable=wrong-import-position,import-outside-toplevel

import os
import unittest
import unittest.mock as mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard

    subject_guard.skip_if_subject_absent(exc)

_APP = QApplication.instance() or QApplication(["octal-exhaustive"])

## The safe range the decoder enforces: printable ASCII plus newline.
_LF = 0x0A
_MIN = 0x20
_MAX = 0x7E


def _oracle(nnn: str) -> "int | None":
    """Expected decoded codepoint for escape '\\NNN', or None if it must be
    rejected (non-octal digit, or octal value outside the safe range)."""
    if any(ch not in "01234567" for ch in nnn):
        return None
    value = int(nnn, 8)
    if _MIN <= value <= _MAX or value == _LF:
        return value
    return None


class OctalDecodeExhaustive(unittest.TestCase):
    """All 1000 \\NNN escapes through the real set_sdwdate_status path."""

    def setUp(self) -> None:
        self.cli = server.SdwdateGuiClient(QLocalSocket())
        self.addCleanup(self.cli.deleteLater)
        self.cli.client_name = "host"
        self.cli.client_name_set = True

    def _set(self, status: str, msg: str) -> bool:
        return getattr(self.cli, "_SdwdateGuiClient__set_sdwdate_status")(
            status, msg
        )

    def test_all_1000_three_digit_escapes(self) -> None:
        accepted = 0
        rejected = 0
        for n in range(1000):
            nnn = f"{n:03d}"
            expected = _oracle(nnn)
            msg = f"a\\{nnn}b"
            with self.subTest(escape=nnn):
                ## kick_client is mocked so a rejected escape does not tear the
                ## socket down; we assert on the return value + decoded output.
                with mock.patch.object(self.cli, "kick_client") as kc:
                    ok = self._set("success", msg)
                if expected is None:
                    self.assertFalse(
                        ok, f"\\{nnn} should be rejected but was accepted"
                    )
                    kc.assert_called_once()
                    rejected += 1
                else:
                    self.assertTrue(
                        ok, f"\\{nnn} should decode but was rejected"
                    )
                    kc.assert_not_called()
                    self.assertEqual(
                        self.cli.sdwdate_msg, f"a{chr(expected)}b"
                    )
                    accepted += 1
        ## Sanity: the domain really did split both ways (not vacuously green).
        self.assertEqual(accepted + rejected, 1000)
        self.assertGreater(accepted, 0)
        self.assertGreater(rejected, 0)


if __name__ == "__main__":
    unittest.main()
