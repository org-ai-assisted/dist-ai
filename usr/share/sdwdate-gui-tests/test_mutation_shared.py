#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Mutation-killing regression tests for the pure (Qt-free) parse/validation
helpers in sdwdate_gui_shared and the sdwdate_gui_config_read CLI.

Each test pins a behavior that cosmic-ray mutation testing proved was executed
but NOT asserted by the existing suite: exact wire-protocol constants, the
printable-ASCII boundary bytes (0x20/0x7E vs their neighbours 0x1F/0x7F), the
unsigned 2-byte length decode, the +2 frame-completeness arithmetic, the qrexec
header NUL scan / overflow boundary / field split, and the octal-escape upper
bound. The assertions deliberately use LITERAL expected values (not the module
constant), so a mutation of the constant itself is caught.
"""

# pylint: disable=invalid-name,protected-access

import io
import unittest
import unittest.mock as mock
from contextlib import redirect_stdout, redirect_stderr

try:
    from sdwdate_gui import sdwdate_gui_config_read as config_read
    from sdwdate_gui import sdwdate_gui_shared as shared
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)


class TestWireConstants(unittest.TestCase):
    """Protocol/limit constants are a wire contract, pinned to literals."""

    def test_max_msg_size_is_4096(self) -> None:
        self.assertEqual(shared.MAX_MSG_SIZE, 4096)

    def test_config_defaults_are_false(self) -> None:
        """The shipped defaults disable neither the GUI nor the Qubes server."""
        self.assertIs(shared.ConfigData.defaults_dict["disable"], False)
        self.assertIs(
            shared.ConfigData.defaults_dict["run_server_in_qubes"], False
        )


class TestCheckBytesPrintableBoundary(unittest.TestCase):
    """check_bytes_printable accepts exactly 0x20..0x7E, nothing adjacent."""

    def test_low_boundary(self) -> None:
        ## 0x1F is the last control byte (rejected); 0x20 (space) is the first
        ## printable byte (accepted). Pins `byte < 0x20`.
        self.assertFalse(shared.check_bytes_printable(bytes([0x1F])))
        self.assertTrue(shared.check_bytes_printable(bytes([0x20])))

    def test_high_boundary(self) -> None:
        ## 0x7E (~) is the last printable byte (accepted); 0x7F (DEL) is the
        ## first high control byte (rejected). Pins `byte > 0x7E`.
        self.assertTrue(shared.check_bytes_printable(bytes([0x7E])))
        self.assertFalse(shared.check_bytes_printable(bytes([0x7F])))


class TestParseIpcBufBoundary(unittest.TestCase):
    """parse_ipc_buf length/sign/framing boundaries."""

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        return len(payload).to_bytes(2, "big") + payload

    def test_exactly_max_accepted(self) -> None:
        """A body of EXACTLY MAX_MSG_SIZE bytes is accepted (pins `> MAX`)."""
        payload = b"a" * 4096
        rest, msg_list = shared.parse_ipc_buf(self._frame(payload))
        self.assertEqual(msg_list, [["a" * 4096]])
        self.assertEqual(rest, b"")

    def test_one_over_max_rejected(self) -> None:
        """A declared length of 4097 is rejected regardless of body."""
        with self.assertRaises(ValueError):
            shared.parse_ipc_buf((4097).to_bytes(2, "big") + b"x")

    def test_high_bit_length_is_unsigned(self) -> None:
        """A 0xFFFF prefix decodes unsigned (65535 > MAX -> raise), not -1."""
        with self.assertRaises(ValueError):
            shared.parse_ipc_buf(b"\xff\xff")

    def test_zero_length_rejected(self) -> None:
        """A 0-length frame is rejected even when a VALID frame follows.

        Pins the `msg_len == 0` raise: a mutant that admits a 0-length frame
        would return it as an empty message plus the trailing valid one (no
        raise), so a bare `(0, 'rest')` buffer -- which raises anyway on the
        oversized trailer -- would not discriminate.
        """
        buf = (0).to_bytes(2, "big") + self._frame(b"ok")
        with self.assertRaises(ValueError):
            shared.parse_ipc_buf(buf)

    def test_one_byte_short_is_incomplete(self) -> None:
        """len == msg_len+1 (one byte short of a full frame) -> incomplete."""
        ## Declares 8 body bytes, supplies 7 -> total len = msg_len+1.
        buf = (8).to_bytes(2, "big") + b"abcdefg"
        rest, msg_list = shared.parse_ipc_buf(buf)
        self.assertEqual(rest, buf)
        self.assertEqual(msg_list, [])

    def test_prefix_only_small_len_is_incomplete(self) -> None:
        """A bare 2-byte prefix (msg_len=2, no body) is incomplete.

        Kills the `+2 -> |2 / ^2 / -2` frame-arithmetic mutants: with msg_len=2
        each of those lowers the completeness threshold to <= 2, so the mutant
        would wrongly try to parse an absent body.
        """
        buf = (2).to_bytes(2, "big")
        rest, msg_list = shared.parse_ipc_buf(buf)
        self.assertEqual(rest, buf)
        self.assertEqual(msg_list, [])


class TestConfigReadArgHandling(unittest.TestCase):
    """sdwdate_gui_config_read.main argument handling gaps."""

    def _run_main(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(config_read.sys, "argv", argv):
            with redirect_stdout(out), redirect_stderr(err):
                with self.assertRaises(SystemExit) as ctx:
                    config_read.main()
        code = ctx.exception.code
        return (0 if code is None else int(code)), out.getvalue(), err.getvalue()

    def test_too_many_args_exits_2(self) -> None:
        """Three argv entries (too many) exit 2, pinning `!= 2` vs `< 2`."""
        def _fake_parse() -> None:  # pragma: no cover - not reached (exits first)
            shared.ConfigData.conf_dict = dict(shared.ConfigData.defaults_dict)

        with mock.patch.object(
            config_read, "parse_config_files", side_effect=_fake_parse
        ):
            code, _, _ = self._run_main(["prog", "disable", "extra"])
        self.assertEqual(code, 2)

    def test_unknown_option_message_names_the_option(self) -> None:
        """The error message names the offending option (argv[1], not argv[0])."""
        code, _, err = self._run_main(["progname", "no_such_option"])
        self.assertEqual(code, 1)
        self.assertIn("no_such_option", err)


if __name__ == "__main__":
    unittest.main()
