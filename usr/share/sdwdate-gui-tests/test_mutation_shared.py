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

    def test_qrexec_header_max_size_is_4096(self) -> None:
        self.assertEqual(shared.QREXEC_HEADER_MAX_SIZE, 4096)

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


class TestParseIpcCommandBoundary(unittest.TestCase):
    """parse_ipc_command length/sign/framing boundaries."""

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        return len(payload).to_bytes(2, "big") + payload

    def test_exactly_max_accepted(self) -> None:
        """A body of EXACTLY MAX_MSG_SIZE bytes is accepted (pins `> MAX`)."""
        payload = b"a" * 4096
        rest, name, parts = shared.parse_ipc_command(self._frame(payload))
        self.assertEqual(name, "a" * 4096)
        self.assertEqual(parts, [])
        self.assertEqual(rest, b"")

    def test_one_over_max_rejected(self) -> None:
        """A declared length of 4097 is rejected regardless of body."""
        with self.assertRaises(ValueError):
            shared.parse_ipc_command((4097).to_bytes(2, "big") + b"x")

    def test_high_bit_length_is_unsigned(self) -> None:
        """A 0xFFFF prefix decodes unsigned (65535 > MAX -> raise), not -1."""
        with self.assertRaises(ValueError):
            shared.parse_ipc_command(b"\xff\xff")

    def test_one_byte_short_is_incomplete(self) -> None:
        """len == msg_len+1 (one byte short of a full frame) -> incomplete."""
        ## Declares 8 body bytes, supplies 7 -> total len = msg_len+1.
        buf = (8).to_bytes(2, "big") + b"abcdefg"
        rest, name, parts = shared.parse_ipc_command(buf)
        self.assertEqual(rest, buf)
        self.assertIsNone(name)
        self.assertIsNone(parts)

    def test_prefix_only_small_len_is_incomplete(self) -> None:
        """A bare 2-byte prefix (msg_len=2, no body) is incomplete.

        Kills the `+2 -> |2 / ^2 / -2` frame-arithmetic mutants: with msg_len=2
        each of those lowers the completeness threshold to <= 2, so the mutant
        would wrongly try to parse an absent body.
        """
        buf = (2).to_bytes(2, "big")
        rest, name, parts = shared.parse_ipc_command(buf)
        self.assertEqual(rest, buf)
        self.assertIsNone(name)
        self.assertIsNone(parts)


class TestParseQrexecHeader(unittest.TestCase):
    """parse_qrexec_header NUL scan, overflow boundary, and field split."""

    def test_buffer_advanced_past_nul(self) -> None:
        """The returned buffer starts exactly one byte past the NUL."""
        buf, result, name = shared.parse_qrexec_header(b"svc src\x00REST")
        self.assertEqual(result, shared.QrexecHeaderResult.OK)
        self.assertEqual(name, "src")
        self.assertEqual(buf, b"REST")

    def test_stops_at_first_nul(self) -> None:
        """Scanning stops at the FIRST NUL; a later NUL is left in the buffer."""
        buf, result, name = shared.parse_qrexec_header(b"svc src\x00extra\x00")
        self.assertEqual(result, shared.QrexecHeaderResult.OK)
        self.assertEqual(name, "src")
        self.assertEqual(buf, b"extra\x00")

    def test_no_nul_within_cap_needs_more(self) -> None:
        """A short, unterminated header asks for more (not OVERFLOW)."""
        buf, result, name = shared.parse_qrexec_header(b"abc")
        self.assertEqual(result, shared.QrexecHeaderResult.NEED_MORE)
        self.assertIsNone(name)
        self.assertEqual(buf, b"abc")

    def test_exactly_cap_no_nul_needs_more(self) -> None:
        """len == cap with no NUL is still NEED_MORE (pins `> cap`)."""
        buf, result, _ = shared.parse_qrexec_header(
            b"a" * shared.QREXEC_HEADER_MAX_SIZE
        )
        self.assertEqual(result, shared.QrexecHeaderResult.NEED_MORE)

    def test_over_cap_no_nul_overflow(self) -> None:
        """len == cap+1 with no NUL is OVERFLOW."""
        _, result, _ = shared.parse_qrexec_header(
            b"a" * (shared.QREXEC_HEADER_MAX_SIZE + 1)
        )
        self.assertEqual(result, shared.QrexecHeaderResult.OVERFLOW)

    def test_three_field_header_keeps_source_vm(self) -> None:
        """A 3-field header still returns the second field as the name.

        Pins `len(parts) < 2` against `!= 2`: a 3-field header has len 3, which
        `!= 2` would wrongly treat as nameless.
        """
        _, result, name = shared.parse_qrexec_header(b"svc src extra\x00")
        self.assertEqual(result, shared.QrexecHeaderResult.OK)
        self.assertEqual(name, "src")

    def test_invalid_bytes_in_header(self) -> None:
        """A non-printable header byte is reported INVALID."""
        _, result, _ = shared.parse_qrexec_header(b"sv\x01c src\x00")
        self.assertEqual(result, shared.QrexecHeaderResult.INVALID)


class TestOctalEscapeBoundary(unittest.TestCase):
    """decode_status_octal_escapes bounds: 0x20..0x7E plus newline (0x0A)."""

    def test_tilde_is_printable_upper_bound(self) -> None:
        """\\176 == octal 126 == 0x7E (~) decodes (pins `> 0x7E`)."""
        self.assertEqual(shared.decode_status_octal_escapes("\\176"), "~")

    def test_del_byte_rejected(self) -> None:
        """\\177 == octal 127 == 0x7F (DEL) is rejected."""
        with self.assertRaises(ValueError):
            shared.decode_status_octal_escapes("\\177")

    def test_space_lower_bound_and_newline(self) -> None:
        """\\040 (space, 0x20) and \\012 (newline, 0x0A exception) decode."""
        self.assertEqual(shared.decode_status_octal_escapes("\\040"), " ")
        self.assertEqual(shared.decode_status_octal_escapes("\\012"), "\n")

    def test_control_byte_rejected(self) -> None:
        """\\037 == 0x1F (just below space) is rejected."""
        with self.assertRaises(ValueError):
            shared.decode_status_octal_escapes("\\037")


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
