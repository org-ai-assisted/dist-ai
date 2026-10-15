#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit tests for sdwdate_gui_config_read.main and the IPC/parse helpers in
sdwdate_gui_shared. These modules carry no Qt dependency and are driven
directly; parse_config_files is patched so the tests do not depend on the
machine's /etc/sdwdate-gui.d contents.
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


class TestConfigReadMain(unittest.TestCase):
    """sdwdate_gui_config_read.main CLI behavior."""

    def _run_main(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(config_read.sys, 'argv', argv):
            with redirect_stdout(out), redirect_stderr(err):
                with self.assertRaises(SystemExit) as ctx:
                    config_read.main()
        code = ctx.exception.code
        return (0 if code is None else int(code)), out.getvalue(), err.getvalue()

    def test_wrong_arg_count_exits_2(self) -> None:
        """No key argument -> exit 2."""
        code, _, _ = self._run_main(['sdwdate-gui-config-read'])
        self.assertEqual(code, 2)

    def test_unknown_option_exits_1(self) -> None:
        """An option not in defaults_dict -> error on stderr, exit 1."""
        code, _, err = self._run_main(['x', 'no_such_option'])
        self.assertEqual(code, 1)
        self.assertIn('Unrecognized configuration option', err)

    def test_parse_failure_exits_1(self) -> None:
        """A config-parse exception -> error + traceback on stderr, exit 1."""
        with mock.patch.object(
            config_read, 'parse_config_files', side_effect=OSError('boom')
        ):
            code, _, err = self._run_main(['x', 'gateway'])
        self.assertEqual(code, 1)
        self.assertIn('Configuration file parsing failed', err)

    def test_bool_value_lowercased(self) -> None:
        """A bool config value prints as Bash-style lowercase, exit 0."""
        def _fake_parse() -> None:
            shared.ConfigData.conf_dict = dict(shared.ConfigData.defaults_dict)
            shared.ConfigData.conf_dict['disable'] = True

        with mock.patch.object(
            config_read, 'parse_config_files', side_effect=_fake_parse
        ):
            code, out, _ = self._run_main(['x', 'disable'])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), 'true')

    def test_string_value_printed(self) -> None:
        """A non-bool config value prints verbatim, exit 0."""
        def _fake_parse() -> None:
            shared.ConfigData.conf_dict = dict(shared.ConfigData.defaults_dict)
            shared.ConfigData.conf_dict['gateway'] = 'sys-test-gw'

        with mock.patch.object(
            config_read, 'parse_config_files', side_effect=_fake_parse
        ):
            code, out, _ = self._run_main(['x', 'gateway'])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), 'sys-test-gw')


class TestCheckBytesPrintable(unittest.TestCase):
    """shared.check_bytes_printable accepts only printable ASCII."""

    def test_all_printable(self) -> None:
        self.assertTrue(shared.check_bytes_printable(b'hello 123 ~'))

    def test_control_byte_rejected(self) -> None:
        self.assertFalse(shared.check_bytes_printable(b'ok\x00'))

    def test_high_byte_rejected(self) -> None:
        self.assertFalse(shared.check_bytes_printable(b'ok\xff'))


class TestParseIpcBuf(unittest.TestCase):
    """shared.parse_ipc_buf framing + validation."""

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        return len(payload).to_bytes(2, 'big') + payload

    def test_full_command_parsed(self) -> None:
        buf = self._frame(b'set_tor_status running')
        rest, msg_list = shared.parse_ipc_buf(buf)
        self.assertEqual(msg_list, [['set_tor_status', 'running']])
        self.assertEqual(rest, b'')

    def test_two_frames_parsed_in_one_pass(self) -> None:
        buf = self._frame(b'set_tor_status running') + self._frame(b'a b c')
        rest, msg_list = shared.parse_ipc_buf(buf)
        self.assertEqual(
            msg_list, [['set_tor_status', 'running'], ['a', 'b', 'c']]
        )
        self.assertEqual(rest, b'')

    def test_oversized_length_raises(self) -> None:
        buf = (shared.MAX_MSG_SIZE + 1).to_bytes(2, 'big') + b'x'
        with self.assertRaises(ValueError):
            shared.parse_ipc_buf(buf)

    def test_partial_message_returns_unchanged(self) -> None:
        ## Claims 10 bytes but only 3 present -> buffer returned unchanged,
        ## no complete messages yet.
        buf = (10).to_bytes(2, 'big') + b'abc'
        rest, msg_list = shared.parse_ipc_buf(buf)
        self.assertEqual(rest, buf)
        self.assertEqual(msg_list, [])

    def test_zero_length_message_raises(self) -> None:
        ## An empty (0-length) frame is now rejected outright.
        buf = (0).to_bytes(2, 'big') + b'rest'
        with self.assertRaises(ValueError):
            shared.parse_ipc_buf(buf)

    def test_nonprintable_payload_raises(self) -> None:
        buf = self._frame(b'ab\x01cd')
        with self.assertRaises(ValueError):
            shared.parse_ipc_buf(buf)


class TestParseConfigFiles(unittest.TestCase):
    """shared.parse_config_files delegates to strict_config_parser."""

    def test_populates_conf_dict(self) -> None:
        sentinel = {'disable': False, 'run_server_in_qubes': True,
                    'gateway': 'sys-x'}
        with mock.patch(
            'sdwdate_gui.sdwdate_gui_shared.strict_config_parser.'
            'parse_config_files',
            return_value=sentinel,
        ):
            shared.parse_config_files()
        self.assertEqual(shared.ConfigData.conf_dict, sentinel)


if __name__ == '__main__':
    unittest.main()
