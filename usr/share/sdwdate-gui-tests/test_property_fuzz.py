#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Hypothesis property-based tests for sdwdate-gui's untrusted-input parsers.

Layer 1 of the fuzzing convention: complements the in-process random fuzzer
(usr/share/sdwdate-gui-tests/fuzz) by generating arbitrary inputs and asserting
invariants that must hold for ALL inputs to the real parser / validation
surfaces that face variable or attacker-influenced data. Every property drives
the REAL functions imported from sdwdate_gui; nothing is reimplemented here.

Covered surfaces:
  - sdwdate_gui_shared.parse_ipc_command: the length-prefixed wire-frame parser
    (2-byte big-endian length, MAX_MSG_SIZE cap, printable-ASCII check, split
    on space). Never raises anything but ValueError; its returned buffer is
    always a suffix of the input, and strictly shorter once a frame was
    consumed; a validly framed message round-trips to the same name + parts.
  - SdwdateGuiClient.__set_sdwdate_status / __octal_decode: the octal-escape
    (\\NNN) decode path for status messages. Arbitrary content decodes or
    cleanly kicks the client (returns False), never raising uncaught; safe
    escapes decode to exactly their character; unsafe escapes are rejected.
  - sdwdate_gui_shared.parse_config_files: arbitrary config-file bytes either
    parse to the typed schema or fail gracefully (ValueError / SchemaError),
    never crashing with an unexpected type and never yielding a value that
    violates the schema.

python3-hypothesis is a declared dependency of this suite; it is imported, not
importorskip'd, so its absence is a broken environment rather than a silent
pass. PyQt5 and the sdwdate_gui package are the suite's existing requirement;
their absence surfaces as a skip exactly as in the sibling tests.
"""

# pylint: disable=invalid-name,protected-access,no-name-in-module
# pylint: disable=wrong-import-position

import os
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import schema  # type: ignore
from hypothesis import given, settings, strategies as st

from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_server as server
    from sdwdate_gui import sdwdate_gui_shared as shared
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
        "or set PYTHONPATH to its dist-packages directory"
    ) from exc


_APP: QApplication = (
    QApplication.instance() or QApplication(["sdwdate-gui-tests"])
)

## Printable-ASCII payload bytes: exactly the range check_bytes_printable
## accepts, i.e. a frame body that parse_ipc_command decodes rather than
## rejecting. Bounded well under MAX_MSG_SIZE so framing stays cheap.
_printable_payload = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    min_size=1,
    max_size=256,
).map(lambda s: s.encode("ascii"))

## Safe octal escapes: every codepoint __octal_decode accepts, i.e. printable
## ASCII plus newline, each rendered as the real 3-digit octal escape.
_SAFE_CODEPOINTS: list[int] = list(range(0x20, 0x7F)) + [0x0A]
_safe_escape = st.sampled_from(
    [("\\" + format(cp, "03o"), chr(cp)) for cp in _SAFE_CODEPOINTS]
)
## Literal characters that are not part of an escape: printable ASCII minus the
## backslash, so the only regex-matchable escapes in a message are the ones the
## strategy inserts deliberately.
_literal_char = st.text(
    alphabet=st.characters(
        min_codepoint=0x20, max_codepoint=0x7E, exclude_characters="\\"
    ),
    min_size=1,
    max_size=1,
).map(lambda ch: (ch, ch))

## Octal escapes __octal_decode must reject: out-of-range codepoints, and
## three-digit groups that are not valid base-8 at all (contain 8 or 9).
_UNSAFE_OCTAL: list[str] = [
    "000", "001", "037", "177", "200", "377", "808", "888", "999",
]


def _mangled(obj: object, name: str):
    return getattr(obj, f"_SdwdateGuiClient__{name}")


def _frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(2, "big") + payload


class TestParseIpcCommandProperties(unittest.TestCase):
    """Invariants of shared.parse_ipc_command over arbitrary input."""

    @settings(max_examples=400, deadline=None)
    @given(buf=st.binary(max_size=8192))
    def test_arbitrary_bytes_contract(self, buf: bytes) -> None:
        """
        Over ANY byte buffer: raises only ValueError; the returned remaining
        buffer is a suffix of the input and never longer; name and parts are
        both None or both set together; and when a frame was consumed (name is
        set) the remaining buffer is strictly shorter.
        """
        try:
            rest, name, parts = shared.parse_ipc_command(buf)
        except ValueError:
            return
        self.assertIsInstance(rest, bytes)
        self.assertTrue(buf.endswith(rest))
        self.assertLessEqual(len(rest), len(buf))
        self.assertEqual(name is None, parts is None)
        if name is not None:
            self.assertIsInstance(name, str)
            self.assertIsInstance(parts, list)
            self.assertLess(len(rest), len(buf))

    @settings(max_examples=300, deadline=None)
    @given(payload=_printable_payload, tail=st.binary(max_size=64))
    def test_valid_frame_round_trips(
        self, payload: bytes, tail: bytes
    ) -> None:
        """
        A validly framed printable-ASCII message parses back to a name + parts
        whose single-space join reconstructs the exact payload, consumes only
        its own frame, and returns the trailing bytes untouched.
        """
        rest, name, parts = shared.parse_ipc_command(_frame(payload) + tail)
        self.assertIsNotNone(name)
        assert name is not None and parts is not None
        self.assertEqual(" ".join([name] + parts), payload.decode("ascii"))
        self.assertEqual(rest, tail)


class _ClientPropertyBase(unittest.TestCase):
    """A ready SdwdateGuiClient on an unconnected socket, name already set."""

    def setUp(self) -> None:
        self.client = server.SdwdateGuiClient(QLocalSocket())
        self.addCleanup(self.client.deleteLater)
        self.client.client_name = "host"
        self.client.client_name_set = True

    def _set_status(self, status: str, msg: str) -> bool:
        return _mangled(self.client, "set_sdwdate_status")(status, msg)


class TestOctalDecodeProperties(_ClientPropertyBase):
    """Invariants of the __set_sdwdate_status octal-decode path."""

    @settings(max_examples=300, deadline=None)
    @given(
        status=st.sampled_from(["success", "busy", "error"]),
        msg=st.text(max_size=256),
    )
    def test_arbitrary_message_never_raises(
        self, status: str, msg: str
    ) -> None:
        """
        Any status message returns a bool and never raises: a decode failure
        is caught and turned into a client kick, not an uncaught exception.
        """
        with mock.patch.object(self.client, "kick_client") as kick:
            result = self._set_status(status, msg)
        self.assertIsInstance(result, bool)
        if result:
            kick.assert_not_called()
        else:
            kick.assert_called()

    @settings(max_examples=300, deadline=None)
    @given(tokens=st.lists(st.one_of(_literal_char, _safe_escape), max_size=40))
    def test_safe_escapes_decode_exactly(
        self, tokens: list[tuple[str, str]]
    ) -> None:
        """
        A message built only from literals and in-range octal escapes is
        accepted, and every escape decodes to exactly its character.
        """
        msg = "".join(raw for raw, _ in tokens)
        expected = "".join(decoded for _, decoded in tokens)
        with mock.patch.object(self.client, "kick_client") as kick:
            result = self._set_status("success", msg)
        self.assertTrue(result)
        kick.assert_not_called()
        self.assertEqual(self.client.sdwdate_msg, expected)

    @settings(max_examples=200, deadline=None)
    @given(
        bad=st.sampled_from(_UNSAFE_OCTAL),
        prefix=st.text(
            alphabet=st.characters(
                min_codepoint=0x61, max_codepoint=0x7A
            ),
            max_size=16,
        ),
        suffix=st.text(
            alphabet=st.characters(
                min_codepoint=0x61, max_codepoint=0x7A
            ),
            max_size=16,
        ),
    )
    def test_unsafe_escape_kicks(
        self, bad: str, prefix: str, suffix: str
    ) -> None:
        """
        A message containing an out-of-range or non-octal \\NNN escape is
        rejected: the call returns False and the client is kicked.
        """
        msg = prefix + "\\" + bad + suffix
        with mock.patch.object(self.client, "kick_client") as kick:
            with self.assertLogs(level="WARNING"):
                result = self._set_status("success", msg)
        self.assertFalse(result)
        kick.assert_called()


def _valid_config_bytes(draw: st.DrawFn) -> bytes:
    """Render a schema-valid sdwdate-gui config to TOML bytes."""
    lines: list[str] = []
    if draw(st.booleans()):
        lines.append(f"disable = {str(draw(st.booleans())).lower()}")
    if draw(st.booleans()):
        lines.append(
            f"run_server_in_qubes = {str(draw(st.booleans())).lower()}"
        )
    if draw(st.booleans()):
        gw = draw(
            st.text(
                alphabet=st.characters(
                    min_codepoint=0x61, max_codepoint=0x7A
                ),
                max_size=20,
            )
        )
        lines.append(f'gateway = "{gw}"')
    return ("\n".join(lines) + "\n").encode("ascii")


@st.composite
def _config_content(draw: st.DrawFn) -> bytes:
    """Arbitrary bytes, a valid config, or a valid config plus a stray key."""
    arm = draw(st.integers(min_value=0, max_value=2))
    if arm == 0:
        return draw(st.binary(max_size=512))
    if arm == 1:
        return _valid_config_bytes(draw)
    stray = draw(
        st.text(
            alphabet=st.characters(min_codepoint=0x61, max_codepoint=0x7A),
            min_size=1,
            max_size=12,
        )
    )
    return _valid_config_bytes(draw) + f'{stray} = 1\n'.encode("ascii")


class TestParseConfigFilesProperties(unittest.TestCase):
    """Invariants of shared.parse_config_files over arbitrary file content."""

    _ALLOWED_KEYS = {"disable", "run_server_in_qubes", "gateway"}

    def setUp(self) -> None:
        self._orig_dir_list = shared.ConfigData.conf_dir_list
        self._orig_conf_dict = shared.ConfigData.conf_dict
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._conf_path = Path(self._tmp.name) / "10_fuzz.conf"
        shared.ConfigData.conf_dir_list = [self._tmp.name]

    def tearDown(self) -> None:
        shared.ConfigData.conf_dir_list = self._orig_dir_list
        shared.ConfigData.conf_dict = self._orig_conf_dict

    @settings(max_examples=250, deadline=None)
    @given(content=_config_content())
    def test_parses_to_schema_or_fails_gracefully(
        self, content: bytes
    ) -> None:
        """
        Any config-file content either parses to a schema-valid dict whose keys
        are a subset of the known options, or fails with the documented
        ValueError / SchemaError; it never crashes otherwise and never produces
        a value the schema rejects.
        """
        self._conf_path.write_bytes(content)
        try:
            shared.parse_config_files()
        except (ValueError, schema.SchemaError):
            return
        result = shared.ConfigData.conf_dict
        self.assertIsInstance(result, dict)
        ## Re-validating must not raise: the returned object satisfies the
        ## schema it was checked against.
        shared.ConfigData.conf_schema.validate(result)
        self.assertTrue(set(result).issubset(self._ALLOWED_KEYS))
        self.assertIsInstance(result["disable"], bool)
        self.assertIsInstance(result["run_server_in_qubes"], bool)
        self.assertIsInstance(result["gateway"], str)


if __name__ == "__main__":
    unittest.main()
