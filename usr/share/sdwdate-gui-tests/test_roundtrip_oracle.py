#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Differential round-trip oracle: the CLIENT encodes an sdwdate status message
(escaping space/newline/backslash to octal) and the SERVER decodes it. For any
message of the supported alphabet (printable ASCII + newline), client-encode
followed by server-decode must reproduce the original. This cross-checks the
two independent halves against each other -- an asymmetry (a char the client
escapes but the server mis/does-not decode, or vice versa) fails the property,
which per-side fuzzing of each half alone would not catch.
"""

# pylint: disable=wrong-import-position,invalid-name,protected-access

import asyncio
import unittest
import unittest.mock as mock

from hypothesis import given, settings
from hypothesis import strategies as st

from PyQt5.QtWidgets import QApplication
from PyQt5.QtNetwork import QLocalSocket

try:
    from sdwdate_gui import sdwdate_gui_client as client
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)

_APP = QApplication.instance() or QApplication(["roundtrip-oracle"])

## The alphabet the encode/decode pair supports: printable ASCII plus newline.
_message = st.text(
    alphabet=st.one_of(
        st.characters(min_codepoint=0x20, max_codepoint=0x7E),
        st.just("\n"),
    ),
    max_size=200,
)


class TestEncodeDecodeRoundTrip(unittest.TestCase):
    """client set_sdwdate_status encode -> server __set_sdwdate_status decode."""

    @settings(max_examples=400, deadline=None)
    @given(
        status=st.sampled_from(["success", "busy", "error"]),
        message=_message,
    )
    def test_client_encode_server_decode_is_identity(
        self, status: str, message: str
    ) -> None:
        ## 1. Drive the REAL client encoder; capture the bytes it would send.
        ## hypothesis cannot run an async test method, so run the async encode
        ## via asyncio.run inside this sync property.
        sent: list[bytes] = []

        async def encode() -> None:
            async def capture(payload: bytes) -> None:
                sent.append(payload)

            with mock.patch.object(client, "generic_rpc_call", capture):
                await client.set_sdwdate_status(status, message)

        asyncio.run(encode())

        self.assertEqual(len(sent), 1)
        prefix = b"set_sdwdate_status " + status.encode("ascii") + b" "
        self.assertTrue(
            sent[0].startswith(prefix), f"unexpected frame: {sent[0]!r}"
        )
        encoded = sent[0][len(prefix):].decode("ascii")

        ## 2. Feed the encoded message through the REAL server decoder.
        sc = server.SdwdateGuiClient(QLocalSocket())
        self.addCleanup(sc.deleteLater)
        sc.client_name = "host"
        sc.client_name_set = True
        accepted = sc._SdwdateGuiClient__set_sdwdate_status(status, encoded)
        self.assertTrue(
            accepted,
            f"server rejected a client-encoded message: {encoded!r}",
        )

        ## 3. The decoded message must equal the original (after the client's
        ## documented ASCII-coerce + length cap, both identities for this
        ## alphabet and size).
        expected = (
            message.encode("ascii", "replace").decode("ascii")
        )[:client.MAX_STATUS_MSG_LEN]
        self.assertEqual(
            sc.sdwdate_msg, expected,
            f"round-trip mismatch: original={message!r} encoded={encoded!r} "
            f"decoded={sc.sdwdate_msg!r}",
        )


if __name__ == "__main__":
    unittest.main()
