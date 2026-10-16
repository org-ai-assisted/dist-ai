#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Property-fuzz the client's sdwdate-status file reader.

sdwdate_status_changed() parses /run/sdwdate/status, a JSON file written by the
local sdwdate daemon. It is not cross-VM attacker input, but a partial write or
corruption must never crash the client and must never forward a malformed
status to the server. These properties drive the REAL coroutine over arbitrary
file contents (garbage, arbitrary JSON including non-objects, and objects with
wrong-typed icon/message) and assert: it never raises, and set_sdwdate_status
is only ever called with a valid status and a string message.
"""

# pylint: disable=wrong-import-position,invalid-name

import asyncio
import builtins
import json
import unittest
import unittest.mock as mock

from hypothesis import given, settings
from hypothesis import strategies as st

try:
    from sdwdate_gui import sdwdate_gui_client as client
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)

## Arbitrary JSON values, including non-objects (int/bool/null/list/str) that a
## corrupt or truncated status file could decode to.
_json_values = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(max_size=20),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=8), children, max_size=4),
    ),
    max_leaves=8,
)

## File contents to feed: raw text/garbage, arbitrary JSON, and objects shaped
## like the real status with deliberately mistyped icon/message.
_status_raw = st.one_of(
    st.text(max_size=256),
    st.builds(json.dumps, _json_values),
    st.builds(
        lambda i, m: json.dumps({"icon": i, "message": m}),
        st.one_of(
            st.sampled_from(["success", "busy", "error", "bogus"]),
            st.integers(),
            st.none(),
        ),
        st.one_of(st.text(max_size=40), st.integers(), st.none()),
    ),
)

_SLOW = settings(max_examples=300, deadline=None)


class TestSdwdateStatusFileFuzz(unittest.TestCase):
    """sdwdate_status_changed never crashes and forwards only valid status."""

    @_SLOW
    @given(raw=_status_raw)
    def test_reader_never_crashes_and_forwards_only_valid(
        self, raw: str
    ) -> None:
        captured: list[tuple[str, str]] = []

        async def fake_set(status: str, msg: str) -> None:
            captured.append((status, msg))

        with mock.patch.object(
            client.os.path, "isfile", return_value=True
        ), mock.patch.object(
            builtins, "open", mock.mock_open(read_data=raw)
        ), mock.patch.object(
            client, "set_sdwdate_status", fake_set
        ):
            ## Must not raise for ANY file content.
            asyncio.run(client.sdwdate_status_changed())

        for status, msg in captured:
            self.assertIn(
                status, ("success", "busy", "error"),
                f"forwarded an invalid status {status!r}",
            )
            self.assertIsInstance(
                msg, str, "forwarded a non-string message",
            )

    def test_valid_status_is_forwarded(self) -> None:
        """Liveness oracle: a well-formed status file MUST forward exactly that
        status and message, once. The property above is safety-only (it never
        forwards a BAD status), so without this a subject that silently dropped
        every status would pass it vacuously."""
        cases = [
            ("success", "clock synced"),
            ("busy", "waiting for consensus"),
            ("error", "sdwdate failed"),
            ## a long message (no wire escaping here -- set_sdwdate_status is
            ## mocked -- so it must forward verbatim).
            ("success", "\\" * 1000),
        ]
        for icon, message in cases:
            with self.subTest(icon=icon, message_len=len(message)):
                captured: list[tuple[str, str]] = []

                async def fake_set(
                    status: str, msg: str, _cap: list = captured
                ) -> None:
                    _cap.append((status, msg))

                raw = json.dumps({"icon": icon, "message": message})
                with mock.patch.object(
                    client.os.path, "isfile", return_value=True
                ), mock.patch.object(
                    builtins, "open", mock.mock_open(read_data=raw)
                ), mock.patch.object(
                    client, "set_sdwdate_status", fake_set
                ):
                    asyncio.run(client.sdwdate_status_changed())
                self.assertEqual(
                    captured,
                    [(icon, message)],
                    "a valid status file was not forwarded exactly once",
                )


if __name__ == "__main__":
    unittest.main()
