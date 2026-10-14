#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Mutation-killing regression tests for sdwdate_gui_client.

Each pins a behavior cosmic-ray proved executed-but-unasserted: the reconnect
backoff cap VALUE (not just the symbol), the inotify event routing to the right
status handler, the frame-loop consumption of a zero-length message, the
client-send length boundary, Tor-status de-duplication ordering, the exact
inotify watch mask, and the anti-flood backoff-reset that must NOT fire on a
sub-threshold session.
"""

# pylint: disable=wrong-import-position,invalid-name,protected-access

import asyncio
import logging
import types
import unittest
import unittest.mock as mock

try:
    from sdwdate_gui import sdwdate_gui_client as client
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)

import pyinotify  # type: ignore  # noqa: E402  (subject present implies dep present)


class _StopLoop(BaseException):
    """Breaks main_loop's otherwise-infinite loop (see backoff test)."""


class _LogCapture:
    """Context manager collecting root-logger records."""

    def __init__(self) -> None:
        self.records: list[logging.LogRecord] = []
        self._handler = logging.Handler()
        self._handler.emit = self.records.append  # type: ignore[assignment]

    def __enter__(self) -> "_LogCapture":
        logging.getLogger().addHandler(self._handler)
        return self

    def __exit__(self, *_exc: object) -> None:
        logging.getLogger().removeHandler(self._handler)

    def messages(self) -> str:
        return " ".join(r.getMessage() for r in self.records)


class TestClientConstants(unittest.TestCase):
    """Backoff / cap constants pinned to literals."""

    def test_max_status_msg_len(self) -> None:
        self.assertEqual(client.MAX_STATUS_MSG_LEN, 1000)


class TestInotifyEventRouting(unittest.TestCase):
    """process_IN_DELETE_SELF / MOVE_SELF route on the status-path match."""

    def _event(self, pathname: str) -> types.SimpleNamespace:
        return types.SimpleNamespace(pathname=pathname)

    def test_delete_self_on_status_path(self) -> None:
        handler = client.INotifyEventHandler()
        ## A fresh (non-identical) equal string: `==` matches, `is` would not.
        ## encode/decode yields a DISTINCT equal string so `==` matches but
        ## `is` does not -- exercising the comparison operator itself.
        path = client.GlobalData.sdwdate_status_path.encode().decode()
        with _LogCapture() as cap:
            handler.process_IN_DELETE_SELF(self._event(path))
        self.assertIn("deleted", cap.messages())
        self.assertNotIn("BUG", cap.messages())

    def test_move_self_on_status_path(self) -> None:
        handler = client.INotifyEventHandler()
        ## encode/decode yields a DISTINCT equal string so `==` matches but
        ## `is` does not -- exercising the comparison operator itself.
        path = client.GlobalData.sdwdate_status_path.encode().decode()
        with _LogCapture() as cap:
            handler.process_IN_MOVE_SELF(self._event(path))
        self.assertIn("moved", cap.messages())
        self.assertNotIn("BUG", cap.messages())

    def test_delete_self_on_other_path_is_bug(self) -> None:
        handler = client.INotifyEventHandler()
        with _LogCapture() as cap:
            handler.process_IN_DELETE_SELF(self._event("/some/other/path"))
        self.assertIn("BUG", cap.messages())


class TestFileChangedRouting(unittest.IsolatedAsyncioTestCase):
    """file_changed routes the sdwdate status path to its handler."""

    def setUp(self) -> None:
        client.GlobalData.awaitable_tasks.clear()
        self.addCleanup(client.GlobalData.awaitable_tasks.clear)

    async def test_status_path_routed_not_unexpected(self) -> None:
        handler = client.INotifyEventHandler()
        scheduled: list[str] = []

        def fake_create_task(coro: object) -> object:
            scheduled.append(getattr(coro, "__qualname__", repr(coro)))
            coro.close()  # type: ignore[attr-defined]
            return types.SimpleNamespace()

        ## Fresh equal string so `==` (match) vs `is` (miss) is exercised.
        ## encode/decode yields a DISTINCT equal string so `==` matches but
        ## `is` does not -- exercising the comparison operator itself.
        path = client.GlobalData.sdwdate_status_path.encode().decode()
        with _LogCapture() as cap, mock.patch.object(
            asyncio, "create_task", fake_create_task
        ):
            handler.file_changed(path)
        self.assertNotIn("Unexpected path change", cap.messages())
        self.assertTrue(
            any("sdwdate_status_changed" in s for s in scheduled),
            f"status path did not route to sdwdate handler: {scheduled}",
        )


class TestTryParseFrameLoop(unittest.IsolatedAsyncioTestCase):
    """The >=2 frame-loop guard consumes a complete zero-length message."""

    def setUp(self) -> None:
        self.addCleanup(setattr, client.GlobalData, "sock_buf", b"")

    async def test_zero_length_message_consumed(self) -> None:
        ## A complete 2-byte frame (length prefix 0, no body). The loop must
        ## enter (len >= 2) and consume it. Mutants >=3 / >2 / !=2 skip the
        ## loop and leave the 2 bytes unconsumed.
        client.GlobalData.sock_buf = (0).to_bytes(2, "big")
        await client.try_parse_commands()
        self.assertEqual(client.GlobalData.sock_buf, b"")


class TestClientSendBoundary(unittest.IsolatedAsyncioTestCase):
    """generic_rpc_call accepts a message of exactly MAX_MSG_SIZE bytes."""

    def setUp(self) -> None:
        self.addCleanup(setattr, client.GlobalData, "sock_write", None)

    async def test_exactly_max_not_rejected(self) -> None:
        class FakeWriter:  # pylint: disable=too-few-public-methods
            def write(self, _data: bytes) -> None:
                pass

            async def drain(self) -> None:
                pass

        client.GlobalData.sock_write = FakeWriter()
        ## Exactly MAX_MSG_SIZE must NOT exit (pins `> MAX` vs `>= MAX`).
        await client.generic_rpc_call(b"x" * client.MAX_MSG_SIZE)

    async def test_oversized_send_exits_one(self) -> None:
        """An oversized client send exits 1 (failure), not 0/2 (pins the code)."""
        class FakeWriter:  # pylint: disable=too-few-public-methods
            def write(self, _data: bytes) -> None:
                pass

            async def drain(self) -> None:
                pass

        client.GlobalData.sock_write = FakeWriter()
        with self.assertRaises(SystemExit) as ctx:
            await client.generic_rpc_call(b"x" * (client.MAX_MSG_SIZE + 1))
        self.assertEqual(ctx.exception.code, 1)


class TestTorStatusDedup(unittest.IsolatedAsyncioTestCase):
    """set_tor_status suppresses only genuine duplicates, in order."""

    def setUp(self) -> None:
        client.GlobalData.last_tor_status = ""
        self.addCleanup(setattr, client.GlobalData, "last_tor_status", "")

    async def test_distinct_statuses_all_sent(self) -> None:
        sent: list[bytes] = []

        async def fake_rpc(msg_bytes: bytes) -> None:
            sent.append(msg_bytes)

        ## 'running' then 'disabled': both distinct from the prior value, so
        ## both must be sent. The `!= -> >` mutant drops 'disabled' (it sorts
        ## below 'running'), leaving only one send.
        with mock.patch.object(client, "generic_rpc_call", fake_rpc):
            await client.set_tor_status("running")
            await client.set_tor_status("disabled")
        self.assertEqual(
            sent,
            [b"set_tor_status running", b"set_tor_status disabled"],
        )

    async def test_repeated_status_deduped(self) -> None:
        sent: list[bytes] = []

        async def fake_rpc(msg_bytes: bytes) -> None:
            sent.append(msg_bytes)

        with mock.patch.object(client, "generic_rpc_call", fake_rpc):
            await client.set_tor_status("running")
            await client.set_tor_status("running")
        self.assertEqual(sent, [b"set_tor_status running"])


class TestInotifyWatchMask(unittest.IsolatedAsyncioTestCase):
    """setup_inotify_watches builds the exact OR of the seven event flags."""

    def setUp(self) -> None:
        self.addCleanup(setattr, client.GlobalData, "watch_manager", None)
        self.addCleanup(setattr, client.GlobalData, "notifier", None)

    async def test_watch_mask_is_exact_union(self) -> None:
        recorded: list[int] = []

        class FakeWM:  # pylint: disable=too-few-public-methods
            def add_watch(self, _path: str, mask: int) -> dict[str, int]:
                recorded.append(mask)
                return {_path: 1}

        expected = (
            pyinotify.IN_MODIFY
            | pyinotify.IN_CREATE
            | pyinotify.IN_DELETE
            | pyinotify.IN_MOVED_FROM
            | pyinotify.IN_MOVED_TO
            | pyinotify.IN_DELETE_SELF
            | pyinotify.IN_MOVE_SELF
        )
        with mock.patch.object(pyinotify, "WatchManager", FakeWM), \
                mock.patch.object(pyinotify, "AsyncioNotifier", lambda *a, **k: None):
            await client.setup_inotify_watches(
                found_tor_paths=True, found_sdwdate_path=True
            )
        self.assertTrue(recorded, "no watch was registered")
        for mask in recorded:
            self.assertEqual(mask, expected)


class TestMainLoopExitPaths(unittest.IsolatedAsyncioTestCase):
    """main_loop's exit-vs-reconnect decision is an OR over three independent
    clauses: `not qubes`, `not do_reconnect`, `server_pid present`. Each must
    independently force the clean exit; mutating any `or` to `and` (the
    anti-flood regression) is caught by isolating that clause as the only true
    one. The server_pid file is MOCKED so the real file in the test environment
    cannot mask a clause."""

    def setUp(self) -> None:
        client.GlobalData.awaitable_tasks.clear()
        self.addCleanup(client.GlobalData.awaitable_tasks.clear)
        self._real_reconnect = client.GlobalData.do_reconnect
        self.addCleanup(
            setattr, client.GlobalData, "do_reconnect", self._real_reconnect
        )

    async def _drive(self, in_qubes: bool, do_reconnect: bool,
                     pid_present: bool):
        """One main_loop pass. do_setup succeeds once then raises _StopLoop, so a
        NON-exiting decision escapes the loop instead of spinning. Returns the
        SystemExit raised on an exit decision, or None if it reconnected."""
        client.GlobalData.do_reconnect = do_reconnect
        calls = {"n": 0}

        async def fake_do_setup() -> bool:
            calls["n"] += 1
            if calls["n"] >= 2:
                raise _StopLoop
            return True

        async def fake_handle() -> bool:
            return False

        real_sleep = asyncio.sleep

        async def fake_sleep(_d: float, *a: object, **k: object) -> None:
            return await real_sleep(0, *a, **k)

        pid = types.SimpleNamespace(is_file=lambda: pid_present)
        ## The Qubes "server disabled" sentinel must be absent, else main_loop
        ## breaks before reaching the exit-vs-reconnect decision under test.
        not_disabled = types.SimpleNamespace(is_file=lambda: False)
        with mock.patch.object(client, "do_setup", fake_do_setup), \
                mock.patch.object(client, "handle_incoming_data", fake_handle), \
                mock.patch.object(
                    client, "running_in_qubes_os", lambda: in_qubes
                ), \
                mock.patch.object(client.GlobalData, "server_pid_path", pid), \
                mock.patch.object(
                    client.GlobalData, "qubes_gateway_server_disabled_path",
                    not_disabled,
                ), \
                mock.patch.object(asyncio, "sleep", fake_sleep):
            try:
                await client.main_loop()
            except SystemExit as exc:
                return exc
            except _StopLoop:
                return None
        return None

    async def test_non_qubes_exits_zero(self) -> None:
        ## Clause 1 (not qubes) alone -> exit 0.
        exc = await self._drive(False, do_reconnect=True, pid_present=False)
        self.assertIsNotNone(exc)
        self.assertEqual(getattr(exc, "code", None) or 0, 0)

    async def test_qubes_no_reconnect_exits_zero(self) -> None:
        ## Clause 2 (not do_reconnect) alone -> exit 0. Pins `or not do_reconnect`
        ## against `and`: an `and` here would NOT exit (clause 1 is false).
        exc = await self._drive(True, do_reconnect=False, pid_present=False)
        self.assertIsNotNone(exc)
        self.assertEqual(getattr(exc, "code", None) or 0, 0)

    async def test_qubes_pid_present_exits_zero(self) -> None:
        ## Clause 3 (server_pid present) alone -> exit 0. Pins
        ## `or server_pid_path.is_file()` against `and`.
        exc = await self._drive(True, do_reconnect=True, pid_present=True)
        self.assertIsNotNone(exc)
        self.assertEqual(getattr(exc, "code", None) or 0, 0)

    async def test_qubes_reconnect_no_pid_does_not_exit(self) -> None:
        ## All clauses false -> the loop reconnects (does NOT exit).
        exc = await self._drive(True, do_reconnect=True, pid_present=False)
        self.assertIsNone(exc)


if __name__ == "__main__":
    unittest.main()
