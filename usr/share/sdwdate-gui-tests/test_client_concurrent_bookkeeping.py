#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Interleaving regression tests for sdwdate_gui_client concurrent task
bookkeeping.

inotify events fire DURING a main_loop await, so INotifyEventHandler.file_changed
can mutate GlobalData.awaitable_tasks between the gather() snapshot and the
popleft() drain. These tests interleave inotify appends with the incoming-data
task and the client-to-server RPC writes, pinning the ordering invariants that
keep the drain correct (single-threaded asyncio, so this is ordering, not a data
race):

- the incoming-data task is appendLEFT (index 0) and file_changed appends RIGHT,
  so popleft(start_deque_len) drains exactly the gathered left prefix and a task
  appended mid-await SURVIVES to the next iteration instead of being dropped;
- the connection decision reads return_vals[0] (the handle_incoming_data result),
  and an exception there is handled (isinstance bool False -> else: break), not
  mis-read as a bool nor propagated;
- generic_rpc_call writes each framed message in ONE write(), so concurrent
  status writers cannot interleave bytes within a frame.

Each test is a CANARY: it fails if file_changed is switched to appendleft, if the
popleft count becomes len(deque), if the return_vals index moves off 0, if the
isinstance/else break is removed, or if generic_rpc_call splits the frame prefix
and body across an await.
"""

# pylint: disable=wrong-import-position,invalid-name,protected-access

import asyncio
import unittest
import unittest.mock as mock

try:
    from sdwdate_gui import sdwdate_gui_client as client
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)


class _ClientStateMixin(unittest.IsolatedAsyncioTestCase):
    """Save/restore the module-level GlobalData fields these tests mutate."""

    def setUp(self) -> None:
        self._saved = {
            name: getattr(client.GlobalData, name)
            for name in (
                'sock_write', 'sock_read', 'sock_buf', 'do_reconnect',
                'last_tor_status', 'reconnect_delay',
            )
        }
        client.GlobalData.sock_buf = b''
        client.GlobalData.do_reconnect = True
        client.GlobalData.last_tor_status = ''
        client.GlobalData.reconnect_delay = client.INITIAL_RECONNECT_DELAY
        ## awaitable_tasks / background_tasks are shared mutable containers;
        ## empty them before and after so no task leaks between cases.
        client.GlobalData.awaitable_tasks.clear()
        client.GlobalData.background_tasks.clear()
        self.addCleanup(client.GlobalData.awaitable_tasks.clear)
        self.addCleanup(client.GlobalData.background_tasks.clear)

    def tearDown(self) -> None:
        for name, value in self._saved.items():
            setattr(client.GlobalData, name, value)


class TestAppendDuringAwaitSurvivesDrain(_ClientStateMixin):
    """A watcher appended mid-await must survive the popleft drain."""

    async def test_append_during_await_survives_drain(self) -> None:
        handler = client.INotifyEventHandler()
        state: dict = {
            'calls': 0,
            'in_data_task1': None,
            'watcher': None,
            'deque_at_iter2': None,
        }

        async def fake_handle() -> bool:
            state['calls'] += 1
            if state['calls'] == 1:
                ## This running task IS in_data_task1 (appendleft, index 0).
                state['in_data_task1'] = asyncio.current_task()
                ## Simulate an inotify event firing mid-session: file_changed
                ## appends a watcher task. Capture it by set difference so the
                ## identity is caught whichever end it lands on.
                before = set(client.GlobalData.awaitable_tasks)
                handler.file_changed(f'{client.GlobalData.tor_path}/something')
                new = set(client.GlobalData.awaitable_tasks) - before
                state['watcher'] = new.pop()
                return True
            ## Iteration 2: snapshot the deque, then drop the connection.
            state['deque_at_iter2'] = list(client.GlobalData.awaitable_tasks)
            return False

        with mock.patch.object(
            client, 'do_setup', mock.AsyncMock(return_value=True)
        ), mock.patch.object(
            client, 'running_in_qubes_os', return_value=False
        ), mock.patch.object(
            client, 'handle_incoming_data', fake_handle
        ), mock.patch.object(
            client, 'tor_status_changed', mock.AsyncMock()
        ), mock.patch.object(
            client, 'sdwdate_status_changed', mock.AsyncMock()
        ):
            with self.assertRaises(SystemExit):
                await client.main_loop()

        self.assertEqual(
            state['calls'], 2, 'main_loop did not run a second iteration'
        )
        self.assertIsNotNone(state['watcher'])
        ## The mid-await watcher is appended RIGHT; popleft drains only the
        ## gathered left prefix (start_deque_len == 1), so it SURVIVES into
        ## iteration 2. file_changed using appendleft, or a popleft count of
        ## len(deque), would have dropped it here.
        self.assertIn(
            state['watcher'],
            state['deque_at_iter2'],
            'a task appended during the await was dropped by the drain '
            'instead of being carried to the next iteration',
        )
        ## in_data_task1 was the gathered task and must have been drained.
        self.assertNotIn(
            state['in_data_task1'],
            state['deque_at_iter2'],
            'the incoming-data task was not drained from the deque',
        )


class TestExceptionAtIndexZeroBreaks(_ClientStateMixin):
    """An exception at return_vals[0] breaks the inner loop, not a crash."""

    async def test_exception_at_index0_breaks_not_crashes(self) -> None:
        state: dict = {'calls': 0}

        async def fake_handle() -> bool:
            state['calls'] += 1
            if state['calls'] == 1:
                ## handle_incoming_data raising (e.g. a reset socket read) lands
                ## in return_vals[0] as an exception. It must break the inner
                ## loop, not propagate nor be mis-read as a bool.
                raise ValueError('simulated read failure')
            return False

        with mock.patch.object(
            client, 'do_setup', mock.AsyncMock(return_value=True)
        ), mock.patch.object(
            client, 'running_in_qubes_os', return_value=False
        ), mock.patch.object(
            client, 'handle_incoming_data', fake_handle
        ):
            with self.assertRaises(SystemExit):
                await client.main_loop()

        ## Correct code breaks on the first iteration (exception at index 0 ->
        ## isinstance bool False -> else: break), so handle runs exactly once.
        ## Removing the else-break would loop and call handle a second time.
        self.assertEqual(
            state['calls'],
            1,
            'an exception in handle_incoming_data did not break the inner '
            'loop at return_vals[0]',
        )


class TestConnectionDecisionUsesHandleResult(_ClientStateMixin):
    """The connection decision reads index 0, never a watcher slot."""

    async def test_return_vals0_is_handle_result_with_watchers(self) -> None:
        state: dict = {'calls': 0}

        async def fake_handle() -> bool:
            state['calls'] += 1
            return False

        async def fake_watcher() -> bool:
            ## Result (True) deliberately differs from the handle result
            ## (False): if the decision read this slot instead of index 0 the
            ## True would keep the session alive and force a second iteration.
            return True

        ## Seed a watcher so the deque already holds >1 task on iteration 1.
        seeded = asyncio.create_task(fake_watcher())
        client.GlobalData.awaitable_tasks.append(seeded)

        with mock.patch.object(
            client, 'do_setup', mock.AsyncMock(return_value=True)
        ), mock.patch.object(
            client, 'running_in_qubes_os', return_value=False
        ), mock.patch.object(
            client, 'handle_incoming_data', fake_handle
        ):
            with self.assertRaises(SystemExit):
                await client.main_loop()

        self.assertEqual(
            state['calls'],
            1,
            'the connection decision did not read return_vals[0] (the '
            'handle_incoming_data result); a watcher result kept the session '
            'alive',
        )


class TestConcurrentStatusWritesWholeFrames(_ClientStateMixin):
    """Concurrent RPC writers must each emit a whole frame per write()."""

    async def test_concurrent_status_writes_emit_whole_frames(self) -> None:
        writer = mock.MagicMock()
        writer.write = mock.MagicMock()

        async def fake_drain() -> None:
            ## Yield so a concurrent writer can interleave at this await; a
            ## split prefix/body write would corrupt the frame on the wire.
            await asyncio.sleep(0)

        writer.drain = fake_drain
        client.GlobalData.sock_write = writer

        payload_a = b'set_tor_status running'
        payload_b = b'set_sdwdate_status busy hello'
        await asyncio.gather(
            client.generic_rpc_call(payload_a),
            client.generic_rpc_call(payload_b),
        )

        frames = [c.args[0] for c in writer.write.call_args_list]
        self.assertEqual(
            len(frames), 2, 'expected exactly one write() per framed message'
        )
        for frame in frames:
            self.assertGreaterEqual(len(frame), 2)
            declared = int.from_bytes(frame[:2], byteorder='big', signed=False)
            self.assertEqual(
                declared,
                len(frame) - 2,
                'a write() did not carry a whole frame (length prefix did not '
                'match the body length); concurrent writers interleaved bytes '
                'within a frame',
            )
        ## Each whole frame must carry exactly one of the two payloads.
        bodies = {frame[2:] for frame in frames}
        self.assertEqual(bodies, {payload_a, payload_b})


if __name__ == '__main__':
    unittest.main()
