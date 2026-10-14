#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit coverage for sdwdate_gui_client. The client is pure asyncio with no Qt
dependency, so these tests drive its functions directly, mocking the socket,
inotify, subprocess and filesystem seams. GlobalData is reset per test so the
module-level mutable state does not leak between cases.
"""

# pylint: disable=invalid-name,protected-access,too-many-public-methods
# pylint: disable=import-outside-toplevel

import asyncio
import json
import types
import unittest
import unittest.mock as mock

try:
    from sdwdate_gui import sdwdate_gui_client as client
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)


class _StopLoop(BaseException):
    """Escape the otherwise-infinite main_loop without being swallowed."""


def _make_writer() -> mock.MagicMock:
    writer = mock.MagicMock()
    writer.write = mock.MagicMock()
    writer.drain = mock.AsyncMock()
    writer.close = mock.MagicMock()
    writer.wait_closed = mock.AsyncMock()
    return writer


class ClientResetMixin(unittest.IsolatedAsyncioTestCase):
    """Reset the GlobalData fields the tests mutate."""

    def setUp(self) -> None:
        self._saved = {
            name: getattr(client.GlobalData, name)
            for name in (
                'sock_write', 'sock_read', 'sock_buf', 'do_reconnect',
                'last_tor_status', 'tor_control_panel_installed',
                'watch_manager', 'notifier',
                'server_pid_path', 'qubes_gateway_server_disabled_path',
            )
        }
        client.GlobalData.sock_buf = b''
        client.GlobalData.do_reconnect = True
        client.GlobalData.last_tor_status = ''
        ## Default the Qubes "server disabled" sentinel to absent so main_loop
        ## tests do not accidentally hit the give-up branch; specific tests
        ## override it.
        disabled_path = mock.MagicMock()
        disabled_path.is_file.return_value = False
        client.GlobalData.qubes_gateway_server_disabled_path = disabled_path
        client.GlobalData.awaitable_tasks.clear()
        client.GlobalData.background_tasks.clear()

    def tearDown(self) -> None:
        for name, value in self._saved.items():
            setattr(client.GlobalData, name, value)


class TestInotifyHandler(ClientResetMixin):
    """INotifyEventHandler dispatch and self-event logging."""

    def test_file_changed_dispatch(self) -> None:
        handler = client.INotifyEventHandler()
        ## Plain MagicMocks (not auto-AsyncMock): file_changed passes their
        ## return value to the mocked create_task, so no coroutine is created
        ## and left un-awaited.
        with mock.patch.object(client.asyncio, 'create_task') as ct, \
                mock.patch.object(client, 'tor_status_changed',
                                  new=mock.MagicMock()), \
                mock.patch.object(client, 'sdwdate_status_changed',
                                  new=mock.MagicMock()):
            handler.file_changed(f'{client.GlobalData.tor_path}/foo')
            handler.file_changed(f'{client.GlobalData.torrc_path}/bar')
            handler.file_changed(client.GlobalData.sdwdate_status_path)
        self.assertEqual(ct.call_count, 3)
        self.assertEqual(len(client.GlobalData.awaitable_tasks), 3)

    def test_file_changed_unexpected_logs(self) -> None:
        handler = client.INotifyEventHandler()
        with self.assertLogs(level='ERROR'):
            handler.file_changed('/some/unexpected/path')

    def test_process_events_forward_to_file_changed(self) -> None:
        handler = client.INotifyEventHandler()
        ev = types.SimpleNamespace(pathname='/x')
        with mock.patch.object(handler, 'file_changed') as fc:
            handler.process_IN_MODIFY(ev)
            handler.process_IN_CREATE(ev)
            handler.process_IN_DELETE(ev)
            handler.process_IN_MOVED_FROM(ev)
            handler.process_IN_MOVED_TO(ev)
        self.assertEqual(fc.call_count, 5)

    def test_delete_self_and_move_self(self) -> None:
        handler = client.INotifyEventHandler()
        ev_known = types.SimpleNamespace(
            pathname=client.GlobalData.sdwdate_status_path
        )
        ev_other = types.SimpleNamespace(pathname='/elsewhere')
        with self.assertLogs(level='ERROR'):
            handler.process_IN_DELETE_SELF(ev_known)
        with self.assertLogs(level='ERROR'):
            handler.process_IN_DELETE_SELF(ev_other)
        with self.assertLogs(level='ERROR'):
            handler.process_IN_MOVE_SELF(ev_known)
        with self.assertLogs(level='ERROR'):
            handler.process_IN_MOVE_SELF(ev_other)


class TestMisc(ClientResetMixin):
    """running_in_qubes_os, kick_server, suppress_client_reconnect."""

    def test_running_in_qubes_true_false(self) -> None:
        with mock.patch.object(client.Path, 'is_file', return_value=True):
            self.assertTrue(client.running_in_qubes_os())
        with mock.patch.object(client.Path, 'is_file', return_value=False):
            self.assertFalse(client.running_in_qubes_os())

    async def test_kick_server(self) -> None:
        writer = _make_writer()
        client.GlobalData.sock_write = writer
        with self.assertLogs(level='ERROR'):
            await client.kick_server()
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    def test_suppress_client_reconnect(self) -> None:
        client.GlobalData.do_reconnect = True
        client.suppress_client_reconnect()
        self.assertFalse(client.GlobalData.do_reconnect)


class TestRpcCalls(ClientResetMixin):
    """Client-to-server RPC encoders."""

    async def test_generic_rpc_call_frames(self) -> None:
        writer = _make_writer()
        client.GlobalData.sock_write = writer
        await client.generic_rpc_call(b'hello')
        sent = writer.write.call_args[0][0]
        self.assertEqual(sent, (5).to_bytes(2, 'big') + b'hello')
        writer.drain.assert_awaited_once()

    async def test_generic_rpc_call_oversized_exits(self) -> None:
        writer = _make_writer()
        client.GlobalData.sock_write = writer
        big = b'x' * (client.MAX_MSG_SIZE + 1)
        with self.assertRaises(SystemExit), self.assertLogs(level='CRITICAL'):
            await client.generic_rpc_call(big)

    async def test_set_client_name(self) -> None:
        with mock.patch.object(
            client, 'generic_rpc_call', new=mock.AsyncMock()
        ) as rpc:
            await client.set_client_name('host')
        self.assertEqual(rpc.await_args[0][0], b'set_client_name host')

    async def test_set_sdwdate_status_escapes(self) -> None:
        with mock.patch.object(
            client, 'generic_rpc_call', new=mock.AsyncMock()
        ) as rpc:
            await client.set_sdwdate_status('success', 'a b\n\\c')
        payload = rpc.await_args[0][0]
        self.assertTrue(payload.startswith(b'set_sdwdate_status success '))
        self.assertIn(b'\\040', payload)
        self.assertIn(b'\\012', payload)
        self.assertIn(b'\\134', payload)

    async def test_set_sdwdate_status_non_ascii_and_truncate(self) -> None:
        with mock.patch.object(
            client, 'generic_rpc_call', new=mock.AsyncMock()
        ) as rpc:
            await client.set_sdwdate_status('busy', 'e\u0301' + 'x' * 5000)
        payload = rpc.await_args[0][0]
        ## Non-ASCII replaced with '?', message capped well under the frame.
        self.assertLessEqual(len(payload), 1100)

    async def test_set_tor_status_dedup(self) -> None:
        client.GlobalData.last_tor_status = ''
        with mock.patch.object(
            client, 'generic_rpc_call', new=mock.AsyncMock()
        ) as rpc:
            await client.set_tor_status('running')
            await client.set_tor_status('running')
        self.assertEqual(rpc.await_count, 1)
        self.assertEqual(client.GlobalData.last_tor_status, 'running')


class TestServerToClientRpc(ClientResetMixin):
    """The subprocess-launching RPC handlers."""

    async def test_subprocess_launchers(self) -> None:
        proc = mock.MagicMock()
        proc.wait = mock.AsyncMock()
        with mock.patch.object(
            client.asyncio, 'create_subprocess_exec',
            new=mock.AsyncMock(return_value=proc),
        ) as cse:
            await client.open_tor_control_panel()
            await client.open_sdwdate_log()
            await client.restart_sdwdate()
            await client.stop_sdwdate()
        self.assertEqual(cse.await_count, 4)
        self.assertEqual(proc.wait.await_count, 4)


class TestTryParseCommands(ClientResetMixin):
    """try_parse_commands dispatch and kick paths."""

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        return len(payload).to_bytes(2, 'big') + payload

    async def test_dispatch_all_commands(self) -> None:
        client.GlobalData.sock_buf = b''.join(
            self._frame(cmd)
            for cmd in (
                b'open_tor_control_panel',
                b'open_sdwdate_log',
                b'restart_sdwdate',
                b'stop_sdwdate',
                b'suppress_client_reconnect',
            )
        )
        with mock.patch.object(client, 'open_tor_control_panel',
                               new=mock.AsyncMock()), \
                mock.patch.object(client, 'open_sdwdate_log',
                                  new=mock.AsyncMock()), \
                mock.patch.object(client, 'restart_sdwdate',
                                  new=mock.AsyncMock()), \
                mock.patch.object(client, 'stop_sdwdate',
                                  new=mock.AsyncMock()), \
                mock.patch.object(client, 'suppress_client_reconnect') as scr:
            await client.try_parse_commands()
            if client.GlobalData.background_tasks:
                await asyncio.gather(*client.GlobalData.background_tasks)
        scr.assert_called_once()
        self.assertEqual(client.GlobalData.sock_buf, b'')

    async def test_command_with_extra_args_kicks(self) -> None:
        client.GlobalData.sock_buf = self._frame(b'restart_sdwdate extra')
        with mock.patch.object(client, 'kick_server',
                               new=mock.AsyncMock()) as ks:
            await client.try_parse_commands()
        ks.assert_awaited_once()

    async def test_unknown_command_kicks(self) -> None:
        client.GlobalData.sock_buf = self._frame(b'bogus_cmd')
        with mock.patch.object(client, 'kick_server',
                               new=mock.AsyncMock()) as ks:
            await client.try_parse_commands()
        ks.assert_awaited_once()

    async def test_invalid_bytes_kicks(self) -> None:
        ## Oversized length prefix -> parse_ipc_command raises ValueError.
        client.GlobalData.sock_buf = (
            (client.MAX_MSG_SIZE + 1).to_bytes(2, 'big') + b'x'
        )
        with mock.patch.object(client, 'kick_server',
                               new=mock.AsyncMock()) as ks:
            await client.try_parse_commands()
        ks.assert_awaited_once()

    async def test_partial_message_breaks(self) -> None:
        ## Claims more bytes than present -> loop breaks, buffer kept.
        buf = (10).to_bytes(2, 'big') + b'abc'
        client.GlobalData.sock_buf = buf
        await client.try_parse_commands()
        self.assertEqual(client.GlobalData.sock_buf, buf)

    async def test_each_command_extra_args_kicks(self) -> None:
        for cmd in (
            b'open_tor_control_panel',
            b'open_sdwdate_log',
            b'restart_sdwdate',
            b'stop_sdwdate',
            b'suppress_client_reconnect',
        ):
            with self.subTest(cmd=cmd):
                client.GlobalData.sock_buf = self._frame(cmd + b' extra')
                with mock.patch.object(client, 'kick_server',
                                       new=mock.AsyncMock()) as ks:
                    await client.try_parse_commands()
                ks.assert_awaited_once()

    async def test_zero_length_message_continues(self) -> None:
        ## A zero-length frame followed by a real command.
        client.GlobalData.sock_buf = (
            (0).to_bytes(2, 'big')
            + self._frame(b'suppress_client_reconnect')
        )
        with mock.patch.object(client, 'suppress_client_reconnect') as scr:
            await client.try_parse_commands()
        scr.assert_called_once()


class TestHandleIncomingData(ClientResetMixin):
    """handle_incoming_data read loop."""

    async def test_empty_read_returns_false(self) -> None:
        reader = mock.MagicMock()
        reader.read = mock.AsyncMock(return_value=b'')
        client.GlobalData.sock_read = reader
        self.assertFalse(await client.handle_incoming_data())

    async def test_data_read_parses(self) -> None:
        reader = mock.MagicMock()
        reader.read = mock.AsyncMock(return_value=b'\x00\x00')
        client.GlobalData.sock_read = reader
        with mock.patch.object(client, 'try_parse_commands',
                               new=mock.AsyncMock()) as tpc:
            self.assertTrue(await client.handle_incoming_data())
        tpc.assert_awaited_once()


class TestStatusChanged(ClientResetMixin):
    """sdwdate_status_changed and tor_status_changed."""

    async def test_sdwdate_missing_file(self) -> None:
        with mock.patch('os.path.isfile', return_value=False):
            await client.sdwdate_status_changed()  # returns, no error

    async def test_sdwdate_read_error(self) -> None:
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open', side_effect=OSError('x')), \
                self.assertLogs(level='ERROR'):
            await client.sdwdate_status_changed()

    async def test_sdwdate_empty_file(self) -> None:
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open', mock.mock_open(read_data='   ')):
            await client.sdwdate_status_changed()

    async def test_sdwdate_json_unexpected_exception(self) -> None:
        ## sdwdate_status_changed parses JSON inline; a non-JSONDecodeError from
        ## json.loads hits its 'except Exception' arm and logs an ERROR.
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open',
                           mock.mock_open(read_data='{"a": 1}')), \
                mock.patch.object(json, 'loads',
                                  side_effect=RuntimeError('x')), \
                self.assertLogs(level='ERROR'):
            await client.sdwdate_status_changed()

    async def test_sdwdate_bad_json(self) -> None:
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open',
                           mock.mock_open(read_data='{not json')), \
                self.assertLogs(level='WARNING'):
            await client.sdwdate_status_changed()

    async def test_sdwdate_non_object_json(self) -> None:
        """A valid-JSON non-object (e.g. 'null') is rejected, not crashed on.
        The membership checks need a dict; a bare scalar would otherwise raise
        TypeError outside the parse try/except (found by the status fuzz)."""
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open',
                           mock.mock_open(read_data='null')), \
                self.assertLogs(level='WARNING'):
            await client.sdwdate_status_changed()

    async def test_sdwdate_missing_key(self) -> None:
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open',
                           mock.mock_open(read_data='{"icon": "success"}')), \
                self.assertLogs(level='WARNING'):
            await client.sdwdate_status_changed()

    async def test_sdwdate_non_string_key(self) -> None:
        data = json.dumps({'icon': 'success', 'message': 5})
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open', mock.mock_open(read_data=data)), \
                self.assertLogs(level='WARNING'):
            await client.sdwdate_status_changed()

    async def test_sdwdate_valid_success(self) -> None:
        data = json.dumps({'icon': 'success', 'message': 'ok'})
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open', mock.mock_open(read_data=data)), \
                mock.patch.object(client, 'set_sdwdate_status',
                                  new=mock.AsyncMock()) as sss:
            await client.sdwdate_status_changed()
        sss.assert_awaited_once_with('success', 'ok')

    async def test_sdwdate_invalid_icon(self) -> None:
        data = json.dumps({'icon': 'weird', 'message': 'ok'})
        with mock.patch('os.path.isfile', return_value=True), \
                mock.patch('builtins.open', mock.mock_open(read_data=data)), \
                self.assertLogs(level='WARNING'):
            await client.sdwdate_status_changed()

    async def test_tor_not_installed(self) -> None:
        client.GlobalData.tor_control_panel_installed = False
        await client.tor_status_changed()  # early return

    async def test_tor_status_variants(self) -> None:
        client.GlobalData.tor_control_panel_installed = True
        client.tor_status = types.SimpleNamespace(
            tor_status=lambda: 'tor_enabled'
        )
        cases = [
            ('tor_enabled', True, 'running'),
            ('tor_disabled', True, 'disabled_running'),
            ('tor_disabled', False, 'disabled'),
            ('tor_enabled', False, 'stopped'),
        ]
        for state, running, expected in cases:
            with self.subTest(state=state, running=running):
                client.tor_status.tor_status = lambda s=state: s
                with mock.patch('os.path.exists', return_value=running), \
                        mock.patch.object(client, 'set_tor_status',
                                          new=mock.AsyncMock()) as sts:
                    await client.tor_status_changed()
                sts.assert_awaited_once_with(expected)

    async def test_tor_status_exception(self) -> None:
        client.GlobalData.tor_control_panel_installed = True

        def _boom() -> str:
            raise RuntimeError('x')

        client.tor_status = types.SimpleNamespace(tor_status=_boom)
        with self.assertLogs(level='ERROR'):
            await client.tor_status_changed()


class TestSetup(ClientResetMixin):
    """open_connection, setup_connection, inotify, do_setup."""

    async def test_open_connection_success(self) -> None:
        path = mock.MagicMock()
        path.exists.return_value = True
        client.GlobalData.server_socket_path = path
        with mock.patch.object(
            client.asyncio, 'open_unix_connection',
            new=mock.AsyncMock(return_value=(mock.MagicMock(),
                                             _make_writer())),
        ):
            self.assertTrue(await client.open_connection())

    async def test_open_connection_waits_for_socket(self) -> None:
        path = mock.MagicMock()
        path.exists.side_effect = [False, True]
        client.GlobalData.server_socket_path = path
        with mock.patch.object(client.asyncio, 'sleep',
                               new=mock.AsyncMock()) as slp, \
                mock.patch.object(
                    client.asyncio, 'open_unix_connection',
                    new=mock.AsyncMock(return_value=(mock.MagicMock(),
                                                     _make_writer()))):
            self.assertTrue(await client.open_connection())
        slp.assert_awaited()

    async def test_open_connection_error(self) -> None:
        path = mock.MagicMock()
        path.exists.return_value = True
        client.GlobalData.server_socket_path = path
        with mock.patch.object(
            client.asyncio, 'open_unix_connection',
            new=mock.AsyncMock(side_effect=OSError('x')),
        ), self.assertLogs(level='ERROR'):
            self.assertFalse(await client.open_connection())

    async def test_setup_connection_non_qubes(self) -> None:
        writer = _make_writer()
        client.GlobalData.sock_write = writer
        with mock.patch.object(client, 'running_in_qubes_os',
                               return_value=False), \
                mock.patch.object(client, 'set_client_name',
                                  new=mock.AsyncMock()) as scn, \
                mock.patch.object(client.os, 'uname',
                                  return_value=('s', 'myhost', '', '', '')):
            await client.setup_connection()
        scn.assert_awaited_once_with('myhost')

    async def test_setup_connection_qubes_name(self) -> None:
        writer = _make_writer()
        client.GlobalData.sock_write = writer
        pid_path = mock.MagicMock()
        pid_path.is_file.return_value = True
        client.GlobalData.server_pid_path = pid_path
        run_result = types.SimpleNamespace(stdout='disp123\n')
        with mock.patch.object(client, 'running_in_qubes_os',
                               return_value=True), \
                mock.patch.object(client.subprocess, 'run',
                                  return_value=run_result), \
                mock.patch.object(client, 'set_client_name',
                                  new=mock.AsyncMock()) as scn:
            await client.setup_connection()
        scn.assert_awaited_once_with('disp123')

    async def test_setup_connection_qubes_empty_name_falls_back(self) -> None:
        writer = _make_writer()
        client.GlobalData.sock_write = writer
        pid_path = mock.MagicMock()
        pid_path.is_file.return_value = True
        client.GlobalData.server_pid_path = pid_path
        run_result = types.SimpleNamespace(stdout='\n')
        with mock.patch.object(client, 'running_in_qubes_os',
                               return_value=True), \
                mock.patch.object(client.subprocess, 'run',
                                  return_value=run_result), \
                mock.patch.object(client.os, 'uname',
                                  return_value=('s', 'fallback', '', '', '')), \
                mock.patch.object(client, 'set_client_name',
                                  new=mock.AsyncMock()) as scn:
            await client.setup_connection()
        scn.assert_awaited_once_with('fallback')

    async def test_setup_connection_qubes_workstation_skips(self) -> None:
        """Qubes workstation (no local server_pid): the whole header/name
        block is skipped -- the gateway's qrexec header provides the name."""
        writer = _make_writer()
        client.GlobalData.sock_write = writer
        pid_path = mock.MagicMock()
        pid_path.is_file.return_value = False
        client.GlobalData.server_pid_path = pid_path
        with mock.patch.object(client, 'running_in_qubes_os',
                               return_value=True), \
                mock.patch.object(client, 'set_client_name',
                                  new=mock.AsyncMock()) as scn:
            await client.setup_connection()
        scn.assert_not_awaited()
        writer.write.assert_not_called()

    def test_setup_inotify_watch_warns_on_failure(self) -> None:
        wm = mock.MagicMock()
        wm.add_watch.return_value = {'/p': -1}
        client.GlobalData.watch_manager = wm
        with self.assertLogs(level='ERROR'):
            client.setup_inotify_watch('/p', 1)

    def test_setup_inotify_watch_ok(self) -> None:
        wm = mock.MagicMock()
        wm.add_watch.return_value = {'/p': 1}
        client.GlobalData.watch_manager = wm
        client.setup_inotify_watch('/p', 1)  # no log

    async def test_setup_inotify_watches(self) -> None:
        with mock.patch.object(client.pyinotify, 'WatchManager'), \
                mock.patch.object(client.pyinotify, 'AsyncioNotifier'), \
                mock.patch.object(client, 'setup_inotify_watch') as siw:
            await client.setup_inotify_watches(True, True)
        self.assertEqual(siw.call_count, 3)

    async def test_setup_inotify_watches_no_tor(self) -> None:
        """No tor paths: only the sdwdate status watch is added."""
        with mock.patch.object(client.pyinotify, 'WatchManager'), \
                mock.patch.object(client.pyinotify, 'AsyncioNotifier'), \
                mock.patch.object(client, 'setup_inotify_watch') as siw:
            await client.setup_inotify_watches(False, True)
        self.assertEqual(siw.call_count, 1)

    async def test_setup_inotify_watches_none(self) -> None:
        """Neither tor nor sdwdate paths: no watches added."""
        with mock.patch.object(client.pyinotify, 'WatchManager'), \
                mock.patch.object(client.pyinotify, 'AsyncioNotifier'), \
                mock.patch.object(client, 'setup_inotify_watch') as siw:
            await client.setup_inotify_watches(False, False)
        self.assertEqual(siw.call_count, 0)

    async def test_find_and_handle_no_tor_sdwdate_present(self) -> None:
        client.GlobalData.tor_control_panel_installed = False
        with mock.patch.object(client, 'set_tor_status',
                               new=mock.AsyncMock()) as sts, \
                mock.patch('os.path.isfile', return_value=True), \
                mock.patch.object(client, 'sdwdate_status_changed',
                                  new=mock.AsyncMock()):
            found_tor, found_sdw = (
                await client.find_and_handle_tor_and_sdwdate_state()
            )
        sts.assert_awaited_once_with('absent')
        self.assertFalse(found_tor)
        self.assertTrue(found_sdw)

    async def test_find_and_handle_sdwdate_missing_kicks(self) -> None:
        client.GlobalData.tor_control_panel_installed = False
        with mock.patch.object(client, 'set_tor_status',
                               new=mock.AsyncMock()), \
                mock.patch('os.path.isfile', return_value=False), \
                mock.patch.object(client.asyncio, 'sleep',
                                  new=mock.AsyncMock()), \
                mock.patch.object(client, 'set_sdwdate_status',
                                  new=mock.AsyncMock()), \
                mock.patch.object(client, 'kick_server',
                                  new=mock.AsyncMock()) as ks, \
                mock.patch.object(client, 'sdwdate_status_changed',
                                  new=mock.AsyncMock()), \
                self.assertLogs(level='ERROR'):
            await client.find_and_handle_tor_and_sdwdate_state()
        ks.assert_awaited_once()

    async def test_find_and_handle_tor_paths_found(self) -> None:
        client.GlobalData.tor_control_panel_installed = True
        with mock.patch('os.path.isdir', return_value=True), \
                mock.patch('os.path.isfile', return_value=True), \
                mock.patch.object(client, 'tor_status_changed',
                                  new=mock.AsyncMock()) as tsc, \
                mock.patch.object(client, 'sdwdate_status_changed',
                                  new=mock.AsyncMock()):
            found_tor, found_sdw = (
                await client.find_and_handle_tor_and_sdwdate_state()
            )
        tsc.assert_awaited()
        self.assertTrue(found_tor)
        self.assertTrue(found_sdw)

    async def test_find_and_handle_tor_paths_missing(self) -> None:
        client.GlobalData.tor_control_panel_installed = True
        with mock.patch('os.path.isdir', return_value=False), \
                mock.patch('os.path.isfile', return_value=True), \
                mock.patch.object(client.asyncio, 'sleep',
                                  new=mock.AsyncMock()), \
                mock.patch.object(client, 'set_tor_status',
                                  new=mock.AsyncMock()) as sts, \
                mock.patch.object(client, 'sdwdate_status_changed',
                                  new=mock.AsyncMock()), \
                self.assertLogs(level='ERROR'):
            await client.find_and_handle_tor_and_sdwdate_state()
        sts.assert_any_await('disabled')

    async def test_do_setup_connect_fails(self) -> None:
        with mock.patch.object(client, 'open_connection',
                               new=mock.AsyncMock(return_value=False)):
            self.assertFalse(await client.do_setup())

    async def test_do_setup_sdwdate_missing(self) -> None:
        with mock.patch.object(client, 'open_connection',
                               new=mock.AsyncMock(return_value=True)), \
                mock.patch.object(client, 'setup_connection',
                                  new=mock.AsyncMock()), \
                mock.patch.object(
                    client, 'find_and_handle_tor_and_sdwdate_state',
                    new=mock.AsyncMock(return_value=(False, False))):
            self.assertFalse(await client.do_setup())

    async def test_do_setup_success(self) -> None:
        client.GlobalData.watch_manager = None
        with mock.patch.object(client, 'open_connection',
                               new=mock.AsyncMock(return_value=True)), \
                mock.patch.object(client, 'setup_connection',
                                  new=mock.AsyncMock()), \
                mock.patch.object(
                    client, 'find_and_handle_tor_and_sdwdate_state',
                    new=mock.AsyncMock(return_value=(True, True))), \
                mock.patch.object(client, 'setup_inotify_watches',
                                  new=mock.AsyncMock()) as siw:
            self.assertTrue(await client.do_setup())
        siw.assert_awaited_once()

    async def test_do_setup_watch_manager_already_set(self) -> None:
        """On reconnect the watch manager already exists, so do_setup must NOT
        re-create the inotify watches (the watch_manager-is-None branch)."""
        client.GlobalData.watch_manager = mock.MagicMock()
        with mock.patch.object(client, 'open_connection',
                               new=mock.AsyncMock(return_value=True)), \
                mock.patch.object(client, 'setup_connection',
                                  new=mock.AsyncMock()), \
                mock.patch.object(
                    client, 'find_and_handle_tor_and_sdwdate_state',
                    new=mock.AsyncMock(return_value=(True, True))), \
                mock.patch.object(client, 'setup_inotify_watches',
                                  new=mock.AsyncMock()) as siw:
            self.assertTrue(await client.do_setup())
        siw.assert_not_awaited()

    async def test_do_setup_exception(self) -> None:
        with mock.patch.object(client, 'open_connection',
                               new=mock.AsyncMock(return_value=True)), \
                mock.patch.object(client, 'setup_connection',
                                  new=mock.AsyncMock(
                                      side_effect=RuntimeError('x'))), \
                self.assertLogs(level='ERROR'):
            self.assertFalse(await client.do_setup())


class TestMainLoopAndMain(ClientResetMixin):
    """main_loop control flow and main()."""

    async def test_main_loop_connect_then_disconnect_exit(self) -> None:
        """A connect that drops on a non-Qubes host exits the loop (no retry)."""

        async def fake_handle() -> bool:
            return False

        with mock.patch.object(client, 'do_setup',
                               new=mock.AsyncMock(return_value=True)), \
                mock.patch.object(client, 'handle_incoming_data',
                                  new=fake_handle), \
                mock.patch.object(client, 'running_in_qubes_os',
                                  return_value=False), \
                mock.patch.object(client.asyncio, 'sleep',
                                  new=mock.AsyncMock()):
            with self.assertRaises(SystemExit):
                await client.main_loop()

    async def test_main_loop_gather_non_bool_breaks_and_exits(self) -> None:
        async def raising_handle() -> bool:
            raise RuntimeError('boom')

        with mock.patch.object(client, 'do_setup',
                               new=mock.AsyncMock(return_value=True)), \
                mock.patch.object(client, 'handle_incoming_data',
                                  new=raising_handle), \
                mock.patch.object(client, 'running_in_qubes_os',
                                  return_value=False):
            with self.assertRaises(SystemExit):
                await client.main_loop()

    async def test_main_loop_qubes_disabled_path_breaks(self) -> None:
        """The Qubes 'gateway server disabled' sentinel ends the loop cleanly
        (break, no sys.exit)."""
        disabled_path = mock.MagicMock()
        disabled_path.is_file.return_value = True
        client.GlobalData.qubes_gateway_server_disabled_path = disabled_path
        with mock.patch.object(client, 'do_setup',
                               new=mock.AsyncMock()) as setup, \
                self.assertLogs(level='INFO'):
            await client.main_loop()
        ## Broke out before ever attempting a connection.
        setup.assert_not_awaited()

    async def test_main_loop_do_setup_false_retries(self) -> None:
        """do_setup returning False sleeps one second and retries; a second
        attempt raises to end the test (covers the busy-spin guard)."""
        setup_calls: dict[str, int] = {'n': 0}

        async def flaky_do_setup() -> bool:
            setup_calls['n'] += 1
            if setup_calls['n'] >= 2:
                raise _StopLoop
            return False

        with mock.patch.object(client, 'do_setup', flaky_do_setup), \
                mock.patch.object(client.asyncio, 'sleep',
                                  new=mock.AsyncMock()) as slp:
            with self.assertRaises(_StopLoop):
                await client.main_loop()
        slp.assert_awaited()
        self.assertEqual(setup_calls['n'], 2)

    async def test_main_loop_qubes_reconnect_retries(self) -> None:
        """
        On Qubes, with reconnect allowed and no server_pid file, a dropped
        session sleeps and retries rather than exiting; a second do_setup
        raises to end the test.
        """
        setup_calls: dict[str, int] = {'n': 0}

        async def flaky_do_setup() -> bool:
            setup_calls['n'] += 1
            if setup_calls['n'] >= 2:
                raise _StopLoop
            return True

        async def disconnect_handle() -> bool:
            return False

        pid_path = mock.MagicMock()
        pid_path.is_file.return_value = False
        client.GlobalData.server_pid_path = pid_path
        client.GlobalData.do_reconnect = True

        with mock.patch.object(client, 'do_setup', flaky_do_setup), \
                mock.patch.object(client, 'handle_incoming_data',
                                  new=disconnect_handle), \
                mock.patch.object(client, 'running_in_qubes_os',
                                  return_value=True), \
                mock.patch.object(client.asyncio, 'sleep',
                                  new=mock.AsyncMock()) as slp:
            with self.assertRaises(_StopLoop):
                await client.main_loop()
        ## Reached the reconnect path (slept) and looped back for a 2nd setup.
        slp.assert_awaited()
        self.assertEqual(setup_calls['n'], 2)

    async def test_main_loop_stays_connected_then_drops(self) -> None:
        """A True handle result loops the inner loop (stays connected); the
        next False result breaks it -- covers the stay-connected branch."""
        results = iter([True, False])

        async def fake_handle() -> bool:
            return next(results)

        with mock.patch.object(client, 'do_setup',
                               new=mock.AsyncMock(return_value=True)), \
                mock.patch.object(client, 'handle_incoming_data',
                                  new=fake_handle), \
                mock.patch.object(client, 'running_in_qubes_os',
                                  return_value=False):
            with self.assertRaises(SystemExit):
                await client.main_loop()

    async def test_main_loop_inner_exception_breaks(self) -> None:
        with mock.patch.object(client, 'do_setup',
                               new=mock.AsyncMock(return_value=True)), \
                mock.patch.object(client, 'handle_incoming_data',
                                  new=mock.MagicMock(return_value=None)), \
                mock.patch.object(client.asyncio, 'create_task',
                                  side_effect=RuntimeError('boom')), \
                mock.patch.object(client, 'running_in_qubes_os',
                                  return_value=False):
            with self.assertRaises(SystemExit):
                await client.main_loop()

    async def test_main_root_exits(self) -> None:
        with mock.patch.object(client.os, 'geteuid', return_value=0):
            with self.assertRaises(SystemExit):
                await client.main()

    async def test_main_templatevm_exits(self) -> None:
        with mock.patch.object(client.os, 'geteuid', return_value=1000), \
                mock.patch.object(client.Path, 'is_file', return_value=True):
            with self.assertRaises(SystemExit):
                await client.main()

    async def test_main_runs_loop_then_exits(self) -> None:
        """main (not root, not a template VM) runs main_loop then exits 0."""
        with mock.patch.object(client.os, 'geteuid', return_value=1000), \
                mock.patch.object(client.Path, 'is_file', return_value=False), \
                mock.patch.object(client, 'parse_config_files'), \
                mock.patch.dict(client.ConfigData.conf_dict,
                                {'disable': False}, clear=False), \
                mock.patch.object(client, 'main_loop',
                                  new=mock.AsyncMock()) as loop:
            with self.assertRaises(SystemExit):
                await client.main()
        loop.assert_awaited_once()

    async def test_main_config_parse_error_exits_one(self) -> None:
        """A config parse failure logs an ERROR and exits 1."""
        with mock.patch.object(client.os, 'geteuid', return_value=1000), \
                mock.patch.object(client.Path, 'is_file', return_value=False), \
                mock.patch.object(client, 'parse_config_files',
                                  side_effect=RuntimeError('bad')), \
                self.assertLogs(level='ERROR'):
            with self.assertRaises(SystemExit) as raised:
                await client.main()
        self.assertEqual(raised.exception.code, 1)

    async def test_main_disabled_exits_zero(self) -> None:
        """'disable'=True logs an INFO and exits 0 before the loop runs."""
        with mock.patch.object(client.os, 'geteuid', return_value=1000), \
                mock.patch.object(client.Path, 'is_file', return_value=False), \
                mock.patch.object(client, 'parse_config_files'), \
                mock.patch.dict(client.ConfigData.conf_dict,
                                {'disable': True}, clear=False), \
                mock.patch.object(client, 'main_loop',
                                  new=mock.AsyncMock()) as loop, \
                self.assertLogs(level='INFO'):
            with self.assertRaises(SystemExit) as raised:
                await client.main()
        self.assertEqual(raised.exception.code, 0)
        loop.assert_not_awaited()


if __name__ == '__main__':
    unittest.main()
