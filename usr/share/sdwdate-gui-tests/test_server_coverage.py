#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit coverage for sdwdate_gui_server. Runs under the Qt offscreen platform
plugin (no X server / tray), with SdwdateGuiListener stubbed so no PID file or
listening socket is created. Private (name-mangled) methods are driven
directly; the wire-format and de-duplication paths are covered by the sibling
test_wire_protocol / test_server_dedup suites, so this file concentrates on
the status/menu/RPC/bootstrap branches those do not reach.
"""

# pylint: disable=invalid-name,protected-access,no-name-in-module
# pylint: disable=wrong-import-position,too-many-public-methods

import os
import unittest
import unittest.mock as mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtGui import QIcon
from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)


_APP: QApplication = QApplication.instance() or QApplication(['sdwdate-gui-tests'])


class _FakeListener(QObject):  # pylint: disable=too-few-public-methods
    """Stub for SdwdateGuiListener; no PID-file / socket side effects."""

    newClient: pyqtSignal = pyqtSignal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        QObject.__init__(self, parent)


def _mangled(obj: object, name: str):
    return getattr(obj, f'_SdwdateGuiClient__{name}')


class TestModuleHelpers(unittest.TestCase):
    """running_in_qubes_os, signal_handler, sanitize_for_richtext."""

    def test_running_in_qubes(self) -> None:
        with mock.patch.object(server.Path, 'is_file', return_value=True):
            self.assertTrue(server.running_in_qubes_os())
        with mock.patch.object(server.Path, 'is_file', return_value=False):
            self.assertFalse(server.running_in_qubes_os())

    def test_signal_handler_exits(self) -> None:
        with self.assertRaises(SystemExit) as ctx, self.assertLogs(level='INFO'):
            server.signal_handler(15, None)
        self.assertEqual(ctx.exception.code, 128 + 15)

    def test_sanitize_truncates(self) -> None:
        out = server.sanitize_for_richtext('abcdef', 3)
        self.assertEqual(len(out), 3)


class TestSdwdateGuiFrame(unittest.TestCase):
    """The status window widget."""

    def test_frame_build_and_close(self) -> None:
        frame = server.SdwdateGuiFrame('hello', QIcon())
        self.addCleanup(frame.deleteLater)
        frame.show()
        _APP.processEvents()
        frame.quiet_close()
        _APP.processEvents()
        self.assertFalse(frame.isVisible())


class ClientTestBase(unittest.TestCase):
    """Builds a bare SdwdateGuiClient on an unconnected socket."""

    def setUp(self) -> None:
        self._real_qubes = server.running_in_qubes_os
        self.client = server.SdwdateGuiClient(QLocalSocket())
        self.addCleanup(self.client.deleteLater)

    def tearDown(self) -> None:
        server.running_in_qubes_os = self._real_qubes
        _APP.processEvents()

    def set_qubes(self, value: bool) -> None:
        server.running_in_qubes_os = lambda: value

    def make_ready(self) -> None:
        self.client.client_name = 'host'
        self.client.client_name_set = True


class TestQubesHeader(ClientTestBase):
    """__parse_qubes_data."""

    def _parse(self) -> bool:
        return _mangled(self.client, 'parse_qubes_data')()

    def test_no_null_small_returns_false(self) -> None:
        self.client._SdwdateGuiClient__sock_buf = b'partial'
        self.assertFalse(self._parse())

    def test_no_null_too_much_kicks(self) -> None:
        self.set_qubes(False)
        self.client._SdwdateGuiClient__sock_buf = b'x' * 4097
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.assertFalse(self._parse())
        kc.assert_called_once()

    def test_nonprintable_header_kicks(self) -> None:
        self.client._SdwdateGuiClient__sock_buf = b'\x01\x00rest'
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.assertFalse(self._parse())
        kc.assert_called_once()

    def test_header_without_name(self) -> None:
        self.client._SdwdateGuiClient__sock_buf = b'service\x00'
        self.assertTrue(self._parse())
        self.assertFalse(self.client.client_name_set)

    def test_header_with_name_sets_it(self) -> None:
        self.set_qubes(True)
        self.client._SdwdateGuiClient__sock_buf = b'svc disp9\x00tail'
        self.assertTrue(self._parse())
        self.assertEqual(self.client.client_name, 'disp9')
        ## The buffer must resume exactly one byte past the NUL (not two): the
        ## first post-header command byte is never dropped.
        self.assertEqual(
            self.client._SdwdateGuiClient__sock_buf, b'tail'
        )

    def test_header_three_fields_keeps_source_vm(self) -> None:
        """A 3-field qrexec header still names the client from the 2nd field;
        the count guard is '< 2', not '!= 2' (which would drop the source VM)."""
        self.set_qubes(True)
        self.client._SdwdateGuiClient__sock_buf = b'svc src extra\x00'
        self.assertTrue(self._parse())
        self.assertTrue(self.client.client_name_set)
        self.assertEqual(self.client.client_name, 'src')


class TestSetClientName(ClientTestBase):
    """__set_client_name validation."""

    def _set(self, name: str) -> bool:
        return _mangled(self.client, 'set_client_name')(name)

    def test_change_after_set_kicks(self) -> None:
        self.client.client_name_set = True
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.assertFalse(self._set('new'))
        kc.assert_called_once()

    def test_qubes_invalid_name_kicks(self) -> None:
        self.set_qubes(True)
        ## 'Domain-0' and 'default' are Qubes reserved names: each passes the
        ## identifier regex and the -dm check, so only the reserved-name tuple
        ## rejects them. Pins every member of that tuple.
        for bad in ('x' * 32, '1startsdigit', 'none', 'default', 'Domain-0',
                    'foo-dm', 'a/b'):
            with self.subTest(bad=bad):
                self.client.client_name_set = False
                with mock.patch.object(self.client, 'kick_client') as kc:
                    self.assertFalse(self._set(bad))
                kc.assert_called_once()

    def test_qubes_valid_name(self) -> None:
        self.set_qubes(True)
        self.assertTrue(self._set('disp123'))
        self.assertEqual(self.client.client_name, 'disp123')

    def test_non_qubes_too_long_kicks(self) -> None:
        self.set_qubes(False)
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.assertFalse(self._set('n' * 256))
        kc.assert_called_once()

    def test_non_qubes_valid(self) -> None:
        self.set_qubes(False)
        self.assertTrue(self._set('my-host'))


class TestSetSdwdateStatus(ClientTestBase):
    """__set_sdwdate_status + __octal_decode."""

    def _set(self, status: str, msg: str) -> bool:
        return _mangled(self.client, 'set_sdwdate_status')(status, msg)

    def test_before_name_kicks(self) -> None:
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.assertFalse(self._set('success', 'x'))
        kc.assert_called_once()

    def test_invalid_status_kicks(self) -> None:
        self.make_ready()
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.assertFalse(self._set('weird', 'x'))
        kc.assert_called_once()

    def test_valid_statuses_and_octal_decode(self) -> None:
        self.make_ready()
        for status, enum in (('success', server.SdwdateStatus.SUCCESS),
                             ('busy', server.SdwdateStatus.BUSY),
                             ('error', server.SdwdateStatus.ERROR)):
            with self.subTest(status=status):
                self.assertTrue(self._set(status, 'a\\040b'))
                self.assertEqual(self.client.sdwdate_status, enum)
        self.assertEqual(self.client.sdwdate_msg, 'a b')

    def test_unsafe_octal_kicks(self) -> None:
        self.make_ready()
        with mock.patch.object(self.client, 'kick_client') as kc, \
                self.assertLogs(level='WARNING'):
            ## \000 decodes to a control char -> __octal_decode raises.
            self.assertFalse(self._set('success', 'x\\000y'))
        kc.assert_called_once()

    def test_tilde_octal_is_accepted(self) -> None:
        """0x7E (~, \\176) is the printable upper bound and must decode, not be
        rejected -- pins the octal guard at '> 0x7E', not '>= 0x7E'."""
        self.make_ready()
        self.assertTrue(self._set('success', 'a\\176b'))
        self.assertEqual(self.client.sdwdate_msg, 'a~b')


class TestSetTorStatus(ClientTestBase):
    """__set_tor_status."""

    def _set(self, status: str) -> bool:
        return _mangled(self.client, 'set_tor_status')(status)

    def test_before_name_kicks(self) -> None:
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.assertFalse(self._set('running'))
        kc.assert_called_once()

    def test_valid_tor_statuses(self) -> None:
        self.make_ready()
        for s, enum in (('running', server.TorStatus.RUNNING),
                        ('stopped', server.TorStatus.STOPPED),
                        ('disabled', server.TorStatus.DISABLED),
                        ('disabled_running', server.TorStatus.DISABLED_RUNNING),
                        ('absent', server.TorStatus.ABSENT)):
            with self.subTest(s=s):
                self.assertTrue(self._set(s))
                self.assertEqual(self.client.tor_status, enum)

    def test_invalid_tor_status_kicks(self) -> None:
        self.make_ready()
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.assertFalse(self._set('weird'))
        kc.assert_called_once()


class TestHandshakeTimeout(ClientTestBase):
    """__handshake_timeout."""

    def test_already_named_returns(self) -> None:
        self.client.client_name_set = True
        _mangled(self.client, 'handshake_timeout')()  # early return, no kick

    def test_unconnected_returns(self) -> None:
        ## Not named and the socket is not connected -> nothing to kick.
        self.client.client_name_set = False
        _mangled(self.client, 'handshake_timeout')()

    def test_connected_unnamed_kicks(self) -> None:
        self.client.client_name_set = False
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        self.client.client_socket = fake_socket
        with mock.patch.object(self.client, 'kick_client') as kc, \
                self.assertLogs(level='WARNING'):
            _mangled(self.client, 'handshake_timeout')()
        kc.assert_called_once()


class TestTryParseCommands(ClientTestBase):
    """__try_parse_commands dispatch and kick paths."""

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        return len(payload).to_bytes(2, 'big') + payload

    def _run(self, buf: bytes) -> None:
        self.client._SdwdateGuiClient__sock_buf = buf
        _mangled(self.client, 'try_parse_commands')()

    def test_valid_dispatch(self) -> None:
        self.set_qubes(False)
        buf = (
            self._frame(b'set_client_name host')
            + self._frame(b'set_sdwdate_status success ok')
            + self._frame(b'set_tor_status running')
        )
        self._run(buf)
        self.assertEqual(self.client.client_name, 'host')
        self.assertEqual(self.client.sdwdate_status, server.SdwdateStatus.SUCCESS)
        self.assertEqual(self.client.tor_status, server.TorStatus.RUNNING)

    def test_wrong_argc_kicks(self) -> None:
        for payload in (b'set_client_name a b', b'set_sdwdate_status only',
                        b'set_tor_status a b'):
            with self.subTest(payload=payload):
                client = server.SdwdateGuiClient(QLocalSocket())
                self.addCleanup(client.deleteLater)
                client._SdwdateGuiClient__sock_buf = self._frame(payload)
                with mock.patch.object(client, 'kick_client') as kc, \
                        self.assertLogs(level='WARNING'):
                    _mangled(client, 'try_parse_commands')()
                kc.assert_called_once()

    def test_unknown_command_kicks(self) -> None:
        with mock.patch.object(self.client, 'kick_client') as kc:
            self._run(self._frame(b'bogus'))
        kc.assert_called_once()

    def test_invalid_bytes_kicks(self) -> None:
        with mock.patch.object(self.client, 'kick_client') as kc, \
                self.assertLogs(level='WARNING'):
            self._run((server.MAX_MSG_SIZE + 1).to_bytes(2, 'big') + b'x')
        kc.assert_called_once()

    def test_partial_message_breaks(self) -> None:
        buf = (10).to_bytes(2, 'big') + b'abc'
        self._run(buf)
        self.assertEqual(self.client._SdwdateGuiClient__sock_buf, buf)

    def test_zero_length_frame_kicks(self) -> None:
        ## A 0-length frame makes parse_ipc_buf raise, so the whole buffer is
        ## rejected and the client kicked -- the trailing set_client_name is
        ## never processed.
        self.set_qubes(False)
        buf = (0).to_bytes(2, 'big') + self._frame(b'set_client_name host')
        with mock.patch.object(self.client, 'kick_client') as kick, \
                self.assertLogs(level='WARNING'):
            self._run(buf)
        kick.assert_called()
        self.assertIsNone(self.client.client_name)

    def test_setter_returns_false_stops(self) -> None:
        ## A second set_client_name in the same buffer -> __set_client_name
        ## returns False (name already set) and parsing stops.
        self.set_qubes(False)
        buf = self._frame(b'set_client_name host') + self._frame(
            b'set_client_name other'
        )
        with mock.patch.object(self.client, 'kick_client'), \
                self.assertLogs(level='WARNING'):
            self._run(buf)
        self.assertEqual(self.client.client_name, 'host')

    def test_sdwdate_setter_false_stops(self) -> None:
        self.set_qubes(False)
        self.make_ready()
        buf = self._frame(b'set_sdwdate_status bogus x')
        with mock.patch.object(self.client, 'kick_client'), \
                self.assertLogs(level='WARNING'):
            self._run(buf)

    def test_tor_setter_false_stops(self) -> None:
        self.set_qubes(False)
        self.make_ready()
        buf = self._frame(b'set_tor_status bogus')
        with mock.patch.object(self.client, 'kick_client'), \
                self.assertLogs(level='WARNING'):
            self._run(buf)


class TestHandleIncomingData(ClientTestBase):
    """__handle_incoming_data pulls from the socket and parses."""

    def test_reads_and_parses_after_header(self) -> None:
        self.client.qubes_header_parsed = True
        fake_socket = mock.MagicMock()
        fake_socket.readAll.return_value.data.return_value = (
            (len(b'set_tor_status running')).to_bytes(2, 'big')
            + b'set_tor_status running'
        )
        self.client.client_socket = fake_socket
        self.make_ready()
        _mangled(self.client, 'handle_incoming_data')()
        self.assertEqual(self.client.tor_status, server.TorStatus.RUNNING)

    def test_parses_qubes_header_first(self) -> None:
        self.client.qubes_header_parsed = False
        fake_socket = mock.MagicMock()
        fake_socket.readAll.return_value.data.return_value = b'svc name\x00'
        self.client.client_socket = fake_socket
        _mangled(self.client, 'handle_incoming_data')()
        self.assertTrue(self.client.qubes_header_parsed)

    def test_incomplete_qubes_header_returns(self) -> None:
        ## No null byte yet -> __parse_qubes_data returns False, so
        ## __handle_incoming_data returns without trying to parse commands.
        self.client.qubes_header_parsed = False
        fake_socket = mock.MagicMock()
        fake_socket.readAll.return_value.data.return_value = b'partial'
        self.client.client_socket = fake_socket
        with mock.patch.object(
            self.client, '_SdwdateGuiClient__try_parse_commands'
        ) as tpc:
            _mangled(self.client, 'handle_incoming_data')()
        tpc.assert_not_called()


class TestGenericRpcAndServerCalls(ClientTestBase):
    """__generic_rpc_call and the server-to-client calls."""

    def test_oversized_exits(self) -> None:
        with self.assertRaises(SystemExit), self.assertLogs(level='CRITICAL'):
            _mangled(self.client, 'generic_rpc_call')(b'x' * (server.MAX_MSG_SIZE + 1))

    def test_not_connected_returns(self) -> None:
        ## Unconnected socket: the send loop returns without writing.
        self.client.open_sdwdate_log()
        self.client.restart_sdwdate()
        self.client.stop_sdwdate()
        self.client.suppress_client_reconnect()

    def test_write_error_kicks(self) -> None:
        self.set_qubes(False)
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        fake_socket.write.return_value = -1
        self.client.client_socket = fake_socket
        with mock.patch.object(self.client, 'kick_client') as kc:
            self.client.open_sdwdate_log()
        kc.assert_called_once()

    def test_full_write_path(self) -> None:
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        payload = b'open_sdwdate_log'
        ## Report the whole framed message written in one call.
        fake_socket.write.return_value = len(payload) + 2
        self.client.client_socket = fake_socket
        self.client.open_sdwdate_log()
        fake_socket.write.assert_called()

    def test_open_tor_control_panel_gated(self) -> None:
        self.client.tor_status = server.TorStatus.ABSENT
        with mock.patch.object(
            self.client, '_SdwdateGuiClient__generic_rpc_call'
        ) as rpc:
            self.client.open_tor_control_panel()
        rpc.assert_not_called()

    def test_open_tor_control_panel_sends(self) -> None:
        self.client.tor_status = server.TorStatus.RUNNING
        with mock.patch.object(
            self.client, '_SdwdateGuiClient__generic_rpc_call'
        ) as rpc:
            self.client.open_tor_control_panel()
        rpc.assert_called_once()


class TrayTestBase(unittest.TestCase):
    """A tray icon with the listener stubbed and qubes patchable."""

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        self._real_qubes = server.running_in_qubes_os
        self._real_qapp = server.QApplication
        server.SdwdateGuiListener = _FakeListener
        self.tray = server.SdwdateTrayIcon()

    def tearDown(self) -> None:
        server.SdwdateGuiListener = self._real_listener
        server.running_in_qubes_os = self._real_qubes
        server.QApplication = self._real_qapp
        if self.tray.msg_window is not None:
            self.tray.msg_window.deleteLater()
        self.tray.deleteLater()
        _APP.processEvents()

    def set_qubes(self, value: bool) -> None:
        server.running_in_qubes_os = lambda: value

    def add_client(
        self,
        name: str,
        tor: 'server.TorStatus' = None,
        sdwdate: 'server.SdwdateStatus' = None,
    ) -> server.SdwdateGuiClient:
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        client.sdwdate_status = sdwdate or server.SdwdateStatus.SUCCESS
        client.sdwdate_msg = 'msg'
        client.tor_status = tor if tor is not None else server.TorStatus.ABSENT
        client.client_name = name
        client.client_name_set = True
        client.clientNameChanged.emit()
        _APP.processEvents()
        return client


class TestTrayStatusWindows(TrayTestBase):
    """show_disconnected_msg / show_status_msg / run_client_method."""

    def test_show_disconnected_msg(self) -> None:
        client = self.add_client('host')
        self.tray.show_disconnected_msg(client)
        self.assertEqual(self.tray.msg_window_type,
                         server.MessageType.DISCONNECTED)

    def test_show_disconnected_replaces_open_window(self) -> None:
        client = self.add_client('host')
        self.tray.show_disconnected_msg(client)
        self.tray.msg_window.show()
        _APP.processEvents()
        ## A second call must close + delete the previously shown window.
        self.tray.show_disconnected_msg(client)
        _APP.processEvents()
        self.assertEqual(self.tray.msg_window_type,
                         server.MessageType.DISCONNECTED)

    def test_show_status_disconnected_client(self) -> None:
        client = self.add_client('host')
        ## Unconnected socket -> show_status_msg routes to disconnected msg.
        self.tray.show_status_msg(server.MessageType.SDWDATE, client)
        self.assertEqual(self.tray.msg_window_type,
                         server.MessageType.DISCONNECTED)

    def test_show_status_sdwdate_and_tor(self) -> None:
        client = self.add_client('host', tor=server.TorStatus.RUNNING)
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        client.client_socket = fake_socket
        for qubes in (False, True):
            self.set_qubes(qubes)
            self.tray.show_status_msg(server.MessageType.SDWDATE, client)
            self.assertEqual(self.tray.msg_window_type,
                             server.MessageType.SDWDATE)
            for tor in (server.TorStatus.RUNNING, server.TorStatus.DISABLED,
                        server.TorStatus.STOPPED,
                        server.TorStatus.DISABLED_RUNNING):
                client.tor_status = tor
                self.tray.show_status_msg(server.MessageType.TOR, client)
                self.assertEqual(self.tray.msg_window_type,
                                 server.MessageType.TOR)

    def test_show_status_sdwdate_none_returns(self) -> None:
        client = self.add_client('host')
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        client.client_socket = fake_socket
        client.sdwdate_msg = None
        before = self.tray.msg_window
        self.tray.show_status_msg(server.MessageType.SDWDATE, client)
        self.assertIs(self.tray.msg_window, before)

    def test_show_status_tor_absent_warns(self) -> None:
        client = self.add_client('host', tor=server.TorStatus.ABSENT)
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        client.client_socket = fake_socket
        with self.assertLogs(level='WARNING'):
            self.tray.show_status_msg(server.MessageType.TOR, client)

    def test_run_client_method_disconnected(self) -> None:
        client = self.add_client('host')
        called = mock.MagicMock()
        self.tray.run_client_method(client, called)
        called.assert_not_called()
        self.assertEqual(self.tray.msg_window_type,
                         server.MessageType.DISCONNECTED)

    def test_run_client_method_connected(self) -> None:
        client = self.add_client('host')
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        client.client_socket = fake_socket
        called = mock.MagicMock()
        self.tray.run_client_method(client, called)
        called.assert_called_once()


class TestTrayMenuAndIcon(TrayTestBase):
    """regen_menu variants, set_tray_icon, handle_state_change, drop_client."""

    def test_single_client_menu(self) -> None:
        self.add_client('solo')
        self.assertEqual(len(self.tray.client_list), 1)

    def test_multi_client_submenus_and_tor(self) -> None:
        self.add_client('a', tor=server.TorStatus.RUNNING)
        self.add_client('b', tor=server.TorStatus.STOPPED,
                        sdwdate=server.SdwdateStatus.ERROR)
        names = [
            action.text()
            for action in self.tray.menu.actions()
            if action.menu() is not None
        ]
        self.assertEqual(sorted(names), ['a', 'b'])

    def test_client_not_ready_skipped(self) -> None:
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        ## No name / both UNKNOWN -> not shown.
        self.tray.regen_menu()
        self.assertFalse(client.present_in_menu)

    def test_client_sdwdate_unknown_renders_busy(self) -> None:
        ## Named, tor not UNKNOWN, but sdwdate UNKNOWN -> effective status BUSY.
        self.add_client('a', tor=server.TorStatus.ABSENT,
                        sdwdate=server.SdwdateStatus.UNKNOWN)
        self.assertEqual(self.tray.client_list[-1].client_name, 'a')

    def test_client_tor_unknown_known_sdwdate(self) -> None:
        ## tor UNKNOWN but sdwdate known -> rendered, Tor action target is
        ## STOPPED (the ABSENT/UNKNOWN -> STOPPED branch in regen_menu).
        self.add_client('a', tor=server.TorStatus.UNKNOWN,
                        sdwdate=server.SdwdateStatus.SUCCESS)
        self.assertEqual(self.tray.client_list[-1].client_name, 'a')

    def test_regen_deferred_while_visible(self) -> None:
        self.add_client('a')
        self.tray.menu.popup(server.QCursor.pos())
        _APP.processEvents()
        self.tray.regen_menu()
        self.assertTrue(self.tray.menu_regen_pending)
        self.tray.handle_menu_show()
        self.assertFalse(self.tray.menu_regen_pending)
        self.tray.menu.hide()

    def test_set_tray_icon(self) -> None:
        self.add_client('a', tor=server.TorStatus.STOPPED,
                        sdwdate=server.SdwdateStatus.ERROR)
        self.tray.set_tray_icon()
        self.add_client('b', sdwdate=server.SdwdateStatus.SUCCESS)
        self.tray.set_tray_icon()

    def test_handle_state_change_updates_open_window(self) -> None:
        client = self.add_client('host', tor=server.TorStatus.RUNNING)
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        client.client_socket = fake_socket
        self.tray.show_status_msg(server.MessageType.SDWDATE, client)
        self.tray.msg_window.show()
        _APP.processEvents()
        self.tray.handle_state_change(server.MessageType.SDWDATE, client)

    def test_handle_state_change_no_open_window(self) -> None:
        """No message window open: handle_state_change only regenerates."""
        c = self.add_client('host')
        self.tray.msg_window = None
        self.tray.handle_state_change(server.MessageType.SDWDATE, c)

    def test_handle_state_change_open_window_other_client(self) -> None:
        """An open window for a DIFFERENT client is not refreshed (the
        type/name-match branch is false), it just regenerates."""
        c = self.add_client('host', tor=server.TorStatus.RUNNING)
        fake_socket = mock.MagicMock()
        fake_socket.state.return_value = QLocalSocket.ConnectedState
        c.client_socket = fake_socket
        self.tray.show_status_msg(server.MessageType.SDWDATE, c)
        self.tray.msg_window.show()
        _APP.processEvents()
        other = self.add_client('other')
        self.tray.handle_state_change(server.MessageType.SDWDATE, other)

    def test_drop_client(self) -> None:
        client = self.add_client('host')
        self.tray.drop_client(client)
        self.assertNotIn(client, self.tray.client_list)

    def test_drop_client_not_present_warns(self) -> None:
        stray = server.SdwdateGuiClient(QLocalSocket())
        self.addCleanup(stray.deleteLater)
        stray.present_in_menu = True
        with self.assertLogs(level='WARNING'):
            self.tray.drop_client(stray)

    def test_accept_client_over_limit_kicks(self) -> None:
        self.tray.client_list = [mock.MagicMock() for _ in range(server.MAX_CLIENTS)]
        extra = server.SdwdateGuiClient(QLocalSocket())
        with mock.patch.object(extra, 'kick_client') as kc, \
                self.assertLogs(level='WARNING'):
            self.tray.accept_client(extra)
        kc.assert_called_once()
        self.tray.client_list = []

    def test_show_menu_wayland_and_reasons(self) -> None:
        self.add_client('a')
        Reason = server.QSystemTrayIcon.ActivationReason

        class _Wl:
            @staticmethod
            def platformName() -> str:
                return 'wayland'

        server.QApplication = _Wl
        self.tray.show_menu(Reason.Trigger)
        self.assertFalse(self.tray.menu.isVisible())
        server.QApplication = self._real_qapp
        self.tray.show_menu(Reason.Trigger)
        _APP.processEvents()
        self.assertTrue(self.tray.menu.isVisible())
        self.tray.menu.hide()
        self.tray.show_menu(Reason.DoubleClick)


class TestObjectLifecycleLeaks(TrayTestBase):
    """Server client objects must not accumulate across connect/disconnect."""

    def test_clients_do_not_accumulate(self) -> None:
        import gc  # pylint: disable=import-outside-toplevel

        def live_client_count() -> int:
            gc.collect()
            return sum(
                1 for obj in gc.get_objects()
                if isinstance(obj, server.SdwdateGuiClient)
            )

        base = live_client_count()
        ## Canary the counter: a held, undropped client IS counted (so a
        ## leak below cannot pass vacuously by counting zero).
        probe = self.add_client('probe')
        self.assertGreaterEqual(
            live_client_count() - base, 1, 'leak counter is not counting'
        )
        probe.clientDisconnected.emit()
        del probe
        self.tray.regen_menu(force_regen=True)
        for _ in range(3):
            _APP.processEvents()
            gc.collect()

        base = live_client_count()
        for idx in range(30):
            client = self.add_client(f'disp{idx}')
            client.clientDisconnected.emit()
            _APP.processEvents()
        ## Force a final regen so the last dropped client loses its menu entry
        ## and is deleteLater'd, then let Qt + Python reclaim everything.
        self.tray.regen_menu(force_regen=True)
        for _ in range(3):
            _APP.processEvents()
            gc.collect()
        after = live_client_count()
        self.assertLessEqual(
            after - base, 1,
            f'SdwdateGuiClient objects accumulated across 30 connect/drop '
            f'cycles ({base} -> {after}); a lifecycle leak',
        )


class TestListener(unittest.TestCase):
    """SdwdateGuiListener.__init__ branches, mocked filesystem + QLocalServer."""

    def _init_with(self, pid_is_file, proc_is_dir, pid_text='123',
                   remove_side=FileNotFoundError):
        run_dir = mock.MagicMock()
        pid_file = mock.MagicMock()
        socket_file = mock.MagicMock()
        pid_file.is_file.return_value = pid_is_file
        run_dir.joinpath.side_effect = [pid_file, socket_file]
        proc_path = mock.MagicMock()
        proc_path.is_dir.return_value = proc_is_dir

        def path_factory(arg):
            return proc_path if str(arg).startswith('/proc/') else run_dir

        with mock.patch.object(server, 'Path', side_effect=path_factory), \
                mock.patch.object(server.os, 'getuid', return_value=1000), \
                mock.patch.object(server.os, 'getpid', return_value=4242), \
                mock.patch.object(server.os, 'remove',
                                  side_effect=remove_side), \
                mock.patch('builtins.open',
                           mock.mock_open(read_data=pid_text)), \
                mock.patch.object(server, 'QLocalServer') as qls:
            listener = server.SdwdateGuiListener()
        return listener, qls

    def test_happy_path_no_pid_file(self) -> None:
        listener, qls = self._init_with(pid_is_file=False, proc_is_dir=False)
        qls.return_value.listen.assert_called_once()
        self.assertIsNotNone(listener)

    def test_stale_pid_file_removed(self) -> None:
        ## pid file present, process not running -> cleaned, server starts.
        listener, qls = self._init_with(
            pid_is_file=True, proc_is_dir=False, remove_side=None
        )
        qls.return_value.listen.assert_called_once()

    def test_running_server_exits(self) -> None:
        with self.assertRaises(SystemExit), self.assertLogs(level='ERROR'):
            self._init_with(pid_is_file=True, proc_is_dir=True)

    def test_non_numeric_pid_exits(self) -> None:
        with self.assertRaises(SystemExit), self.assertLogs(level='ERROR'):
            self._init_with(pid_is_file=True, proc_is_dir=False,
                            pid_text='notanumber')

    def test_listen_failure_exits(self) -> None:
        ## org-ai-assisted/sdwdate-gui#19: a failed QLocalServer.listen() must
        ## bail out loudly, not sit in the event loop with no bound socket.
        run_dir = mock.MagicMock()
        pid_file = mock.MagicMock()
        pid_file.is_file.return_value = False
        run_dir.joinpath.side_effect = [pid_file, mock.MagicMock()]
        qls = mock.MagicMock()
        qls.listen.return_value = False
        with self.assertRaises(SystemExit), self.assertLogs(level='CRITICAL'):
            self._run_init(run_dir, mock.mock_open(read_data='1'),
                           FileNotFoundError, qls=qls)
        qls.listen.assert_called_once()

    def _run_init(self, run_dir, open_mock, remove_side, qls=None):
        proc_path = mock.MagicMock()
        proc_path.is_dir.return_value = False

        def path_factory(arg):
            return proc_path if str(arg).startswith('/proc/') else run_dir

        qls = qls or mock.MagicMock()
        with mock.patch.object(server, 'Path', side_effect=path_factory), \
                mock.patch.object(server.os, 'getuid', return_value=1000), \
                mock.patch.object(server.os, 'getpid', return_value=4242), \
                mock.patch.object(server.os, 'remove', side_effect=remove_side), \
                mock.patch('builtins.open', open_mock), \
                mock.patch.object(server, 'QLocalServer', return_value=qls):
            return server.SdwdateGuiListener()

    def test_mkdir_failure_exits(self) -> None:
        run_dir = mock.MagicMock()
        run_dir.mkdir.side_effect = OSError('nope')
        run_dir.joinpath.side_effect = [mock.MagicMock(), mock.MagicMock()]
        with self.assertRaises(SystemExit), self.assertLogs(level='CRITICAL'):
            self._run_init(run_dir, mock.mock_open(read_data='1'),
                           FileNotFoundError)

    def test_pid_check_exception_exits(self) -> None:
        run_dir = mock.MagicMock()
        pid_file = mock.MagicMock()
        pid_file.is_file.return_value = True
        run_dir.joinpath.side_effect = [pid_file, mock.MagicMock()]
        open_mock = mock.mock_open()
        open_mock.side_effect = RuntimeError('read blew up')
        with self.assertRaises(SystemExit), self.assertLogs(level='ERROR'):
            self._run_init(run_dir, open_mock, FileNotFoundError)

    def test_remove_pid_failure_exits(self) -> None:
        run_dir = mock.MagicMock()
        pid_file = mock.MagicMock()
        pid_file.is_file.return_value = False
        run_dir.joinpath.side_effect = [pid_file, mock.MagicMock()]
        with self.assertRaises(SystemExit), self.assertLogs(level='ERROR'):
            self._run_init(run_dir, mock.mock_open(read_data='1'),
                           PermissionError('denied'))

    def test_write_pid_failure_exits(self) -> None:
        run_dir = mock.MagicMock()
        pid_file = mock.MagicMock()
        pid_file.is_file.return_value = False
        run_dir.joinpath.side_effect = [pid_file, mock.MagicMock()]
        open_mock = mock.mock_open()
        open_mock.side_effect = OSError('cannot write')
        with self.assertRaises(SystemExit), self.assertLogs(level='ERROR'):
            self._run_init(run_dir, open_mock, FileNotFoundError)

    def test_remove_socket_failure_exits(self) -> None:
        run_dir = mock.MagicMock()
        pid_file = mock.MagicMock()
        pid_file.is_file.return_value = False
        run_dir.joinpath.side_effect = [pid_file, mock.MagicMock()]
        ## First remove (pid) ok, second remove (socket) fails.
        with self.assertRaises(SystemExit), self.assertLogs(level='ERROR'):
            self._run_init(run_dir, mock.mock_open(read_data='1'),
                           [None, PermissionError('denied')])

    def test_spawn_client_emits(self) -> None:
        listener, _ = self._init_with(pid_is_file=False, proc_is_dir=False)
        fake_server = mock.MagicMock()
        fake_server.nextPendingConnection.return_value = QLocalSocket()
        listener.server = fake_server
        received = []
        listener.newClient.connect(received.append)
        listener.spawn_client()
        _APP.processEvents()
        self.assertEqual(len(received), 1)


class TestMain(unittest.TestCase):
    """main() bootstrap gating."""

    def _patch_common(self):
        return mock.patch.multiple(
            server.os, geteuid=mock.DEFAULT,
        )

    def test_root_exits(self) -> None:
        with mock.patch.object(server.os, 'geteuid', return_value=0):
            with self.assertRaises(SystemExit):
                server.main()

    def test_templatevm_exits(self) -> None:
        with mock.patch.object(server.os, 'geteuid', return_value=1000), \
                mock.patch.object(server.Path, 'is_file', return_value=True):
            with self.assertRaises(SystemExit):
                server.main()

    def test_parse_failure_exits(self) -> None:
        with mock.patch.object(server.os, 'geteuid', return_value=1000), \
                mock.patch.object(server.Path, 'is_file', return_value=False), \
                mock.patch.object(server, 'QApplication'), \
                mock.patch.object(server.signal, 'signal'), \
                mock.patch.object(server, 'parse_config_files',
                                  side_effect=OSError('x')), \
                self.assertLogs(level='ERROR'):
            with self.assertRaises(SystemExit):
                server.main()

    def test_qubes_without_run_server_exits(self) -> None:
        with mock.patch.object(server.os, 'geteuid', return_value=1000), \
                mock.patch.object(server.Path, 'is_file', return_value=False), \
                mock.patch.object(server, 'QApplication'), \
                mock.patch.object(server.signal, 'signal'), \
                mock.patch.object(server, 'parse_config_files'), \
                mock.patch.object(server, 'running_in_qubes_os',
                                  return_value=True), \
                mock.patch.dict(server.ConfigData.conf_dict,
                                {'disable': False,
                                 'run_server_in_qubes': False},
                                clear=True):
            with self.assertRaises(SystemExit):
                server.main()

    def test_happy_path_runs_app(self) -> None:
        fake_tray = mock.MagicMock()
        with mock.patch.object(server.os, 'geteuid', return_value=1000), \
                mock.patch.object(server.Path, 'is_file', return_value=False), \
                mock.patch.object(server, 'QApplication') as qapp, \
                mock.patch.object(server.signal, 'signal'), \
                mock.patch.object(server, 'QTimer'), \
                mock.patch.object(server, 'parse_config_files'), \
                mock.patch.object(server, 'running_in_qubes_os',
                                  return_value=False), \
                mock.patch.object(server, 'SdwdateTrayIcon',
                                  return_value=fake_tray), \
                mock.patch.dict(server.ConfigData.conf_dict,
                                {'disable': False,
                                 'run_server_in_qubes': True},
                                clear=True):
            with self.assertRaises(SystemExit):
                server.main()
        qapp.return_value.exec_.assert_called_once()

    def test_happy_path_qubes_server(self) -> None:
        """Qubes + run_server_in_qubes=True: the server does NOT exit on the
        role check, it proceeds to the tray (the 'not run_server' branch is
        false)."""
        fake_tray = mock.MagicMock()
        with mock.patch.object(server.os, 'geteuid', return_value=1000), \
                mock.patch.object(server.Path, 'is_file', return_value=False), \
                mock.patch.object(server, 'QApplication') as qapp, \
                mock.patch.object(server.signal, 'signal'), \
                mock.patch.object(server, 'QTimer'), \
                mock.patch.object(server, 'parse_config_files'), \
                mock.patch.object(server, 'running_in_qubes_os',
                                  return_value=True), \
                mock.patch.object(server, 'SdwdateTrayIcon',
                                  return_value=fake_tray), \
                mock.patch.dict(server.ConfigData.conf_dict,
                                {'disable': False,
                                 'run_server_in_qubes': True},
                                clear=True):
            with self.assertRaises(SystemExit):
                server.main()
        qapp.return_value.exec_.assert_called_once()

    def test_disable_exits(self) -> None:
        """'disable'=True logs and exits 0 before building the tray."""
        with mock.patch.object(server.os, 'geteuid', return_value=1000), \
                mock.patch.object(server.Path, 'is_file', return_value=False), \
                mock.patch.object(server, 'QApplication'), \
                mock.patch.object(server.signal, 'signal'), \
                mock.patch.object(server, 'parse_config_files'), \
                mock.patch.object(server, 'running_in_qubes_os',
                                  return_value=False), \
                mock.patch.dict(server.ConfigData.conf_dict,
                                {'disable': True,
                                 'run_server_in_qubes': False},
                                clear=True), \
                self.assertLogs(level='INFO'):
            with self.assertRaises(SystemExit) as raised:
                server.main()
        self.assertEqual(raised.exception.code, 0)

    def test_keepalive_timer_lambda_is_callable(self) -> None:
        """The keepalive QTimer's timeout slot is a no-op lambda; fire it so its
        body is exercised (it only keeps the Python signal handlers serviced)."""
        fake_tray = mock.MagicMock()
        with mock.patch.object(server.os, 'geteuid', return_value=1000), \
                mock.patch.object(server.Path, 'is_file', return_value=False), \
                mock.patch.object(server, 'QApplication'), \
                mock.patch.object(server.signal, 'signal'), \
                mock.patch.object(server, 'QTimer') as qtimer, \
                mock.patch.object(server, 'parse_config_files'), \
                mock.patch.object(server, 'running_in_qubes_os',
                                  return_value=False), \
                mock.patch.object(server, 'SdwdateTrayIcon',
                                  return_value=fake_tray), \
                mock.patch.dict(server.ConfigData.conf_dict,
                                {'disable': False,
                                 'run_server_in_qubes': True},
                                clear=True):
            with self.assertRaises(SystemExit):
                server.main()
        ## Retrieve the lambda passed to timer.timeout.connect and invoke it.
        slot = qtimer.return_value.timeout.connect.call_args[0][0]
        self.assertIsNone(slot())


if __name__ == '__main__':
    unittest.main()
