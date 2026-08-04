#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Tests for privleapd's control-message handling and startup lifecycle.

These are the paths that decide who gets a comm socket and whether the daemon
comes up at all. They are not reachable from a comm socket, so the fuzzers do
not cover them, but they carry the same consequences: a create that answers OK
for an account that should have been refused is an authorization failure, and
a startup check that passes when it should not leaves two daemons fighting
over one socket directory.

The liveness regressions live in unit_test.py, the parser in config_test.py,
and the client tools in client_test.py.

Runs without root: the state directory is redirected into a temporary
directory and the ownership calls only root may make are stubbed.
"""

import argparse
import inspect
import io
import os
import sys
import tempfile
from types import ModuleType
from typing import Any, Callable

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import (  # noqa: E402
    Results,
    current_username,
    import_privleap,
    import_privleapd,
)


class DaemonSandbox:
    """
    Redirects privleap's state directory and isolates the daemon's module
    level lists, so each test starts from a known state and leaves nothing
    behind.
    """

    GLOBALS: tuple[str, ...] = (
        'socket_list',
        'action_list',
        'persistent_user_list',
        'allowed_user_list',
        'allowed_group_list',
        'expected_disallowed_user_list',
    )

    def __init__(
        self, pl: ModuleType, pld: ModuleType, make_dirs: bool = True
    ) -> None:
        self.pl: ModuleType = pl
        self.pld: ModuleType = pld
        self.make_dirs: bool = make_dirs
        self.tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.saved: dict[str, Any] = {}

    def __enter__(self) -> 'DaemonSandbox':
        self.tmpdir = tempfile.TemporaryDirectory(prefix='privleap-daemon-')
        common: Any = self.pl.PrivleapCommon
        self.saved = {
            'state_dir': common.state_dir,
            'control_path': common.control_path,
            'comm_dir': common.comm_dir,
            'pid_file_path': self.pld.PrivleapdGlobal.pid_file_path,
            'chown': self.pl.os.chown,
        }
        for name in self.GLOBALS:
            self.saved[name] = getattr(self.pld.PrivleapdGlobal, name)
            setattr(self.pld.PrivleapdGlobal, name, [])
        common.state_dir = self.pl.Path(self.tmpdir.name, 'privleapd')
        common.control_path = self.pl.Path(common.state_dir, 'control')
        common.comm_dir = self.pl.Path(common.state_dir, 'comm')
        self.pld.PrivleapdGlobal.pid_file_path = self.pl.Path(
            common.state_dir, 'pid'
        )
        if self.make_dirs:
            common.comm_dir.mkdir(parents=True)
        self.pl.os.chown = lambda *_args, **_kwargs: None
        return self

    def __exit__(self, *_exc: Any) -> None:
        common: Any = self.pl.PrivleapCommon
        for sock_info in list(self.pld.PrivleapdGlobal.socket_list):
            try:
                sock_info.listen_socket.close()
            except OSError:
                pass
        common.state_dir = self.saved['state_dir']
        common.control_path = self.saved['control_path']
        common.comm_dir = self.saved['comm_dir']
        self.pld.PrivleapdGlobal.pid_file_path = self.saved['pid_file_path']
        self.pl.os.chown = self.saved['chown']
        for name in self.GLOBALS:
            setattr(self.pld.PrivleapdGlobal, name, self.saved[name])
        if self.tmpdir is not None:
            self.tmpdir.cleanup()
            self.tmpdir = None


class RecordingSession:
    """A session that records the replies the daemon chose to send."""

    def __init__(self, user_name: str | None = None) -> None:
        self.user_name: str | None = user_name
        self.backend_socket: Any = None
        self.sent: list[Any] = []
        self.closed: bool = False
        self.incoming: list[Any] = []
        self.fail_on_send: bool = False

    def send_msg(self, msg: Any) -> None:
        """Record a reply, or fail the way a hung-up client makes it fail."""

        if self.fail_on_send:
            raise ConnectionAbortedError('unit-injected send failure')
        self.sent.append(msg)

    def get_msg(self) -> Any:
        """Hand over the next scripted client message."""

        if not self.incoming:
            raise ConnectionAbortedError('unit-injected end of messages')
        return self.incoming.pop(0)

    def close_session(self) -> None:
        """Record that the daemon closed the session."""

        self.closed = True

    def reply_names(self) -> list[str]:
        """The type names of everything the daemon sent, in order."""

        return [msg.name for msg in self.sent]


def prep_sock_notify_pipe_once(pld: ModuleType) -> None:
    """
    Make sure the control-to-main wakeup pipe exists. The socket list helpers
    write to it, and outside of a running daemon nothing else has set it up.
    """

    if pld.PrivleapdGlobal.ctm_write_pipe is None:
        pld.prep_sock_notify_pipe()


# ---------------------------------------------------------------------------
# Comm socket creation and destruction
# ---------------------------------------------------------------------------


def test_create_refuses_the_accounts_it_should(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A create must answer OK only for an account the configuration actually
    allows. Every other outcome has its own reply, because leapctl turns them
    into different exit codes.
    """

    print('== a comm socket is created only for an allowed account ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        prep_sock_notify_pipe_once(pld)

        cases: list[tuple[str, str, list[str], list[str], str]] = [
            (
                'an account that does not exist',
                'privleap-no-such-account',
                [],
                [],
                'CONTROL_ERROR',
            ),
            (
                'an account that is not allowed',
                user,
                [],
                [],
                'DISALLOWED_USER',
            ),
            (
                'an account that is expected to be disallowed',
                user,
                [],
                [user],
                'EXPECTED_DISALLOWED_USER',
            ),
            ('an allowed account', user, [user], [], 'OK'),
        ]
        for label, target, allowed, expected_disallowed, want in cases:
            pld.PrivleapdGlobal.allowed_user_list = list(allowed)
            pld.PrivleapdGlobal.expected_disallowed_user_list = list(
                expected_disallowed
            )
            session: RecordingSession = RecordingSession()
            pld.handle_control_create_msg(
                session, pl.PrivleapControlClientCreateMsg(target)
            )
            results.expect_eq(
                f"create for {label}", session.reply_names(), [want]
            )

        ## The account now has a socket, so a second create must say so
        ## rather than building a second one.
        session = RecordingSession()
        pld.handle_control_create_msg(
            session, pl.PrivleapControlClientCreateMsg(user)
        )
        results.expect_eq(
            'create for an account that already has one',
            session.reply_names(),
            ['EXISTS'],
        )
        results.expect_eq(
            'no duplicate socket was added',
            len(pld.PrivleapdGlobal.socket_list),
            1,
        )


def test_destroy_outcomes(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A destroy answers differently for a socket that existed, one that never
    did, and one belonging to a persistent account, which privleapd refuses to
    remove.
    """

    print('== a comm socket destroy reports what actually happened ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        prep_sock_notify_pipe_once(pld)
        pld.PrivleapdGlobal.allowed_user_list = [user]

        session: RecordingSession = RecordingSession()
        pld.handle_control_destroy_msg(
            session, pl.PrivleapControlClientDestroyMsg(user)
        )
        results.expect_eq(
            'destroy for an account with no socket',
            session.reply_names(),
            ['NOUSER'],
        )

        pld.handle_control_create_msg(
            RecordingSession(), pl.PrivleapControlClientCreateMsg(user)
        )
        session = RecordingSession()
        pld.handle_control_destroy_msg(
            session, pl.PrivleapControlClientDestroyMsg(user)
        )
        results.expect_eq(
            'destroy for an account with a socket',
            session.reply_names(),
            ['OK'],
        )
        results.expect_eq(
            'the socket is gone from the list',
            len(pld.PrivleapdGlobal.socket_list),
            0,
        )
        results.check(
            'the socket file is gone from the filesystem',
            not os.path.exists(str(pl.Path(pl.PrivleapCommon.comm_dir, user))),
        )

        pld.handle_control_create_msg(
            RecordingSession(), pl.PrivleapControlClientCreateMsg(user)
        )
        pld.PrivleapdGlobal.persistent_user_list = [user]
        session = RecordingSession()
        pld.handle_control_destroy_msg(
            session, pl.PrivleapControlClientDestroyMsg(user)
        )
        results.expect_eq(
            'destroy for a persistent account',
            session.reply_names(),
            ['PERSISTENT_USER'],
        )
        results.expect_eq(
            'a persistent account keeps its socket',
            len(pld.PrivleapdGlobal.socket_list),
            1,
        )


def test_destroy_survives_a_missing_socket_file(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    If the socket file has already gone, the daemon must still drop its own
    record of it. Leaving a stale entry behind would make the account look
    like it still has a working socket forever.
    """

    print('== a destroy with the socket file already gone still succeeds ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        prep_sock_notify_pipe_once(pld)
        pld.PrivleapdGlobal.allowed_user_list = [user]
        pld.handle_control_create_msg(
            RecordingSession(), pl.PrivleapControlClientCreateMsg(user)
        )
        os.unlink(str(pl.Path(pl.PrivleapCommon.comm_dir, user)))

        real_user, result = pld.destroy_comm_socket(user)
        results.expect_eq('the account name is reported back', real_user, user)
        results.expect_eq(
            'the destroy is reported as successful',
            result,
            pld.PrivleapdCommDestroyResult.SUCCESS,
        )
        results.expect_eq(
            'the daemon dropped its record of the socket',
            len(pld.PrivleapdGlobal.socket_list),
            0,
        )


def test_pruning_removes_no_longer_allowed_accounts(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    After a config reload takes an account's permission away, its existing
    comm socket must be taken away too. A socket that outlives its grant is a
    standing grant nobody can see in the config.
    """

    print('== a reload removes sockets for no-longer-allowed accounts ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        prep_sock_notify_pipe_once(pld)
        pld.PrivleapdGlobal.allowed_user_list = [user]
        pld.handle_control_create_msg(
            RecordingSession(), pl.PrivleapControlClientCreateMsg(user)
        )
        results.expect_eq(
            'the account has a socket to begin with',
            len(pld.PrivleapdGlobal.socket_list),
            1,
        )

        pld.PrivleapdGlobal.allowed_user_list = []
        pld.prune_disallowed_comm_sockets()
        results.expect_eq(
            'the socket is pruned once the grant is gone',
            len(pld.PrivleapdGlobal.socket_list),
            0,
        )

        ## A still-allowed account must not be pruned along with it.
        pld.PrivleapdGlobal.allowed_user_list = [user]
        pld.handle_control_create_msg(
            RecordingSession(), pl.PrivleapControlClientCreateMsg(user)
        )
        pld.prune_disallowed_comm_sockets()
        results.expect_eq(
            'a still-allowed account keeps its socket',
            len(pld.PrivleapdGlobal.socket_list),
            1,
        )


def test_group_membership_is_re_read_every_time(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    Group membership is looked up fresh on every check, so that adding or
    removing an account from an allowed group takes effect without a restart.
    A cached answer would leave a removed account authorized.
    """

    print('== group membership decides access and is re-read each time ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        pld.PrivleapdGlobal.allowed_group_list = []
        results.expect_eq(
            'no groups allowed means no access',
            pld.is_user_allowed(user),
            False,
        )

        user_group: str = pld.grp.getgrgid(
            pld.pwd.getpwnam(user).pw_gid
        ).gr_name
        pld.PrivleapdGlobal.allowed_group_list = [user_group]
        results.expect_eq(
            "the account's own primary group grants access",
            pld.is_user_allowed(user),
            True,
        )

        pld.PrivleapdGlobal.allowed_group_list = ['privleap-no-such-group']
        results.expect_eq(
            'a group that does not exist grants nothing',
            pld.is_user_allowed(user),
            False,
        )
        results.expect_eq(
            'an account that does not exist is never allowed',
            pld.is_user_allowed('privleap-no-such-account'),
            False,
        )

        pld.PrivleapdGlobal.allowed_group_list = []
        pld.PrivleapdGlobal.allowed_user_list = [user]
        results.expect_eq(
            'an explicit user grant works without any group',
            pld.is_user_allowed(user),
            True,
        )

        ## The property the docstring names: membership is read fresh every
        ## time. Changing the allowed-group LIST does not test that -- an
        ## implementation that cached the group database at import would pass
        ## every check above while leaving a removed account authorized until
        ## the daemon restarted. So vary what the database itself reports.
        pld.PrivleapdGlobal.allowed_user_list = []
        pld.PrivleapdGlobal.allowed_group_list = ['privleap-unit-group']
        saved_getgrnam: Any = pld.grp.getgrnam
        try:
            membership: list[str] = [user]

            def changing_getgrnam(name: str) -> Any:
                if name != 'privleap-unit-group':
                    return saved_getgrnam(name)
                return pld.grp.struct_group(
                    ('privleap-unit-group', 'x', 987654, list(membership))
                )

            pld.grp.getgrnam = changing_getgrnam
            results.expect_eq(
                'membership in an allowed group grants access',
                pld.is_user_allowed(user),
                True,
            )
            membership = []
            results.expect_eq(
                'access is withdrawn as soon as membership is, with no '
                'restart',
                pld.is_user_allowed(user),
                False,
            )
        finally:
            pld.grp.getgrnam = saved_getgrnam


# ---------------------------------------------------------------------------
# Control session dispatch
# ---------------------------------------------------------------------------


def test_dangling_primary_group_does_not_lock_out(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    An account whose primary group has no group entry must still be able to
    run the actions it is authorized for.

    getgrouplist() returns the primary GID whether or not a group exists for
    it, so resolving every GID eagerly raised KeyError and locked that account
    out of every group-authorized action -- a stale group entry, or an LDAP
    primary group that fails to resolve, is enough. It fails closed, so it
    grants nothing, but it denies service to a legitimate account.
    """

    print('== a dangling primary group does not lock an account out ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        saved_getgrouplist: Any = pld.os.getgrouplist
        saved_getgrgid: Any = pld.grp.getgrgid
        try:
            ## One resolvable group, one GID with no entry at all.
            real_gid: int = pld.pwd.getpwnam(user).pw_gid
            pld.os.getgrouplist = lambda _n, _g: [real_gid, 987654]

            def getgrgid_missing(gid: int) -> Any:
                if gid == 987654:
                    raise KeyError(f"getgrgid(): gid not found: {gid}")
                return saved_getgrgid(gid)

            pld.grp.getgrgid = getgrgid_missing
            real_group: str = saved_getgrgid(real_gid).gr_name
            action: Any = pl.PrivleapAction(
                'unit-group-action', 'true', [], [real_group], None, None
            )
            results.expect_eq(
                'the account is still authorized through its resolvable group',
                pld.authorize_user(action, user),
                pld.PrivleapdAuthStatus.AUTHORIZED,
            )

            ## And an account with ONLY the unresolvable group is refused
            ## rather than crashing.
            pld.os.getgrouplist = lambda _n, _g: [987654]
            results.expect_eq(
                'an account with only an unresolvable group is refused',
                pld.authorize_user(action, user),
                pld.PrivleapdAuthStatus.UNAUTHORIZED,
            )
        finally:
            pld.os.getgrouplist = saved_getgrouplist
            pld.grp.getgrgid = saved_getgrgid


def test_control_session_dispatch(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    Each control message reaches its handler, the session is always closed,
    and a client that sends nothing usable is handled without taking the
    control thread down.
    """

    print('== control messages are dispatched and the session closed ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        prep_sock_notify_pipe_once(pld)
        pld.PrivleapdGlobal.allowed_user_list = [user]

        session: RecordingSession = RecordingSession()
        session.incoming = [pl.PrivleapControlClientCreateMsg(user)]
        pld.handle_control_session(session)
        results.expect_eq(
            'a CREATE reaches the create handler',
            session.reply_names(),
            ['OK'],
        )
        results.check('the session was closed', session.closed)

        session = RecordingSession()
        session.incoming = [pl.PrivleapControlClientDestroyMsg(user)]
        pld.handle_control_session(session)
        results.expect_eq(
            'a DESTROY reaches the destroy handler',
            session.reply_names(),
            ['OK'],
        )

        ## A client that hangs up before sending anything must not produce a
        ## reply, and must not leave the session open.
        session = RecordingSession()
        pld.handle_control_session(session)
        results.expect_eq(
            'a client that sends nothing gets no reply',
            session.reply_names(),
            [],
        )
        results.check(
            'the session is still closed after a failed read', session.closed
        )


def test_reload_reports_success_and_failure(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A reload must answer OK only when the new configuration actually loaded.
    Answering OK for a config that failed to parse would tell an
    administrator their change is live when the daemon is still running the
    old rules.
    """

    print('== a reload reports whether the config actually loaded ==')
    with DaemonSandbox(pl, pld):
        saved_parse: Any = pld.parse_config_files
        try:
            pld.parse_config_files = lambda: True
            session: RecordingSession = RecordingSession()
            pld.handle_control_reload_msg(session)
            results.expect_eq(
                'a config that loads is reported OK',
                session.reply_names(),
                ['OK'],
            )

            pld.parse_config_files = lambda: False
            session = RecordingSession()
            pld.handle_control_reload_msg(session)
            results.expect_eq(
                'a config that fails to load is reported as an error',
                session.reply_names(),
                ['CONTROL_ERROR'],
            )
        finally:
            pld.parse_config_files = saved_parse


def test_send_failures_are_survivable(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A client that hangs up before reading its reply is ordinary, not
    exceptional. Sending must report the failure rather than raise it into
    the control thread.
    """

    print('== a client that hangs up mid-reply is handled ==')
    with DaemonSandbox(pl, pld):
        session: RecordingSession = RecordingSession()
        results.expect_eq(
            'a successful send is reported as such',
            pld.send_msg_safe(session, pl.PrivleapControlServerOkMsg()),
            True,
        )
        session.fail_on_send = True
        results.expect_eq(
            'a failed send is reported as such',
            pld.send_msg_safe(session, pl.PrivleapControlServerOkMsg()),
            False,
        )


def test_comm_session_rejects_a_revoked_account(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    An account whose permission was revoked while it held an open socket must
    be refused at the start of the next session, and its socket queued for
    destruction. Otherwise a revoked account keeps working until the daemon
    restarts.
    """

    print('== a revoked account is refused and its socket queued to go ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        while not pld.PrivleapdGlobal.control_request_queue.empty():
            pld.PrivleapdGlobal.control_request_queue.get()
        pld.PrivleapdGlobal.allowed_user_list = []
        session: RecordingSession = RecordingSession(user)
        sock_info: Any = pld.PrivleapdSocketInfo(None, 0, 0, None, None)
        pld.handle_comm_session(session, sock_info)
        results.expect_eq(
            'a revoked account gets no reply', session.reply_names(), []
        )
        results.check('the session was closed', session.closed)
        results.check(
            'the socket was queued for destruction',
            not pld.PrivleapdGlobal.control_request_queue.empty(),
        )
        request: Any = pld.PrivleapdGlobal.control_request_queue.get()
        results.expect_eq(
            'the queued request is a destroy for that account',
            (request.get('type'), request.get('user_name')),
            ('destroy_comm_sock', user),
        )


def test_first_message_must_be_a_request(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    Only a SIGNAL or an ACCESS_CHECK may open a comm session. Anything else,
    including a control message smuggled onto a comm socket, must be refused
    without being acted on.
    """

    print('== a comm session must open with a SIGNAL or an ACCESS_CHECK ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        session: RecordingSession = RecordingSession(user)
        session.incoming = [pl.PrivleapCommClientSignalMsg('act')]
        results.check(
            'a SIGNAL is accepted as the first message',
            pld.get_client_initial_msg(session) is not None,
        )

        session = RecordingSession(user)
        session.incoming = [pl.PrivleapCommClientAccessCheckMsg(['act'])]
        results.check(
            'an ACCESS_CHECK is accepted as the first message',
            pld.get_client_initial_msg(session) is not None,
        )

        session = RecordingSession(user)
        session.incoming = [pl.PrivleapCommClientTerminateMsg()]
        results.expect_eq(
            'a TERMINATE is refused as the first message',
            pld.get_client_initial_msg(session),
            None,
        )

        session = RecordingSession(user)
        results.expect_eq(
            'a client that sends nothing is refused',
            pld.get_client_initial_msg(session),
            None,
        )


def test_terminate_assertion(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    Once an action is running, TERMINATE is the only message the client may
    send. Anything else is logged and ignored rather than acted on.
    """

    print('== only TERMINATE is accepted while an action runs ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        session: RecordingSession = RecordingSession(user)
        session.incoming = [pl.PrivleapCommClientTerminateMsg()]
        pld.assert_action_terminate(session, 'act')
        results.expect_eq(
            'a TERMINATE produces no reply', session.reply_names(), []
        )
        ## Consumption is what separates reading the message from ignoring it:
        ## a function body of 'return' would satisfy the no-reply check alone.
        results.expect_eq(
            'the TERMINATE was actually read', session.incoming, []
        )

        session = RecordingSession(user)
        session.incoming = [pl.PrivleapCommClientSignalMsg('act')]
        pld.assert_action_terminate(session, 'act')
        results.expect_eq(
            'a wrong message produces no reply', session.reply_names(), []
        )
        results.expect_eq(
            'the wrong message was actually read', session.incoming, []
        )

        session = RecordingSession(user)
        pld.assert_action_terminate(session, 'act')
        results.expect_eq(
            'a hung-up client produces no reply', session.reply_names(), []
        )


# ---------------------------------------------------------------------------
# Startup lifecycle
# ---------------------------------------------------------------------------


def test_startup_refuses_a_second_daemon(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    Two privleapd processes would fight over one socket directory. The PID
    file check must refuse to start when a live one is recorded, and must not
    refuse over a stale or unreadable record.
    """

    print('== startup refuses to run a second daemon ==')
    with DaemonSandbox(pl, pld) as sandbox:
        pid_path: Any = pld.PrivleapdGlobal.pid_file_path
        pid_path.parent.mkdir(parents=True, exist_ok=True)

        results.check(
            'no PID file means nothing is running',
            _returns_normally(pld.verify_not_running_twice),
        )

        pid_path.write_text('not-a-pid\n', encoding='utf-8')
        results.check(
            'an unreadable PID file is not treated as a running daemon',
            _returns_normally(pld.verify_not_running_twice),
        )

        ## A PID that cannot exist: the check must conclude nothing is
        ## running rather than refusing forever over a stale file.
        pid_path.write_text('2147483646\n', encoding='utf-8')
        results.check(
            'a stale PID file is not treated as a running daemon',
            _returns_normally(pld.verify_not_running_twice),
        )

        pid_path.write_text(f"{os.getpid()}\n", encoding='utf-8')
        results.check(
            'a live PID file stops the daemon starting',
            _exits_with(pld.verify_not_running_twice, 1),
        )
        _ = sandbox


def test_state_dir_lifecycle(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    The state directory is created fresh at startup and cleaned up from a
    previous run. Reusing a directory left by an older daemon would reuse its
    sockets too.
    """

    print('== the state directory is cleaned and recreated at startup ==')
    with DaemonSandbox(pl, pld, make_dirs=False) as sandbox:
        state_dir: Any = pl.PrivleapCommon.state_dir
        state_dir.mkdir(parents=True)
        (state_dir / 'leftover').write_text('old', encoding='utf-8')
        pld.cleanup_old_state_dir()
        results.check(
            'an old state directory is removed', not state_dir.exists()
        )
        results.check(
            'cleanup with nothing to clean is fine',
            _returns_normally(pld.cleanup_old_state_dir),
        )

        pld.populate_state_dir()
        results.check('the state directory is created', state_dir.exists())
        results.check(
            'the comm directory is created',
            pl.PrivleapCommon.comm_dir.is_dir(),
        )
        results.check(
            'the PID file records this process',
            pld.PrivleapdGlobal.pid_file_path.read_text(
                encoding='utf-8'
            ).strip()
            == str(os.getpid()),
        )
        results.check(
            'populating over an existing state directory is refused',
            _exits_with(pld.populate_state_dir, 1),
        )
        _ = sandbox


def test_persistent_sockets_are_opened(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    Persistent accounts get their sockets without anyone asking, and an
    account in the list that no longer exists must be skipped rather than
    stopping the rest from being opened.
    """

    print('== persistent accounts get sockets at startup ==')
    user: str = current_username()
    with DaemonSandbox(pl, pld):
        prep_sock_notify_pipe_once(pld)
        pld.PrivleapdGlobal.persistent_user_list = [
            'privleap-no-such-account',
            user,
        ]
        pld.open_persistent_comm_sockets(in_control_thread=False)
        results.expect_eq(
            'only the account that exists got a socket',
            [
                info.listen_socket.user_name
                for info in pld.PrivleapdGlobal.socket_list
            ],
            [user],
        )

        ## Called again from the control thread, as a reload does: it must
        ## notice the socket already exists rather than making a second one.
        pld.open_persistent_comm_sockets(in_control_thread=True)
        results.expect_eq(
            'a second pass adds no duplicate',
            len(pld.PrivleapdGlobal.socket_list),
            1,
        )


def test_root_requirement(results: Results, pld: ModuleType) -> None:
    """
    privleapd runs actions as other accounts, so it cannot work unprivileged.
    It must refuse rather than start and fail later.
    """

    print('== privleapd refuses to run unprivileged ==')
    if os.geteuid() == 0:
        results.check(
            'running as root is accepted',
            _returns_normally(pld.ensure_running_as_root),
        )
        return
    results.check(
        'running unprivileged is refused',
        _exits_with(pld.ensure_running_as_root, 1),
    )


def test_config_list_helpers(results: Results, pld: ModuleType) -> None:
    """The small helpers the config merge is built out of."""

    print('== config merge helpers ==')
    items: list[str] = []
    pld.append_if_not_in('a', items)
    pld.append_if_not_in('a', items)
    pld.append_if_not_in('b', items)
    results.expect_eq('appending skips duplicates', items, ['a', 'b'])

    results.expect_eq(
        'an empty list quotes to nothing',
        pld.str_list_quote_and_comma_delimit([]),
        '',
    )
    results.expect_eq(
        'one item needs no separator',
        pld.str_list_quote_and_comma_delimit(['a']),
        "'a'",
    )
    results.expect_eq(
        'several items are comma separated',
        pld.str_list_quote_and_comma_delimit(['a', 'b']),
        "'a', 'b'",
    )


def test_command_line_handling(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    privleapd's own command line. --check-config is what a package's
    postinst and systemcheck rely on to tell a good config from a bad one, so
    its exit code has to be right; an unrecognised argument must be refused
    rather than ignored.
    """

    print('== the privleapd command line behaves ==')
    saved_argv: list[str] = sys.argv
    saved_umask: Any = pld.PrivleapdGlobal.check_config_mode
    with ConfigDirForCheck(pl) as conf_path:
        try:
            cases: list[tuple[str, list[str], int, str]] = [
                ('--help', ['privleapd', '--help'], 0, 'privleapd ['),
                ('-h', ['privleapd', '-h'], 0, 'privleapd ['),
                ('-?', ['privleapd', '-?'], 0, 'privleapd ['),
                (
                    'an unrecognised argument',
                    ['privleapd', '--nonsense'],
                    1,
                    'Unrecognized argument',
                ),
            ]
            for label, argv, want, want_text in cases:
                pld.PrivleapdGlobal.check_config_mode = False
                sys.argv = argv
                exit_code, output = _main_output(pld)
                results.expect_eq(f"{label} exits {want}", exit_code, want)
                results.check(
                    f"{label} says why (not just the wrong exit code)",
                    want_text in output,
                )

            saved_dirs: Any = pld.PrivleapdGlobal.config_dir_list
            try:
                pld.PrivleapdGlobal.config_dir_list = [pl.Path(conf_path)]
                pld.PrivleapdGlobal.check_config_mode = False
                sys.argv = ['privleapd', '--check-config']
                results.expect_eq(
                    '--check-config accepts a good config',
                    _main_exit_code(pld),
                    0,
                )

                with open(
                    os.path.join(conf_path, 'bad.conf'), 'w', encoding='utf-8'
                ) as handle:
                    handle.write('User=root\n')
                pld.PrivleapdGlobal.check_config_mode = False
                sys.argv = ['privleapd', '-C']
                results.expect_eq(
                    '--check-config refuses a bad config',
                    _main_exit_code(pld),
                    1,
                )
            finally:
                pld.PrivleapdGlobal.config_dir_list = saved_dirs
        finally:
            sys.argv = saved_argv
            pld.PrivleapdGlobal.check_config_mode = saved_umask


class ConfigDirForCheck:
    """A config directory holding one valid config file."""

    def __init__(self, pl: ModuleType) -> None:
        self.pl: ModuleType = pl
        self.tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.saved_check: Any = None

    def __enter__(self) -> str:
        self.tmpdir = tempfile.TemporaryDirectory(prefix='privleap-cli-')
        path: str = os.path.join(self.tmpdir.name, 'conf.d')
        os.mkdir(path, 0o755)
        ## getattr_static so the staticmethod descriptor itself is saved.
        ## A plain class attribute read hands back the underlying
        ## function, and restoring that would leave PrivleapCommon with an
        ## ordinary method that binds an instance as its first argument.
        self.saved_check = inspect.getattr_static(
            self.pl.PrivleapCommon, 'check_secure_file_permissions'
        )
        self.pl.PrivleapCommon.check_secure_file_permissions = staticmethod(
            lambda _file_id: True
        )
        with open(
            os.path.join(path, 'good.conf'), 'w', encoding='utf-8'
        ) as handle:
            handle.write(
                f"[action:act]\nCommand=true\n"
                f"AuthorizedUsers={current_username()}\n"
            )
        return path

    def __exit__(self, *_exc: Any) -> None:
        self.pl.PrivleapCommon.check_secure_file_permissions = (
            self.saved_check
        )
        if self.tmpdir is not None:
            self.tmpdir.cleanup()
            self.tmpdir = None


def _main_output(pld: ModuleType) -> tuple[int, str]:
    """
    Run privleapd's main() with sys.argv already set, returning its exit code
    and everything it printed.

    The output matters as much as the code here: this suite runs
    unprivileged, so main() exits 1 from ensure_running_as_root() too. An
    argument check that had been deleted entirely would still produce exit 1
    and look correct.
    """

    saved_stdout: Any = sys.stdout
    saved_stderr: Any = sys.stderr
    captured: io.StringIO = io.StringIO()
    try:
        sys.stdout = captured
        sys.stderr = captured
        try:
            pld.main()
        except SystemExit as exc:
            return int(exc.code or 0), captured.getvalue()
        return -1, captured.getvalue()
    finally:
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr


def _main_exit_code(pld: ModuleType) -> int:
    """
    Run privleapd's main() with sys.argv already set, returning the exit code
    it chose. Every path main() takes for these arguments ends in sys.exit
    before any socket is opened.
    """

    saved_stdout: Any = sys.stdout
    saved_stderr: Any = sys.stderr
    # pylint: disable=consider-using-with
    # Rationale:
    #   consider-using-with: the sink has to outlive the redirect it backs,
    #     and is closed alongside it in the same finally.
    sink: Any = open(os.devnull, 'w', encoding='utf-8')
    try:
        sys.stdout = sink
        sys.stderr = sink
        try:
            pld.main()
        except SystemExit as exc:
            return int(exc.code or 0)
        return -1
    finally:
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr
        sink.close()


def _returns_normally(func: Callable[[], Any]) -> bool:
    """True if func returns without raising."""

    try:
        func()
    except BaseException:  # pylint: disable=broad-exception-caught
        return False
    return True


def _exits_with(func: Callable[[], Any], code: int) -> bool:
    """True if func exits with the given code."""

    try:
        func()
    except SystemExit as exc:
        return int(exc.code or 0) == code
    except BaseException:  # pylint: disable=broad-exception-caught
        return False
    return False


def run_test(
    results: Results, test: Callable[..., None], *args: Any
) -> None:
    """Run one test, turning an unexpected exception into a failure."""

    try:
        test(results, *args)
    except BaseException as exc:  # pylint: disable=broad-exception-caught
        results.check(
            f"{test.__name__} raised {type(exc).__name__}: {exc}", False
        )


def main() -> int:
    """Entry point."""

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='privleapd control and lifecycle tests'
    )
    parser.add_argument(
        '--seed', type=int, default=1, help='accepted for interface parity'
    )
    parser.parse_args()

    pl: ModuleType = import_privleap()
    pld: ModuleType = import_privleapd()
    results: Results = Results()

    run_test(results, test_create_refuses_the_accounts_it_should, pl, pld)
    run_test(results, test_destroy_outcomes, pl, pld)
    run_test(results, test_destroy_survives_a_missing_socket_file, pl, pld)
    run_test(results, test_pruning_removes_no_longer_allowed_accounts, pl, pld)
    run_test(results, test_group_membership_is_re_read_every_time, pl, pld)
    run_test(results, test_dangling_primary_group_does_not_lock_out, pl, pld)
    run_test(results, test_control_session_dispatch, pl, pld)
    run_test(results, test_reload_reports_success_and_failure, pl, pld)
    run_test(results, test_send_failures_are_survivable, pl, pld)
    run_test(results, test_comm_session_rejects_a_revoked_account, pl, pld)
    run_test(results, test_first_message_must_be_a_request, pl, pld)
    run_test(results, test_terminate_assertion, pl, pld)
    run_test(results, test_startup_refuses_a_second_daemon, pl, pld)
    run_test(results, test_state_dir_lifecycle, pl, pld)
    run_test(results, test_persistent_sockets_are_opened, pl, pld)
    run_test(results, test_root_requirement, pld)
    run_test(results, test_config_list_helpers, pld)
    run_test(results, test_command_line_handling, pl, pld)

    print('')
    return results.report('daemon control test')


if __name__ == '__main__':
    sys.exit(main())
