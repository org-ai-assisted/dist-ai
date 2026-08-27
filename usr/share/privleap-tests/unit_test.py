#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
In-process liveness regression tests for the privleap daemon internals.

The parser and authorizer fuzzers cover what an unprivileged client can send.
This suite covers the parts of privleapd that no client message reaches
directly but that decide whether the daemon stays alive and answerable: the
non-blocking accept path, the transient-resource accept backoff, the epoll
registration bookkeeping the main loop keeps as sockets come and go, the socket
list synchronisation between the main and control threads, the action output
pump, and the systemd watchdog ping.

Every test here is a regression test for a specific way privleapd could stop
answering, stop pinging its watchdog, or leak a timing side channel. They are
written to fail against a daemon that regresses the behaviour they cover, not
merely to exercise the fixed code.

These target the reworked (AB3) daemon: the listening socket is non-blocking
(``setblocking(False)``), an accept that fails for lack of resources is
classified by ``classify_accept_error`` and drives ``main_loop``'s inline
backoff + watchdog withholding, and epoll registration is keyed on the
``PrivleapdSocketInfo`` object identity that ``main_loop`` rebuilds whenever the
socket list changes.

Runs without root: the state directory is redirected into a temporary
directory and the ownership calls only root may make are stubbed.
"""

import argparse
import errno
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest.mock as mock
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


## How long a call that must not block is given before the test declares it
## hung. Generous enough not to trip on a loaded machine, far below the
## indefinite block a blocking-accept regression would take.
NONBLOCKING_BUDGET_S: float = 15.0

## The daemon delays an authentication failure to this many seconds after the
## request arrived, so that a client cannot tell a nonexistent action from a
## forbidden one by timing the reply.
AUTH_FAIL_DEADLINE_S: float = 3.0

## Objects that must outlive the test that created them, because a daemon
## thread the daemon code offers no way to stop is still looking at them.
_KEEPALIVE: list[Any] = []


class StateDirSandbox:
    """
    Redirects privleap's state directory into a temporary directory and stubs
    the ownership changes only root may make, so the daemon's socket handling
    can be exercised by an ordinary account.
    """

    def __init__(self, pl: ModuleType) -> None:
        self.pl: ModuleType = pl
        self.tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.saved: dict[str, Any] = {}

    def __enter__(self) -> 'StateDirSandbox':
        return self.activate()

    def activate(self) -> 'StateDirSandbox':
        """
        Redirect the state directory. Separate from __enter__ because the
        in-process daemon holds its sandbox open for the rest of the process
        rather than for the span of a with block.
        """

        # pylint: disable=consider-using-with
        # Rationale:
        #   consider-using-with: the lifetime of this directory is the
        #     lifetime of the sandbox, which deactivate() ends.
        self.tmpdir = tempfile.TemporaryDirectory(prefix='privleap-unit-')
        root: str = self.tmpdir.name
        common: Any = self.pl.PrivleapCommon
        self.saved = {
            'state_dir': common.state_dir,
            'control_path': common.control_path,
            'comm_dir': common.comm_dir,
            'chown': self.pl.os.chown,
        }
        common.state_dir = self.pl.Path(root, 'privleapd')
        common.control_path = self.pl.Path(common.state_dir, 'control')
        common.comm_dir = self.pl.Path(common.state_dir, 'comm')
        common.comm_dir.mkdir(parents=True)
        ## Only root may hand a socket to another account. These tests do not
        ## depend on the resulting ownership, only on the socket existing.
        self.pl.os.chown = lambda *_args, **_kwargs: None
        return self

    def __exit__(self, *_exc: Any) -> None:
        common: Any = self.pl.PrivleapCommon
        common.state_dir = self.saved['state_dir']
        common.control_path = self.saved['control_path']
        common.comm_dir = self.saved['comm_dir']
        self.pl.os.chown = self.saved['chown']
        if self.tmpdir is not None:
            self.tmpdir.cleanup()
            self.tmpdir = None


class FakeSession:
    """A comm session stand-in for tests that never touch the wire."""

    def __init__(self) -> None:
        self.user_name: str = current_username()
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.backend_socket: socket.socket = left
        self._peer: socket.socket = right
        self.sent: list[Any] = []

    def send_msg(self, msg: Any) -> None:
        """Record a reply the daemon chose to send."""

        self.sent.append(msg)

    def close_session(self) -> None:
        """Release the socket pair standing in for the client connection."""

        self.backend_socket.close()
        self._peer.close()


def call_with_deadline(
    func: Callable[[], Any], budget_s: float = NONBLOCKING_BUDGET_S
) -> tuple[bool, Any, BaseException | None]:
    """
    Run func on a throwaway thread and give it budget_s to return. Returns
    (finished, result, exception). A call that never returns leaves the thread
    parked, which is why it is a daemon thread: the suite must be able to
    report the hang rather than hang with it.
    """

    outcome: dict[str, Any] = {}

    def runner() -> None:
        try:
            outcome['result'] = func()
        except (Exception, SystemExit) as exc:  # pylint: disable=broad-exception-caught
            outcome['exception'] = exc

    thread: threading.Thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join(budget_s)
    if thread.is_alive():
        return False, None, None
    return True, outcome.get('result'), outcome.get('exception')


def make_socket_info(pld: ModuleType, listen_socket: Any = None) -> Any:
    """Build a PrivleapdSocketInfo with a real notification pipe pair."""

    read_fd, write_fd = os.pipe()
    os.set_blocking(write_fd, False)
    return pld.PrivleapdSocketInfo(
        listen_socket,
        read_fd,
        write_fd,
        os.fdopen(read_fd, 'rb', buffering=0),
        os.fdopen(write_fd, 'wb', buffering=0),
    )


def close_socket_info(sock_info: Any) -> None:
    """Release the notification pipes of a socket info built for a test."""

    for pipe in (
        sock_info.term_notify_read_pipe,
        sock_info.term_notify_write_pipe,
    ):
        if pipe is not None and not pipe.closed:
            pipe.close()


# ---------------------------------------------------------------------------
# main_loop drivers
#
# The reworked daemon does its epoll registration and its transient-resource
# accept backoff inline in main_loop, keyed on the PrivleapdSocketInfo object
# identity it rebuilds whenever the socket list changes. There is no standalone
# refresh/backoff helper to call, so these tests drive the real main_loop one
# iteration at a time behind a scripted fake epoll, exactly as the daemon's own
# focused tests (privleap.tests.test_daemon_defects) do.
# ---------------------------------------------------------------------------


class _StopLoop(Exception):
    """Sentinel raised by the fake epoll to break main_loop's while True."""


class _RecordingNotifier:
    """Records the sd_notify messages main_loop chose to send."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def notify(self, message: str) -> None:
        """Record one notification."""

        self.messages.append(message)


class _FakeReadPipe:
    """A ctm read pipe stand-in whose read() is a no-op returning no bytes."""

    def read(self) -> bytes:
        """Consume the connection-change wakeup byte(s); value is ignored."""

        return b''


class _FakeBackendSocket:
    """A backend socket stand-in that only has to answer fileno()."""

    def __init__(self, fd: int) -> None:
        self._fd: int = fd

    def fileno(self) -> int:
        """Return the descriptor number this fake stands in for."""

        return self._fd


class _StartRaisesThread:
    """
    Thread stand-in whose start() raises RuntimeError, emulating thread
    exhaustion (RLIMIT_NPROC / kernel thread cap). Constructed the same way
    privleapd constructs its comm threads.
    """

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def start(self) -> None:
        """Refuse to start, as the kernel does once threads are exhausted."""

        raise RuntimeError("can't start new thread")


class _RecordingCloseSession:
    """A minimal accepted-session double that records being closed."""

    def __init__(self) -> None:
        self.closed: bool = False

    def close_session(self) -> None:
        """Record that the handler closed this session."""

        self.closed = True


class _RaisingCloseSession:
    """
    An accepted-session double whose close_session() raises OSError, emulating
    a client that already disconnected (shutdown() then raises ENOTCONN).
    """

    def __init__(self) -> None:
        self.close_attempted: bool = False

    def close_session(self) -> None:
        """Record the close attempt, then raise as a gone client would."""

        self.close_attempted = True
        raise OSError(errno.ENOTCONN, 'Transport endpoint is not connected')


class _TermCommSession:
    """
    Minimal comm-session double for check_early_action_terminate: it only needs
    a backend_socket exposing fileno() and a user_name for logging.
    """

    def __init__(self, fd: int, user_name: str = 'testuser') -> None:
        self.backend_socket: _FakeBackendSocket = _FakeBackendSocket(fd)
        self.user_name: str = user_name


class _FakeListenSocket:
    """
    A listening-socket stand-in. get_session() either raises the scripted
    exception (an accept failure), returns the scripted accepted-session double,
    or records that a session was started.
    """

    def __init__(
        self,
        fd: int,
        socket_type: Any,
        raise_exc: BaseException | None = None,
        user_name: str = 'testuser',
        session: object | None = None,
    ) -> None:
        self.backend_socket: _FakeBackendSocket = _FakeBackendSocket(fd)
        self.socket_type: Any = socket_type
        self.user_name: str = user_name
        self._raise_exc: BaseException | None = raise_exc
        self._session: object | None = session
        self.session_started: bool = False

    def get_session(self) -> object:
        """Accept a connection, or raise the scripted accept failure."""

        if self._raise_exc is not None:
            raise self._raise_exc
        self.session_started = True
        if self._session is not None:
            return self._session
        return object()


class _FakeEpoll:
    """
    A select.epoll stand-in. register() records the fds main_loop watches;
    poll() replays a scripted list of ready-fd batches, then raises _StopLoop
    to break the otherwise-infinite main loop.
    """

    def __init__(self, poll_results: list[list[tuple[int, int]]]) -> None:
        self._poll_results: list[list[tuple[int, int]]] = list(poll_results)
        self.registered_fds: list[int] = []

    def register(self, fd: int, _events: int) -> None:
        """Record that main_loop registered this fd."""

        self.registered_fds.append(fd)

    def poll(self, _timeout: float) -> list[tuple[int, int]]:
        """Replay one scripted batch, or end the loop."""

        if not self._poll_results:
            raise _StopLoop()
        return self._poll_results.pop(0)


def _fake_comm_sock_info(
    pld: ModuleType,
    fd: int,
    raise_exc: BaseException | None = None,
    session: object | None = None,
) -> Any:
    """A PrivleapdSocketInfo wrapping a fake comm listening socket."""

    listen_socket: _FakeListenSocket = _FakeListenSocket(
        fd,
        pld.PrivleapSocketType.COMMUNICATION,
        raise_exc=raise_exc,
        session=session,
    )
    return pld.PrivleapdSocketInfo(listen_socket, -1, -1, None, None)


def _drive_main_loop(
    pld: ModuleType,
    poll_results: list[list[tuple[int, int]]],
    ctm_read_pipe: Any = None,
) -> tuple[_RecordingNotifier, _FakeEpoll, Any, BaseException | None]:
    """
    Run the real main_loop for the scripted poll batches, behind a fake epoll,
    a recording notifier and a mocked time.sleep. The caller sets
    PrivleapdGlobal.socket_list first; this saves and restores the notifier and
    the ctm pipe/fd it borrows. Returns the notifier, the fake epoll, the
    time.sleep mock, and whatever exception ended the loop (normally _StopLoop).
    """

    saved_notifier: Any = pld.PrivleapdGlobal.sdnotify_object
    saved_ctm_pipe: Any = pld.PrivleapdGlobal.ctm_read_pipe
    saved_ctm_fd: int = pld.PrivleapdGlobal.ctm_read_fd

    notifier: _RecordingNotifier = _RecordingNotifier()
    fake_epoll: _FakeEpoll = _FakeEpoll(poll_results)
    fake_select: Any = mock.Mock()
    fake_select.epoll = lambda: fake_epoll
    fake_select.EPOLLIN = 1

    pld.PrivleapdGlobal.sdnotify_object = notifier
    pld.PrivleapdGlobal.ctm_read_pipe = (
        ctm_read_pipe if ctm_read_pipe is not None else _FakeReadPipe()
    )
    ## A ctm fd that never collides with a scripted listening fd.
    pld.PrivleapdGlobal.ctm_read_fd = 9000

    raised: BaseException | None = None
    try:
        with mock.patch.object(
            pld, 'select', fake_select
        ), mock.patch.object(pld.time, 'sleep') as sleep_mock:
            try:
                pld.main_loop()
            except (Exception, SystemExit) as exc:  # noqa: BLE001
                raised = exc
    finally:
        pld.PrivleapdGlobal.sdnotify_object = saved_notifier
        pld.PrivleapdGlobal.ctm_read_pipe = saved_ctm_pipe
        pld.PrivleapdGlobal.ctm_read_fd = saved_ctm_fd
    return notifier, fake_epoll, sleep_mock, raised


# ---------------------------------------------------------------------------
# Main thread liveness
# ---------------------------------------------------------------------------


def test_listening_socket_is_nonblocking(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    The listening socket must be non-blocking, so an accept driven off a stale
    epoll readiness event returns at once instead of parking the main thread.

    privleapd accepts on the main thread, driven by an epoll readiness event.
    That event can be stale by the time it is acted on (the socket may have been
    destroyed and its descriptor number handed to a new socket in the meantime),
    in which case accept() finds nothing waiting. A blocking listener would park
    the main thread there forever; it stops pinging the watchdog and systemd
    kills the daemon with nothing in the log. The rework makes the listener
    non-blocking so that empty accept raises a would-block error the daemon
    classifies as a spurious wakeup and shrugs off.
    """

    print('== the listening socket is non-blocking ==')
    with StateDirSandbox(pl):
        listener: Any = pl.PrivleapSocket(pl.PrivleapSocketType.CONTROL)
        try:
            results.expect_eq(
                'the listening socket is non-blocking',
                listener.backend_socket.gettimeout(),
                0.0,
            )
            finished, session, exception = call_with_deadline(
                listener.get_session, budget_s=5.0
            )
            results.check(
                'get_session on an idle listener returns promptly instead of '
                'parking',
                finished,
            )
            results.check(
                'get_session on an idle listener raises rather than returning '
                'a session',
                session is None and exception is not None,
            )
            results.check(
                'the empty accept is classified as a spurious wakeup, not a '
                'resource error',
                pld.classify_accept_error(exception)
                is pld.PrivleapdAcceptError.SPURIOUS,
            )
        finally:
            listener.close()


def test_stale_ready_event_does_not_hang_daemon(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    The main loop's connection handlers must survive a stale readiness event.

    This is the caller-side half of the non-blocking accept: given a socket
    with no pending connection, handle_comm_socket_conn and
    handle_control_socket_conn must return promptly rather than block, and
    must not mistake the empty accept for a real session.
    """

    print('== stale readiness events do not hang the connection handlers ==')
    user: str = current_username()
    with StateDirSandbox(pl):
        control_socket: Any = pl.PrivleapSocket(pl.PrivleapSocketType.CONTROL)
        comm_socket: Any = pl.PrivleapSocket(
            pl.PrivleapSocketType.COMMUNICATION, user
        )
        sock_info: Any = make_socket_info(pld, comm_socket)
        try:
            finished, _r, _e = call_with_deadline(
                lambda: pld.handle_control_socket_conn(control_socket)
            )
            results.check(
                'handle_control_socket_conn returns on a stale event', finished
            )
            finished, _r, _e = call_with_deadline(
                lambda: pld.handle_comm_socket_conn(sock_info)
            )
            results.check(
                'handle_comm_socket_conn returns on a stale event', finished
            )
            results.check(
                'no control session was queued from a stale event',
                pld.PrivleapdGlobal.control_request_queue.empty(),
            )
        finally:
            close_socket_info(sock_info)
            control_socket.close()
            comm_socket.close()


def test_accept_failure_does_not_spin(
    results: Results, pld: ModuleType
) -> None:
    """
    An accept that fails for lack of resources must not turn the main loop
    into a spin.

    A connection that could not be accepted stays in the kernel's backlog, so
    the level-triggered epoll keeps the listening socket readable and the same
    event comes straight back. Without a pause the loop runs flat out: busy
    enough that its watchdog keeps telling systemd the daemon is healthy while
    it answers nobody. Any client can cause this by holding connections open
    until the descriptor limit is reached. main_loop must, on such an
    iteration, back off (time.sleep by the resource backoff) AND withhold the
    watchdog ping. An ordinary accept failure -- a client that hung up -- is not
    a resource problem and must neither back off nor be reported unhealthy.
    """

    print('== an accept that ran out of descriptors does not spin ==')

    ## A descriptor-exhaustion accept (EMFILE) on a ready comm fd.
    emfile_fd: int = 42
    saved_list: list[Any] = pld.PrivleapdGlobal.socket_list
    pld.PrivleapdGlobal.socket_list = [
        _fake_comm_sock_info(
            pld, emfile_fd, raise_exc=OSError(errno.EMFILE, 'Too many open')
        )
    ]
    try:
        notifier, _epoll, sleep_mock, raised = _drive_main_loop(
            pld, [[(emfile_fd, 1)]]
        )
        results.check(
            'the EMFILE iteration ended cleanly', isinstance(raised, _StopLoop)
        )
        results.check(
            'running out of descriptors backs off by the resource backoff',
            sleep_mock.call_count == 1
            and sleep_mock.call_args
            == mock.call(pld.accept_resource_backoff_seconds),
        )
        results.check(
            'the watchdog is withheld while backing off on EMFILE',
            'WATCHDOG=1' not in notifier.messages,
        )
        results.expect_eq(
            'the EMFILE socket never established a session',
            pld.PrivleapdGlobal.socket_list[0].listen_socket.session_started,
            False,
        )
    finally:
        pld.PrivleapdGlobal.socket_list = saved_list

    ## An ordinary accept failure: a client that aborted. Not a resource
    ## problem, so no backoff, and the iteration is still healthy.
    ordinary_fd: int = 43
    pld.PrivleapdGlobal.socket_list = [
        _fake_comm_sock_info(
            pld, ordinary_fd, raise_exc=ConnectionAbortedError('went away')
        )
    ]
    try:
        notifier, _epoll, sleep_mock, _raised = _drive_main_loop(
            pld, [[(ordinary_fd, 1)]]
        )
        results.expect_eq(
            'an ordinary accept failure schedules no backoff',
            sleep_mock.call_count,
            0,
        )
        results.check(
            'an ordinary accept failure still pings the watchdog',
            'WATCHDOG=1' in notifier.messages,
        )
    finally:
        pld.PrivleapdGlobal.socket_list = saved_list

    ## A healthy idle iteration must still ping the watchdog, so the backoff
    ## gating did not break ordinary liveness.
    pld.PrivleapdGlobal.socket_list = []
    try:
        notifier, _epoll, sleep_mock, _raised = _drive_main_loop(pld, [[]])
        results.check(
            'a healthy idle iteration pings the watchdog',
            'WATCHDOG=1' in notifier.messages,
        )
    finally:
        pld.PrivleapdGlobal.socket_list = saved_list


def test_reused_descriptor_is_registered(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A socket that reuses a just-closed descriptor number must still be watched.

    The kernel hands the descriptor number of a closed socket straight back to
    the next socket opened. main_loop keys its epoll registrations on the
    PrivleapdSocketInfo *object*, not on the descriptor number, and rebuilds
    them whenever the socket list changes -- so a destroy immediately followed
    by a create (what a reload, or a leapctl destroy then create, does) is a new
    object and gets registered even though its descriptor number is unchanged.
    A descriptor-number-keyed scheme would have seen no change at all and never
    registered the new socket, and connections to it would never be accepted for
    the remaining lifetime of the daemon.
    """

    print('== a reused descriptor number is registered ==')
    user: str = current_username()
    with StateDirSandbox(pl):
        saved_list: list[Any] = pld.PrivleapdGlobal.socket_list
        socket_path: Any = pl.Path(pl.PrivleapCommon.comm_dir, user)
        pld.PrivleapdGlobal.socket_list = []
        first_socket: Any = pl.PrivleapSocket(
            pl.PrivleapSocketType.COMMUNICATION, user
        )
        pld.socket_list_add(first_socket)
        first_fd: int = first_socket.backend_socket.fileno()

        state: dict[str, Any] = {
            'swapped': False,
            'second': None,
            'second_info': None,
            'second_fd': None,
        }

        def swap_on_ctm_read() -> bytes:
            ## The connection-change the control thread signals during a reload:
            ## destroy the socket and immediately recreate it, with no main
            ## loop turn in between, so the new socket reuses the freed fd.
            if not state['swapped']:
                close_socket_info(pld.PrivleapdGlobal.socket_list.pop(0))
                first_socket.close()
                socket_path.unlink(missing_ok=True)
                second: Any = pl.PrivleapSocket(
                    pl.PrivleapSocketType.COMMUNICATION, user
                )
                pld.socket_list_add(second)
                state['swapped'] = True
                state['second'] = second
                state['second_info'] = pld.PrivleapdGlobal.socket_list[-1]
                state['second_fd'] = second.backend_socket.fileno()
            return b''

        ctm_pipe: Any = type(
            '_SwapPipe', (), {'read': staticmethod(swap_on_ctm_read)}
        )()
        try:
            ## Poll returns the ctm event once (triggering the destroy/create),
            ## then _StopLoop -- so main_loop does two registration passes: the
            ## first for first_socket, the second (after the swap) for the
            ## recreated socket.
            _notifier, fake_epoll, _sleep, raised = _drive_main_loop(
                pld, [[(9000, 1)]], ctm_read_pipe=ctm_pipe
            )
            results.check(
                'the registration passes ended cleanly',
                isinstance(raised, _StopLoop),
            )
            results.check(
                'the destroy/create cycle ran', state['swapped']
            )
            reused: bool = state['second_fd'] == first_fd
            results.check(
                'the recreated socket reused the closed descriptor number',
                reused,
            )
            results.check(
                'the recreated socket was registered with epoll',
                state['second_fd'] in fake_epoll.registered_fds,
            )
            if reused:
                ## Object-identity keying registers the reused fd a SECOND time
                ## (once per distinct socket object); a descriptor-keyed scheme
                ## would have registered it only once and missed the new socket.
                results.expect_eq(
                    'the reused descriptor was registered for both sockets',
                    fake_epoll.registered_fds.count(first_fd),
                    2,
                )
        finally:
            if state['second_info'] is not None:
                close_socket_info(state['second_info'])
            if state['second'] is not None:
                state['second'].close()
            else:
                close_socket_info(pld.PrivleapdGlobal.socket_list.pop(0))
                first_socket.close()
            socket_path.unlink(missing_ok=True)
            pld.PrivleapdGlobal.socket_list = saved_list


def test_destroyed_socket_is_unregistered(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A readiness event for a socket that was removed from the list must be
    skipped, not turned into an accept on a closed descriptor.

    A control thread can remove and close a socket in the window between
    epoll_obj.poll() and the main thread taking socket_list_lock, leaving a
    stale readiness event for an fd that is gone (or already reused).
    dispatch_ready_sockets must skip such an fd and report the iteration
    healthy; turning it into an accept on a closed socket, or terminating the
    daemon over it, is the defect this guards.
    """

    print('== a destroyed socket is skipped, not accepted on ==')
    user: str = current_username()
    with StateDirSandbox(pl):
        saved_list: list[Any] = pld.PrivleapdGlobal.socket_list
        pld.PrivleapdGlobal.socket_list = []
        try:
            comm_socket: Any = pl.PrivleapSocket(
                pl.PrivleapSocketType.COMMUNICATION, user
            )
            pld.socket_list_add(comm_socket)
            comm_fd: int = comm_socket.backend_socket.fileno()

            ## While the socket is live, dispatch accepts on it (a stale event
            ## on a live socket is a spurious wakeup, handled, healthy).
            results.check(
                'a live socket is dispatched healthily',
                pld.dispatch_ready_sockets([comm_fd]) is True,
            )

            ## Destroy it: remove from the list and close it.
            close_socket_info(pld.PrivleapdGlobal.socket_list.pop(0))
            comm_socket.close()

            queue_empty_before: bool = (
                pld.PrivleapdGlobal.control_request_queue.empty()
            )
            healthy: bool = pld.dispatch_ready_sockets([comm_fd])
            results.check(
                'a destroyed socket\'s stale event is skipped and reported '
                'healthy',
                healthy is True,
            )
            results.check(
                'no session was queued from a destroyed socket',
                queue_empty_before
                and pld.PrivleapdGlobal.control_request_queue.empty(),
            )
        finally:
            pld.PrivleapdGlobal.socket_list = saved_list


def test_thread_exhaustion_backs_off_and_closes_session(
    results: Results, pld: ModuleType
) -> None:
    """
    An accept that succeeds but whose handler thread cannot start must not crash
    the daemon.

    accept() returns a session, then Thread.start() raises RuntimeError (thread
    exhaustion: RLIMIT_NPROC or the kernel thread cap). Any local account can
    drive the process count to that limit. handle_comm_socket_conn must catch
    the RuntimeError, close the accepted session, and return False (back off) --
    not let the RuntimeError escape into dispatch_ready_sockets and main_loop,
    which would crash the root daemon, the very failure this handler prevents.
    """

    print('== thread exhaustion backs off and closes the session ==')
    session: _RecordingCloseSession = _RecordingCloseSession()
    sock_info: Any = _fake_comm_sock_info(pld, 42, session=session)
    with mock.patch.object(pld, 'Thread', _StartRaisesThread):
        finished, result, exception = call_with_deadline(
            lambda: pld.handle_comm_socket_conn(sock_info)
        )
    results.check('the thread-exhaustion handler returns', finished)
    results.check(
        'thread exhaustion does not let the RuntimeError escape the handler',
        exception is None,
    )
    results.check(
        'thread exhaustion returns False to trigger the resource backoff',
        result is False,
    )
    results.check(
        'the accepted session was closed on thread exhaustion', session.closed
    )


def test_thread_exhaustion_close_oserror_does_not_escape(
    results: Results, pld: ModuleType
) -> None:
    """
    Closing the accepted session while backing off on thread exhaustion must
    survive a client that already disconnected.

    Same path as the previous test, but the accepted session's close_session()
    raises OSError (the client is gone, so shutdown() raises ENOTCONN).
    handle_comm_socket_conn must swallow that OSError and STILL return False;
    letting it escape would crash the root daemon just as the unguarded
    Thread.start() would.
    """

    print('== a raising close_session on thread exhaustion does not escape ==')
    session: _RaisingCloseSession = _RaisingCloseSession()
    sock_info: Any = _fake_comm_sock_info(pld, 42, session=session)
    with mock.patch.object(pld, 'Thread', _StartRaisesThread):
        finished, result, exception = call_with_deadline(
            lambda: pld.handle_comm_socket_conn(sock_info)
        )
    results.check(
        'the handler returns even when close_session raises', finished
    )
    results.check(
        'a raising close_session does not escape the handler',
        exception is None,
    )
    results.check(
        'a raising close_session still backs off (returns False)',
        result is False,
    )
    results.check(
        'close_session was attempted before it raised', session.close_attempted
    )


def test_dispatch_breaks_on_first_resource_error(
    results: Results, pld: ModuleType
) -> None:
    """
    A resource-exhaustion accept must break the per-fd dispatch loop, not go on
    hammering the rest of the ready batch.

    Two ready comm fds in one batch: the first hits EMFILE, the second would
    accept cleanly. dispatch_ready_sockets must break on the first RESOURCE
    error and return False, so the second socket is never accept-attempted and
    no handler thread is constructed. A loop that only marked the iteration
    unhealthy but kept iterating would accept the second socket while the daemon
    is already out of descriptors -- exactly the storm the backoff exists to
    stop.
    """

    print('== a RESOURCE error breaks the per-fd dispatch loop ==')
    saved_list: list[Any] = pld.PrivleapdGlobal.socket_list
    first: Any = _fake_comm_sock_info(
        pld, 42, raise_exc=OSError(errno.EMFILE, 'Too many open files')
    )
    second: Any = _fake_comm_sock_info(pld, 43)
    pld.PrivleapdGlobal.socket_list = [first, second]
    try:
        with mock.patch.object(pld, 'Thread') as thread_mock:
            result: bool = pld.dispatch_ready_sockets([42, 43])
        results.check(
            'a RESOURCE error makes the iteration report unhealthy',
            result is False,
        )
        results.expect_eq(
            'the EMFILE socket never established a session',
            first.listen_socket.session_started,
            False,
        )
        results.expect_eq(
            'after a RESOURCE error the loop breaks rather than accepting the '
            'next ready socket in the batch',
            second.listen_socket.session_started,
            False,
        )
        results.check(
            'no handler thread was constructed after the RESOURCE error',
            not thread_mock.called,
        )
    finally:
        pld.PrivleapdGlobal.socket_list = saved_list


def test_connection_change_and_emfile_co_occurrence(
    results: Results, pld: ModuleType
) -> None:
    """
    A poll batch that carries BOTH a connection-change notification and an
    EMFILE listening fd must consume the notification AND still back off.

    The restructured main loop must, in that one iteration: (a) read the ctm
    connection-change notification exactly once, (b) still dispatch the
    co-occurring listening fd so its EMFILE backoff (time.sleep) runs, and (c)
    withhold the watchdog for the iteration. A loop that consumed the ctm event
    and then short-circuited the rest of the batch would skip the EMFILE fd
    entirely -- no backoff, and a WATCHDOG=1 telling systemd the pegged,
    non-serving daemon is healthy.
    """

    print('== a connection change co-occurring with EMFILE still backs off ==')

    read_calls: list[int] = [0]

    class _CountingReadPipe:
        """A ctm read pipe stand-in that counts how often it was read."""

        def read(self) -> bytes:
            """Consume the connection-change wakeup byte and count the call."""

            read_calls[0] += 1
            return b''

    emfile_fd: int = 42
    ## _drive_main_loop pins PrivleapdGlobal.ctm_read_fd to 9000.
    ctm_fd: int = 9000
    saved_list: list[Any] = pld.PrivleapdGlobal.socket_list
    sock_info: Any = _fake_comm_sock_info(
        pld, emfile_fd, raise_exc=OSError(errno.EMFILE, 'Too many open files')
    )
    pld.PrivleapdGlobal.socket_list = [sock_info]
    try:
        notifier, _epoll, sleep_mock, raised = _drive_main_loop(
            pld,
            [[(ctm_fd, 1), (emfile_fd, 1)]],
            ctm_read_pipe=_CountingReadPipe(),
        )
        results.check(
            'the co-occurrence iteration ended cleanly',
            isinstance(raised, _StopLoop),
        )
        results.expect_eq(
            'the connection-change notification was read exactly once',
            read_calls[0],
            1,
        )
        results.check(
            'the co-occurring EMFILE fd was still dispatched and backed off',
            sleep_mock.call_count == 1
            and sleep_mock.call_args
            == mock.call(pld.accept_resource_backoff_seconds),
        )
        results.expect_eq(
            'the EMFILE socket never established a session',
            sock_info.listen_socket.session_started,
            False,
        )
        results.check(
            'the watchdog is withheld even though a connection change was '
            'consumed',
            'WATCHDOG=1' not in notifier.messages,
        )
    finally:
        pld.PrivleapdGlobal.socket_list = saved_list


def test_early_terminate_keeps_shared_term_notify_open(
    results: Results, pld: ModuleType
) -> None:
    """
    A sibling that terminates on should_terminate must not close the term_notify
    pipes it shares with the account's other comm threads.

    Several comm threads for one account share a single PrivleapdSocketInfo and
    each epolls its term_notify_read_fd. When should_terminate is set,
    check_early_action_terminate must return True WITHOUT closing the shared
    pipes -- otherwise the first sibling to terminate yanks the read fd out from
    under a still-blocking sibling, which could then miss its terminate wake.
    This drives two sibling calls against the SAME socket_info (real os.pipe()-
    backed pipes): both must return True and the pipes must stay open.
    """

    print('== an early terminate keeps the shared term_notify pipes open ==')
    read_fd, write_fd = os.pipe()
    os.set_blocking(write_fd, False)
    read_pipe: Any = os.fdopen(read_fd, 'rb', buffering=0)
    write_pipe: Any = os.fdopen(write_fd, 'wb', buffering=0)
    ## One wake byte, never consumed, so the read fd stays level-triggered
    ## readable for every sibling.
    write_pipe.write(b'\x00')
    sock_info: Any = pld.PrivleapdSocketInfo(
        _FakeListenSocket(50, pld.PrivleapSocketType.COMMUNICATION),
        read_fd,
        write_fd,
        read_pipe,
        write_pipe,
        should_terminate=True,
    )
    try:
        session_a: _TermCommSession = _TermCommSession(60)
        session_b: _TermCommSession = _TermCommSession(61)
        ## The sessions' backend fds are deliberately NOT in ready_fds, so the
        ## should_terminate branch (not the client-TERMINATE branch) is what
        ## returns True.
        ready_fds: list[int] = []

        result_a: bool = pld.check_early_action_terminate(
            sock_info, ready_fds, session_a, 'testaction'
        )
        results.check(
            'the first sibling observes should_terminate and returns True',
            result_a is True,
        )
        results.expect_eq(
            'the first sibling does not close the shared read pipe',
            read_pipe.closed,
            False,
        )
        results.expect_eq(
            'the first sibling does not close the shared write pipe',
            write_pipe.closed,
            False,
        )

        result_b: bool = pld.check_early_action_terminate(
            sock_info, ready_fds, session_b, 'testaction'
        )
        results.check(
            'the second sibling also returns True on the still-open pipes',
            result_b is True,
        )
        results.expect_eq(
            'the shared read pipe stays open after both siblings terminate',
            read_pipe.closed,
            False,
        )
        results.expect_eq(
            'the shared write pipe stays open after both siblings terminate',
            write_pipe.closed,
            False,
        )
    finally:
        if not read_pipe.closed:
            read_pipe.close()
        if not write_pipe.closed:
            write_pipe.close()


class InProcessDaemon:
    """
    Runs the real privleapd main and control threads in this process against a
    sandboxed state directory, so the genuine socket bookkeeping can be driven
    end to end without root, systemd, or a subprocess.

    This is deliberately the whole loop rather than one helper: the socket
    registration defects it is here to catch live in how the main loop, the
    control thread and the descriptor allocator interleave, which no
    single-function test can reproduce.

    privleapd offers no way to stop either thread, and both read module level
    state, so exactly one of these may exist per process and it has to be the
    last thing set up. get_in_process_daemon() enforces that.
    """

    def __init__(self, pl: ModuleType, pld: ModuleType, user: str) -> None:
        self.pl: ModuleType = pl
        self.pld: ModuleType = pld
        self.user: str = user
        self.sandbox: StateDirSandbox = StateDirSandbox(pl)

    def start(self) -> 'InProcessDaemon':
        """Bring the sandboxed daemon up. Never torn down again."""

        pld: ModuleType = self.pld
        self.sandbox.activate()
        pld.PrivleapdGlobal.socket_list = []
        pld.PrivleapdGlobal.allowed_user_list = [self.user]
        ## An action the probe below is allowed to ask about. Probing an
        ## unknown action instead would make the daemon hold every single
        ## reply for its constant-time authentication failure delay, turning
        ## a socket-bookkeeping test into a three-second-per-probe timing
        ## test that reports a slow machine as the regression.
        pld.PrivleapdGlobal.action_list = [
            self.pl.PrivleapAction(
                'unit-probe', 'true', [self.user], [], None, None
            )
        ]
        pld.open_control_socket()
        pld.prep_sock_notify_pipe()
        threading.Thread(target=pld.control_handler_loop, daemon=True).start()
        threading.Thread(target=pld.main_loop, daemon=True).start()
        return self

    def control_request(self, msg: Any, timeout_s: float = 10.0) -> str | None:
        """
        Send one control message and return the reply's type name, or None if
        no reply arrived.

        Bounded on purpose. privleap's client-side read retries indefinitely
        on a timeout, by design, so a daemon whose control thread has died
        leaves a caller waiting forever. That is one of the conditions under
        test here, so the harness must be able to outlive it and report it.
        """

        def ask() -> str | None:
            session: Any = self.pl.PrivleapSession(is_control_session=True)
            try:
                session.send_msg(msg)
                return str(session.get_msg().name)
            except Exception:  # pylint: disable=broad-exception-caught
                return None
            finally:
                try:
                    session.close_session()
                except OSError:
                    pass

        finished, result, _exc = call_with_deadline(ask, budget_s=timeout_s)
        if not finished:
            return None
        return result if isinstance(result, str) else None

    def comm_socket_answers(self, timeout_s: float = 10.0) -> bool:
        """
        Ask the account's comm socket a question and report whether an answer
        came back. An unregistered socket accepts the connection at the kernel
        level but no thread ever picks it up, so the reply simply never
        arrives, which is exactly the shape of the defect being probed for.
        """

        def ask() -> bool:
            session: Any = self.pl.PrivleapSession(
                self.user, is_control_session=False
            )
            try:
                session.send_msg(
                    self.pl.PrivleapCommClientAccessCheckMsg(['unit-probe'])
                )
                while True:
                    name: str = session.get_msg().name
                    if name == 'ACCESS_CHECK_RESULTS_END':
                        return True
            except Exception:  # pylint: disable=broad-exception-caught
                return False
            finally:
                try:
                    session.close_session()
                except OSError:
                    pass

        finished, result, _exc = call_with_deadline(ask, budget_s=timeout_s)
        return bool(finished and result)


def get_in_process_daemon(
    pl: ModuleType, pld: ModuleType, user: str
) -> InProcessDaemon:
    """
    Return the one in-process daemon, starting it on first use. It is kept
    alive for the rest of the process because privleapd's main and control
    loops cannot be stopped; a second set of them would fight the first over
    the same module level socket list.
    """

    for entry in _KEEPALIVE:
        if isinstance(entry, InProcessDaemon):
            return entry
    daemon: InProcessDaemon = InProcessDaemon(pl, pld, user).start()
    _KEEPALIVE.append(daemon)
    return daemon


## How many destroy-then-create cycles the socket bookkeeping regression is
## probed with. The defect needs the create to land before the main loop next
## rebuilds its registrations, which is a race, so a single cycle can pass on
## broken code. A reload does exactly this pairing every time it runs.
RECREATE_CYCLES: int = 40


def test_live_daemon_answers_after_socket_recreate(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A comm socket destroyed and immediately recreated within one control
    thread turn must still be a socket the daemon answers on.

    This is the whole-daemon form of the descriptor reuse defect. The control
    thread does exactly this pairing during a reload: it prunes sockets whose
    accounts are no longer allowed, then opens sockets for persistent
    accounts, with no main loop turn in between. The kernel hands the
    destroyed socket's descriptor number straight to the new socket, and
    registration bookkeeping keyed on that number saw no change at all, so the
    new socket was never added to the main loop's epoll set. Clients then
    connected successfully and waited forever for a reply no thread was ever
    going to send.
    """

    print('== the daemon still answers after a destroy/create cycle ==')
    user: str = current_username()
    daemon: InProcessDaemon = get_in_process_daemon(pl, pld, user)
    created: str | None = daemon.control_request(
        pl.PrivleapControlClientCreateMsg(user)
    )
    results.expect_eq('the comm socket was created', created, 'OK')
    results.check(
        'the daemon answers on a freshly created socket',
        daemon.comm_socket_answers(),
    )
    socket_path = pl.Path(pl.PrivleapCommon.comm_dir, user)

    deaf_cycle: int | None = None
    for cycle in range(RECREATE_CYCLES):
        ## Drive the destroy and the create from one thread with nothing
        ## in between, the way the control thread drives a reload.
        def recreate() -> None:
            index: int = _socket_index(pld, user)
            pld.socket_list_stop_sync(index)
            socket_path.unlink(missing_ok=True)
            pld.socket_list_add_sync(
                pl.PrivleapSocket(
                    pl.PrivleapSocketType.COMMUNICATION, user
                )
            )

        finished, _r, exc = call_with_deadline(recreate, budget_s=20.0)
        if not finished or exc is not None:
            results.check(
                f"cycle {cycle}: the recreate itself completed "
                f"({'hung' if not finished else exc})",
                False,
            )
            deaf_cycle = cycle
            break
        if not daemon.comm_socket_answers(timeout_s=6.0):
            deaf_cycle = cycle
            break

    results.expect_eq(
        f"the daemon answers on the recreated socket, every cycle "
        f"(of {RECREATE_CYCLES})",
        deaf_cycle,
        None,
    )


def _socket_index(pld: ModuleType, user: str) -> int:
    """Index of an account's comm socket in the daemon's socket list."""

    for index, sock_info in enumerate(pld.PrivleapdGlobal.socket_list):
        if sock_info.listen_socket.user_name == user:
            return index
    raise LookupError(f"no comm socket for account '{user}'")


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------


def test_live_daemon_pings_watchdog_while_serving(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    The main loop must keep pinging the watchdog while it is serving requests,
    not only while it is idle.

    main_loop pings WATCHDOG=1 on every healthy iteration -- idle, a consumed
    connection change, or a healthy dispatch -- and withholds it only on a
    transient-resource backoff. A ping that only fired between connections would
    let a steady stream of connection work overrun the watchdog deadline while
    the daemon is in fact healthy. This drives the live daemon through repeated
    comm requests and confirms the watchdog keeps being pinged throughout.
    """

    print('== the main loop keeps pinging the watchdog while serving ==')
    user: str = current_username()
    daemon: InProcessDaemon = get_in_process_daemon(pl, pld, user)
    daemon.control_request(pl.PrivleapControlClientCreateMsg(user))

    ## Swap in a recorder for the live daemon's notifier for the span of the
    ## probe, so the WATCHDOG=1 pings its main loop sends can be counted.
    saved_notifier: Any = pld.PrivleapdGlobal.sdnotify_object
    notifier: _RecordingNotifier = _RecordingNotifier()
    pld.PrivleapdGlobal.sdnotify_object = notifier
    try:
        deadline: float = time.monotonic() + 3.0
        served: int = 0
        while time.monotonic() < deadline:
            if daemon.comm_socket_answers(timeout_s=5.0):
                served += 1
        pings: int = notifier.messages.count('WATCHDOG=1')
        results.check(
            f"the daemon kept serving while watched ({served} answered)",
            served > 0,
        )
        results.check(
            f"the watchdog was pinged while serving ({pings} pings)",
            pings > 0,
        )
    finally:
        pld.PrivleapdGlobal.sdnotify_object = saved_notifier


# ---------------------------------------------------------------------------
# Comm thread liveness
# ---------------------------------------------------------------------------


def test_action_output_pump_is_not_a_busy_loop(
    results: Results, pld: ModuleType
) -> None:
    """
    An action that closes one output stream and keeps the other open must not
    cost the daemon a core. Measured as processor time actually consumed by
    the pump, which is what starves the main thread.
    """

    print('== the action output pump does not spin on a half-closed action ==')
    sock_info: Any = make_socket_info(pld)
    session: FakeSession = FakeSession()
    ## stdout closes immediately, stderr stays open and silent, then both end.
    bash_path: str = shutil.which('bash') or '/bin/bash'
    action: Any = pld.subprocess.Popen(
        [bash_path, '-c', '--', 'exec 1>&-; sleep 2'],
        stdout=pld.subprocess.PIPE,
        stderr=pld.subprocess.PIPE,
        stdin=pld.subprocess.PIPE,
    )
    os.set_blocking(action.stdout.fileno(), False)
    os.set_blocking(action.stderr.fileno(), False)
    action.stdin.close()
    try:
        ## Per-thread, not per-process: os.times() would count every other
        ## thread in the interpreter, so this measurement would quietly start
        ## reporting someone else's work if the suite ever grew a background
        ## thread or was reordered.
        pump_cpu: list[float] = []

        def run_pump() -> None:
            started: float = time.thread_time()
            try:
                pld.send_action_results(
                    session, 'unit-action', action, sock_info
                )
            finally:
                pump_cpu.append(time.thread_time() - started)

        finished, _r, exception = call_with_deadline(run_pump, budget_s=30.0)
        cpu_s: float = pump_cpu[0] if pump_cpu else float('inf')
        results.check('the output pump finished', finished)
        results.check('the output pump did not raise', exception is None)
        results.check(
            f"the pump stayed idle while waiting (used {cpu_s:.2f}s of "
            'processor time over ~2s)',
            cpu_s < 0.5,
        )
    finally:
        session.close_session()
        close_socket_info(sock_info)
        if action.poll() is None:
            action.kill()
            action.wait()


# ---------------------------------------------------------------------------
# Constant-time authentication failure
# ---------------------------------------------------------------------------


def _timed_auth_failure(
    pld: ModuleType, auth_cost_s: float, invoke: Callable[[], None]
) -> float:
    """
    Run a failing authentication whose own work takes auth_cost_s, and return
    how long the daemon took to get to its reply.
    """

    saved_auth: Any = pld.auth_signal_request
    saved_send: Any = pld.send_msg_safe
    try:

        def slow_failing_auth(*_args: Any, **_kwargs: Any) -> None:
            time.sleep(auth_cost_s)

        pld.auth_signal_request = slow_failing_auth
        pld.send_msg_safe = lambda *_a, **_k: True
        started: float = time.monotonic()
        invoke()
        return time.monotonic() - started
    finally:
        pld.auth_signal_request = saved_auth
        pld.send_msg_safe = saved_send


def test_auth_failure_reply_is_constant_time(
    results: Results, pld: ModuleType
) -> None:
    """
    The authentication failure delay must absorb the time authentication took.

    The delay exists so a client cannot tell a nonexistent action from a
    forbidden one by timing the reply. Sleeping a fixed three seconds *after*
    the variable authentication work leaves that difference fully visible in
    the reply, which is the leak the delay was added to close.
    """

    print('== an authentication failure replies at a constant time ==')
    sock_info: Any = make_socket_info(pld)
    session: FakeSession = FakeSession()
    auth_cost_s: float = 1.5
    message: Any = type(
        'SignalMsg', (), {'signal_name': 'unit-missing-action'}
    )()
    try:
        elapsed: float = _timed_auth_failure(
            pld,
            auth_cost_s,
            lambda: pld.handle_signal_message(message, session, sock_info),
        )
        results.check(
            f"the reply does not leak the authentication time (replied after "
            f"{elapsed:.2f}s of a {AUTH_FAIL_DEADLINE_S:.1f}s deadline, with "
            f"{auth_cost_s:.1f}s of authentication work)",
            elapsed < AUTH_FAIL_DEADLINE_S + auth_cost_s / 2,
        )
        results.check(
            'the reply is still held back to the constant deadline',
            elapsed >= AUTH_FAIL_DEADLINE_S - 0.25,
        )
    finally:
        session.close_session()
        close_socket_info(sock_info)


def test_access_check_reply_is_constant_time(
    results: Results, pld: ModuleType
) -> None:
    """
    The same requirement applies to an access check, where the variable work
    is proportional to how many actions the client asked about and so is far
    easier for a client to steer.
    """

    print('== an access check failure replies at a constant time ==')
    session: FakeSession = FakeSession()
    signal_count: int = 6
    per_signal_cost_s: float = 0.25
    total_cost_s: float = per_signal_cost_s * signal_count
    message: Any = type(
        'AccessCheckMsg',
        (),
        {
            'signal_name_list': [
                f"unit-missing-{index}" for index in range(signal_count)
            ]
        },
    )()
    try:
        elapsed: float = _timed_auth_failure(
            pld,
            per_signal_cost_s,
            lambda: pld.handle_access_check_message(message, session),
        )
        results.check(
            f"the reply does not leak the access check time (replied after "
            f"{elapsed:.2f}s of a {AUTH_FAIL_DEADLINE_S:.1f}s deadline, with "
            f"{total_cost_s:.1f}s of authentication work)",
            elapsed < AUTH_FAIL_DEADLINE_S + total_cost_s / 2,
        )
        results.check(
            'the reply is still held back to the constant deadline',
            elapsed >= AUTH_FAIL_DEADLINE_S - 0.25,
        )
    finally:
        session.close_session()


def run_test(
    results: Results, test: Callable[..., None], *args: Any
) -> None:
    """
    Run one test, turning an unexpected exception into a recorded failure.

    A test that explodes must not take the rest of the suite with it: against
    a regressed tree a missing helper or a torn-down socket is exactly the
    kind of failure the suite exists to report, and the remaining tests still
    have findings to contribute.
    """

    try:
        test(results, *args)
    except (Exception, SystemExit) as exc:  # pylint: disable=broad-exception-caught
        results.check(f"{test.__name__} raised {type(exc).__name__}: {exc}", False)


def main() -> int:
    """Entry point."""

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='privleap daemon liveness regression tests'
    )
    parser.add_argument(
        '--seed', type=int, default=1, help='accepted for interface parity'
    )
    parser.parse_args()

    pl: ModuleType = import_privleap()
    pld: ModuleType = import_privleapd()
    results: Results = Results()

    ## Order matters. Everything that borrows privleapd's module level socket
    ## list runs first, while nothing else is looking at it. The tests that
    ## start unstoppable daemon threads run last, because from then on that
    ## state belongs to those threads.
    run_test(results, test_listening_socket_is_nonblocking, pl, pld)
    run_test(results, test_stale_ready_event_does_not_hang_daemon, pl, pld)
    run_test(results, test_accept_failure_does_not_spin, pld)
    run_test(results, test_reused_descriptor_is_registered, pl, pld)
    run_test(results, test_destroyed_socket_is_unregistered, pl, pld)
    run_test(results, test_thread_exhaustion_backs_off_and_closes_session, pld)
    run_test(results, test_thread_exhaustion_close_oserror_does_not_escape, pld)
    run_test(results, test_dispatch_breaks_on_first_resource_error, pld)
    run_test(results, test_connection_change_and_emfile_co_occurrence, pld)
    run_test(results, test_early_terminate_keeps_shared_term_notify_open, pld)
    run_test(results, test_action_output_pump_is_not_a_busy_loop, pld)
    run_test(results, test_auth_failure_reply_is_constant_time, pld)
    run_test(results, test_access_check_reply_is_constant_time, pld)
    run_test(results, test_live_daemon_answers_after_socket_recreate, pl, pld)
    ## Last: it starts the unstoppable in-process daemon threads (via the
    ## recreate test's shared daemon) and probes them while serving.
    run_test(results, test_live_daemon_pings_watchdog_while_serving, pl, pld)

    print('')
    return results.report('daemon liveness test')


if __name__ == '__main__':
    sys.exit(main())
