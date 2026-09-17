#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
In-process liveness regression tests for the privleap daemon internals.

The parser and authorizer fuzzers cover what an unprivileged client can send.
This suite covers the parts of privleapd that no client message reaches
directly but that decide whether the daemon stays alive and answerable: the
epoll registration bookkeeping the main loop keeps as sockets come and go, the
socket list synchronisation between the main and control threads, the shared
term-notify pipe lifecycle, the action output pump, the systemd watchdog ping,
and the constant-time reply that keeps an authorization failure from leaking a
timing side channel.

Every test here is a regression test for a specific way privleapd could stop
answering, stop pinging its watchdog, or leak a timing side channel. They are
written to fail against a daemon that regresses the behaviour they cover, not
merely to exercise the fixed code.

Runs without root: the state directory is redirected into a temporary
directory and the ownership calls only root may make are stubbed.
"""

import argparse
import os
import pwd
import shutil
import socket
import sys
import tempfile
import threading
import time
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
        self.user_uid: int = pwd.getpwnam(current_username()).pw_uid
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
# Test doubles
# ---------------------------------------------------------------------------


class _RecordingNotifier:
    """Records the sd_notify messages main_loop chose to send."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def notify(self, message: str) -> None:
        """Record one notification."""

        self.messages.append(message)


class _FakeBackendSocket:
    """A backend socket stand-in that only has to answer fileno()."""

    def __init__(self, fd: int) -> None:
        self._fd: int = fd

    def fileno(self) -> int:
        """Return the descriptor number this fake stands in for."""

        return self._fd


class _TermCommSession:
    """
    Minimal comm-session double for check_early_action_terminate: it only needs
    a backend_socket exposing fileno() and a user_uid for logging.
    """

    def __init__(self, fd: int, user_uid: int = 4321) -> None:
        self.backend_socket: _FakeBackendSocket = _FakeBackendSocket(fd)
        self.user_uid: int = user_uid


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
        user_uid: int = 4321,
        session: object | None = None,
    ) -> None:
        self.backend_socket: _FakeBackendSocket = _FakeBackendSocket(fd)
        self.socket_type: Any = socket_type
        self.user_uid: int = user_uid
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


# ---------------------------------------------------------------------------
# main_loop driver
#
# main_loop() is an infinite epoll loop. To exercise it a bounded number of
# iterations against the REAL code, a scripted epoll replays a fixed list of
# ready-fd batches, then raises a sentinel the loop has no handler for so the
# driver regains control. Nothing here re-implements the daemon; it only feeds
# main_loop scripted readiness and records what it did.
# ---------------------------------------------------------------------------


class _MainLoopStop(Exception):
    """
    Raised by the scripted epoll once its poll script is spent, to break
    main_loop's ``while True`` and hand control back to the driver. main_loop
    has no handler for it, so it propagates cleanly; the driver catches it.
    """


class _ScriptedEpoll:
    """
    A select.epoll stand-in for driving main_loop deterministically. poll()
    returns the next scripted batch of ready fds (as (fd, event) pairs, the
    shape main_loop reads), then raises _MainLoopStop. register() records every
    fd main_loop asked to watch, so a test can assert a resync re-registered a
    socket. before_poll, if given, runs at the start of each poll so a test can
    mutate the socket list the way the control thread would between iterations.
    """

    def __init__(
        self,
        poll_batches: list[list[int]],
        before_poll: Callable[[int], None] | None = None,
    ) -> None:
        self._batches: list[list[int]] = list(poll_batches)
        self._before_poll: Callable[[int], None] | None = before_poll
        self.registered_fds: list[int] = []
        self.poll_count: int = 0

    def register(self, fd: int, _eventmask: int) -> None:
        """Record a descriptor main_loop registered for readiness."""

        self.registered_fds.append(fd)

    def poll(self, _timeout: Any = None) -> list[tuple[int, int]]:
        """Return the next scripted ready-fd batch, or end the loop."""

        index: int = self.poll_count
        self.poll_count += 1
        if self._before_poll is not None:
            self._before_poll(index)
        if not self._batches:
            raise _MainLoopStop()
        return [(fd, 1) for fd in self._batches.pop(0)]

    def close(self) -> None:
        """Match select.epoll's interface; there is nothing to release."""


class _MainLoopSandbox:
    """
    Isolate the PrivleapdGlobal state main_loop touches -- the socket list and
    the control-to-main notify pipe -- and give it a real, empty pipe, then
    restore everything (and close the pipe) on exit. main_loop registers
    ctm_read_fd and reads ctm_read_pipe, so both must be real for it to run.
    """

    _FIELDS: tuple[str, ...] = (
        'socket_list',
        'ctm_read_fd',
        'ctm_write_fd',
        'ctm_read_pipe',
        'ctm_write_pipe',
    )

    def __init__(self, pld: ModuleType) -> None:
        self.pld: ModuleType = pld
        self.saved: dict[str, Any] = {}
        self._opened: list[Any] = []

    def __enter__(self) -> '_MainLoopSandbox':
        glob: Any = self.pld.PrivleapdGlobal
        for name in self._FIELDS:
            self.saved[name] = getattr(glob, name)
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        glob.socket_list = []
        glob.ctm_read_fd = read_fd
        glob.ctm_write_fd = write_fd
        glob.ctm_read_pipe = os.fdopen(read_fd, 'rb', buffering=0)
        glob.ctm_write_pipe = os.fdopen(write_fd, 'wb', buffering=0)
        self._opened = [glob.ctm_read_pipe, glob.ctm_write_pipe]
        return self

    def __exit__(self, *_exc: Any) -> None:
        for pipe in self._opened:
            if not pipe.closed:
                pipe.close()
        glob: Any = self.pld.PrivleapdGlobal
        for name, value in self.saved.items():
            setattr(glob, name, value)


def _run_main_loop(
    pld: ModuleType,
    poll_batches: list[list[int]],
    notifier: _RecordingNotifier,
    before_poll: Callable[[int], None] | None = None,
) -> _ScriptedEpoll:
    """
    Run the REAL privleapd.main_loop for the scripted iterations behind a fake
    epoll and a recording sd-notify, restoring both afterward. Returns the
    scripted epoll so a test can inspect what main_loop registered and polled.
    A SystemExit main_loop raises (the lost-socket check) propagates to the
    caller; the loop-ending _MainLoopStop does not.
    """

    scripted: _ScriptedEpoll = _ScriptedEpoll(poll_batches, before_poll)
    saved_epoll: Any = pld.select.epoll
    saved_notifier: Any = pld.PrivleapdGlobal.sdnotify_object
    pld.select.epoll = lambda: scripted
    pld.PrivleapdGlobal.sdnotify_object = notifier
    try:
        pld.main_loop()
    except _MainLoopStop:
        pass
    finally:
        pld.select.epoll = saved_epoll
        pld.PrivleapdGlobal.sdnotify_object = saved_notifier
    return scripted


# ---------------------------------------------------------------------------
# Main thread liveness
# ---------------------------------------------------------------------------


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


def test_main_loop_exits_when_it_loses_track_of_a_socket(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A ready fd that matches no socket in the socket list ends the daemon.

    main_loop dispatches each ready fd by finding its PrivleapdSocketInfo. A
    ready fd it cannot account for means its view of the socket list has
    diverged from the kernel's, which it must never paper over: it logs and
    exits so the divergence is loud and observable rather than a silent
    mis-dispatch. The daemon source marks this check as one AI agents must not
    remove, so it is exercised here directly.
    """

    print('== a ready fd with no known socket ends the daemon ==')
    _ = pl
    with _MainLoopSandbox(pld):
        notifier: _RecordingNotifier = _RecordingNotifier()
        ## A ready fd that is neither the connection-change pipe nor any known
        ## socket (the socket list is empty): the "lost track of a socket"
        ## condition exactly.
        stray_fd: int = pld.PrivleapdGlobal.ctm_read_fd + 4321
        finished: bool
        exc: BaseException | None
        finished, _r, exc = call_with_deadline(
            lambda: _run_main_loop(pld, [[stray_fd]], notifier)
        )
        results.check('main_loop returned rather than hanging', finished)
        results.check(
            'the lost-socket check raised SystemExit',
            isinstance(exc, SystemExit),
        )
        results.expect_eq(
            'the daemon exits with status 1 on a lost socket',
            exc.code if isinstance(exc, SystemExit) else exc,
            1,
        )


def test_main_loop_resyncs_on_a_connection_change_before_dispatch(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A connection-change wakeup re-syncs the socket list and skips dispatch for
    that iteration.

    When the control thread adds or removes a socket it wakes main_loop through
    the ctm pipe. main_loop must resync before acting on any other ready fd that
    iteration -- otherwise it could act on a socket its view is momentarily out
    of date about. So when the ctm fd is ready, main_loop drains it, flags a
    resync and continues WITHOUT running the dispatch loop; the socket added
    during the change is only registered on the next iteration's resync.
    """

    print('== a connection change re-syncs before dispatching ==')
    with StateDirSandbox(pl), _MainLoopSandbox(pld):
        control_socket: Any = pl.PrivleapSocket(pl.PrivleapSocketType.CONTROL)
        ctrl_info: Any = make_socket_info(pld, control_socket)
        pld.PrivleapdGlobal.socket_list = [ctrl_info]
        ctrl_fd: int = control_socket.backend_socket.fileno()
        ctm_fd: int = pld.PrivleapdGlobal.ctm_read_fd

        ## A second socket the control thread adds mid-run; main_loop learns of
        ## it only by re-syncing after the ctm wakeup.
        added_socket: Any = pl.PrivleapSocket(
            pl.PrivleapSocketType.COMMUNICATION, current_username()
        )
        added_info: Any = make_socket_info(pld, added_socket)
        added_fd: int = added_socket.backend_socket.fileno()

        dispatched: list[str] = []
        saved_control: Any = pld.handle_control_socket_conn
        saved_comm: Any = pld.handle_comm_socket_conn
        pld.handle_control_socket_conn = (  # type: ignore[attr-defined]
            lambda _s: dispatched.append('control')
        )
        pld.handle_comm_socket_conn = (  # type: ignore[attr-defined]
            lambda _s: dispatched.append('comm')
        )

        def add_socket(poll_index: int) -> None:
            if poll_index == 0:
                pld.PrivleapdGlobal.socket_list = [ctrl_info, added_info]

        notifier: _RecordingNotifier = _RecordingNotifier()
        try:
            ## Batch 1 carries the connection-change fd AND a known control fd:
            ## main_loop must take the ctm path and NOT dispatch the control fd.
            finished: bool
            scripted: Any
            finished, scripted, exc = call_with_deadline(
                lambda: _run_main_loop(
                    pld,
                    [[ctm_fd, ctrl_fd], []],
                    notifier,
                    before_poll=add_socket,
                )
            )
            results.check('main_loop iterated without hanging', finished)
            results.check(
                'main_loop raised no unexpected exception', exc is None
            )
            results.expect_eq(
                'nothing was dispatched on the connection-change iteration',
                dispatched,
                [],
            )
            results.check(
                'the socket added during the change was registered on resync',
                scripted is not None and added_fd in scripted.registered_fds,
            )
        finally:
            pld.handle_control_socket_conn = (  # type: ignore[attr-defined]
                saved_control
            )
            pld.handle_comm_socket_conn = (  # type: ignore[attr-defined]
                saved_comm
            )
            close_socket_info(ctrl_info)
            close_socket_info(added_info)
            control_socket.close()
            added_socket.close()


def test_main_loop_pings_the_watchdog_every_iteration(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    The systemd watchdog is pinged once per loop iteration, unconditionally.

    main_loop notifies WATCHDOG=1 right after every epoll poll, before it looks
    at what (if anything) was ready. An idle iteration with no ready socket must
    still ping, so a quiet daemon is never mistaken for a hung one; the ping is
    never withheld for any reason.
    """

    print('== the watchdog is pinged every iteration, even when idle ==')
    _ = pl
    with _MainLoopSandbox(pld):
        notifier: _RecordingNotifier = _RecordingNotifier()
        ## Three idle polls: no ready fds at all, so nothing is dispatched and
        ## the only thing each iteration does is poll and ping.
        finished: bool
        finished, _r, _e = call_with_deadline(
            lambda: _run_main_loop(pld, [[], [], []], notifier)
        )
        results.check('main_loop iterated without hanging', finished)
        results.expect_eq(
            'one watchdog ping per iteration, all idle',
            notifier.messages,
            ['WATCHDOG=1', 'WATCHDOG=1', 'WATCHDOG=1'],
        )


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
        self.user_uid: int = pwd.getpwnam(user).pw_uid
        self.sandbox: StateDirSandbox = StateDirSandbox(pl)

    def start(self) -> 'InProcessDaemon':
        """Bring the sandboxed daemon up. Never torn down again."""

        pld: ModuleType = self.pld
        self.sandbox.activate()
        pld.PrivleapdGlobal.socket_list = []
        pld.PrivleapdGlobal.allowed_uid_list = [self.user_uid]
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
    user_uid: int = pwd.getpwnam(user).pw_uid
    daemon: InProcessDaemon = get_in_process_daemon(pl, pld, user)
    created: str | None = daemon.control_request(
        pl.PrivleapControlClientCreateMsg(user)
    )
    results.expect_eq('the comm socket was created', created, 'OK')
    results.check(
        'the daemon answers on a freshly created socket',
        daemon.comm_socket_answers(),
    )
    socket_path = pl.Path(pl.PrivleapCommon.comm_dir, str(user_uid))

    deaf_cycle: int | None = None
    for cycle in range(RECREATE_CYCLES):
        ## Drive the destroy and the create from one thread with nothing
        ## in between, the way the control thread drives a reload.
        def recreate() -> None:
            index: int = _socket_index(pld, user_uid)
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


def _socket_index(pld: ModuleType, user_uid: int) -> int:
    """Index of an account's comm socket in the daemon's socket list."""

    for index, sock_info in enumerate(pld.PrivleapdGlobal.socket_list):
        if sock_info.listen_socket.user_uid == user_uid:
            return index
    raise LookupError(f"no comm socket for UID '{user_uid}'")


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

        pld.auth_signal_request = slow_failing_auth  # type: ignore[attr-defined]
        pld.send_msg_safe = lambda *_a, **_k: True  # type: ignore[attr-defined]
        started: float = time.monotonic()
        invoke()
        return time.monotonic() - started
    finally:
        pld.auth_signal_request = saved_auth  # type: ignore[attr-defined]
        pld.send_msg_safe = saved_send  # type: ignore[attr-defined]


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
    run_test(results, test_stale_ready_event_does_not_hang_daemon, pl, pld)
    run_test(results, test_early_terminate_keeps_shared_term_notify_open, pld)
    run_test(results, test_action_output_pump_is_not_a_busy_loop, pld)
    run_test(results, test_auth_failure_reply_is_constant_time, pld)
    run_test(results, test_access_check_reply_is_constant_time, pld)
    ## The main_loop driver patches select.epoll and the sd-notify object
    ## globally, so it must run before the live in-process daemon threads below
    ## start their own real main_loop.
    run_test(
        results,
        test_main_loop_exits_when_it_loses_track_of_a_socket,
        pl,
        pld,
    )
    run_test(
        results,
        test_main_loop_resyncs_on_a_connection_change_before_dispatch,
        pl,
        pld,
    )
    run_test(
        results,
        test_main_loop_pings_the_watchdog_every_iteration,
        pl,
        pld,
    )
    run_test(results, test_live_daemon_answers_after_socket_recreate, pl, pld)
    ## Last: it starts the unstoppable in-process daemon threads (via the
    ## recreate test's shared daemon) and probes them while serving.
    run_test(results, test_live_daemon_pings_watchdog_while_serving, pl, pld)

    print('')
    return results.report('daemon liveness test')


if __name__ == '__main__':
    sys.exit(main())
