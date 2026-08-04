#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
In-process liveness regression tests for the privleap daemon internals.

The parser and authorizer fuzzers cover what an unprivileged client can send.
This suite covers the parts of privleapd that no client message reaches
directly but that decide whether the daemon stays alive and answerable: the
systemd watchdog path, the epoll registration bookkeeping, the socket list
synchronisation between the main and control threads, and the action output
pump.

Every test here is a regression test for a specific defect that made
privleapd stop answering, stop pinging its watchdog, or leak a timing
side channel. They are written to fail against the code as it was before the
fix, not merely to exercise the fixed code, so that a revert is caught.

Runs without root: the state directory is redirected into a temporary
directory and the ownership calls only root may make are stubbed.
"""

import argparse
import errno
import os
import select
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
## indefinite block the unfixed code would take.
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
        except BaseException as exc:  # pylint: disable=broad-exception-caught
            outcome['exception'] = exc

    thread: threading.Thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join(budget_s)
    if thread.is_alive():
        return False, None, None
    return True, outcome.get('result'), outcome.get('exception')


def fill_datagram_socket(sock: socket.socket) -> bool:
    """
    Write to a connected datagram socket until its peer's receive buffer is
    full. Returns True once the next send would block. Reproduces systemd
    falling behind on its notification socket.
    """

    sock.setblocking(False)
    payload: bytes = b'X' * 512
    for _ in range(200000):
        try:
            sock.send(payload)
        except BlockingIOError:
            return True
        except OSError as exc:
            if exc.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EMSGSIZE):
                return True
            raise
    return False


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
# Main thread liveness
# ---------------------------------------------------------------------------


def test_listener_accept_is_bounded(results: Results, pl: ModuleType) -> None:
    """
    A listening socket with nothing pending must not park its caller.

    privleapd accepts on the main thread, driven by an epoll readiness event.
    That event can be stale by the time it is acted on (the socket may have
    been destroyed and its descriptor number handed to a new socket in the
    meantime), in which case accept() finds nothing waiting. With a blocking
    listener the main thread parked there forever, stopped pinging the
    watchdog, and systemd killed the daemon with nothing in the log.
    """

    print('== listening socket accept() is bounded ==')
    with StateDirSandbox(pl):
        listener: Any = pl.PrivleapSocket(pl.PrivleapSocketType.CONTROL)
        try:
            ## Ordered so that no earlier check leaves a thread parked in
            ## accept() on this listener: a parked accept would take the late
            ## client below and the last check would hang on a correct daemon.

            ## The bound must stay OPT-IN. A caller that has just started a
            ## client and is now waiting to serve it -- which is how the
            ## upstream test suite drives its fake servers -- needs the accept
            ## to wait. Making the bound the default broke dozens of those
            ## tests while every other suite here stayed green.
            def connect_later() -> None:
                time.sleep(0.5)
                late: socket.socket = socket.socket(socket.AF_UNIX)
                late.connect(str(pl.PrivleapCommon.control_path))
                _KEEPALIVE.append(late)

            threading.Thread(target=connect_later, daemon=True).start()
            finished, session, exception = call_with_deadline(
                listener.get_session, budget_s=10.0
            )
            results.check(
                'an ordinary accept serves a client that arrives later',
                finished and session is not None and exception is None,
            )
            results.expect_eq(
                'the listening socket is left blocking',
                listener.backend_socket.gettimeout(),
                None,
            )

            finished, _result, exception = call_with_deadline(
                lambda: listener.get_session(bounded=True)
            )
            results.check(
                'a bounded accept on an idle listener returns instead of '
                'blocking',
                finished,
            )
            results.check(
                'a bounded accept on an idle listener raises TimeoutError',
                isinstance(exception, TimeoutError),
            )
            results.expect_eq(
                'a bounded accept restores the socket it borrowed',
                listener.backend_socket.gettimeout(),
                None,
            )

            ## Last: this one leaves a thread parked in accept() for good.
            finished, _result, _exception = call_with_deadline(
                listener.get_session, budget_s=2.0
            )
            results.check(
                'an ordinary accept waits rather than giving up', not finished
            )
        finally:
            listener.close()


def test_stale_ready_event_does_not_hang_daemon(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    The main loop's connection handlers must survive a stale readiness event.

    This is the caller-side half of the bounded-accept fix: given a socket
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


# pylint: disable=too-many-locals
# Rationale:
#   too-many-locals: reproducing descriptor reuse needs both sockets, both
#     descriptor numbers, the epoll set, the registration map, the dispatch
#     map and a client, all at once.
def test_accept_failure_does_not_spin(
    results: Results, pld: ModuleType
) -> None:
    """
    An accept that fails for lack of resources must not turn the main loop
    into a spin.

    A connection that could not be accepted stays in the kernel's backlog, so
    the listening socket stays readable and the same event comes straight
    back. Without a pause the loop runs flat out: busy enough that its
    heartbeat keeps advancing and the watchdog keeps telling systemd the
    daemon is healthy, while it answers nobody. Any client can cause this by
    holding connections open until the descriptor limit is reached.
    """

    print('== an accept that ran out of descriptors does not spin ==')
    saved_backoff: float = pld.PrivleapdGlobal.accept_backoff_seconds
    saved_until: float = pld.PrivleapdGlobal.accept_backoff_until
    try:
        pld.PrivleapdGlobal.accept_backoff_seconds = 0.3

        ## The pause is SCHEDULED here, not taken here. This runs with
        ## socket_list_lock held, so sleeping would block the control thread
        ## for the whole backoff and stall leapctl create and destroy along
        ## with it -- turning a descriptor shortage into a control outage.
        pld.PrivleapdGlobal.accept_backoff_until = 0.0
        started: float = time.monotonic()
        pld.report_accept_failure(
            OSError(errno.EMFILE, 'Too many open files'), 'unit probe'
        )
        exhausted_elapsed: float = time.monotonic() - started
        results.check(
            f"running out of descriptors does not wait under the lock "
            f"({exhausted_elapsed:.2f}s)",
            exhausted_elapsed < 0.1,
        )
        results.check(
            'running out of descriptors schedules a pause',
            pld.PrivleapdGlobal.accept_backoff_until - time.monotonic()
            >= 0.25,
        )

        ## An ordinary failure -- a client that hung up -- is not a resource
        ## problem and must not slow the daemon down for every other caller.
        pld.PrivleapdGlobal.accept_backoff_until = 0.0
        pld.report_accept_failure(
            ConnectionAbortedError('client went away'), 'unit probe'
        )
        results.expect_eq(
            'an ordinary accept failure schedules no pause',
            pld.PrivleapdGlobal.accept_backoff_until,
            0.0,
        )
    finally:
        pld.PrivleapdGlobal.accept_backoff_seconds = saved_backoff
        pld.PrivleapdGlobal.accept_backoff_until = saved_until


def test_reused_descriptor_is_registered(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A socket that reuses a just-closed descriptor number must still be watched.

    The kernel hands the descriptor number of a closed socket straight back to
    the next socket opened. The old bookkeeping tracked epoll registrations by
    descriptor number, so a destroy immediately followed by a create (what a
    reload, or a leapctl destroy then create, does) looked like no change at
    all and the new socket was never registered. Connections to it were then
    never accepted, for the remaining lifetime of the daemon.
    """

    print('== a reused descriptor number is registered ==')
    user: str = current_username()
    with StateDirSandbox(pl):
        saved_list: list[Any] = pld.PrivleapdGlobal.socket_list
        pld.PrivleapdGlobal.socket_list = []
        epoll_obj: select.epoll = select.epoll()
        registered: dict[Any, int] = {}
        socket_path: Any = pl.Path(pl.PrivleapCommon.comm_dir, user)
        try:
            first_socket: Any = pl.PrivleapSocket(
                pl.PrivleapSocketType.COMMUNICATION, user
            )
            pld.socket_list_add(first_socket)
            first_fd: int = first_socket.backend_socket.fileno()
            pld.refresh_epoll_registrations(epoll_obj, registered)

            ## Destroy and immediately recreate, exactly as a reload does.
            close_socket_info(pld.PrivleapdGlobal.socket_list.pop(0))
            first_socket.close()
            socket_path.unlink()
            second_socket: Any = pl.PrivleapSocket(
                pl.PrivleapSocketType.COMMUNICATION, user
            )
            pld.socket_list_add(second_socket)
            second_fd: int = second_socket.backend_socket.fileno()
            if not results.check(
                'the new socket reused the closed descriptor number '
                '(precondition)',
                second_fd == first_fd,
            ):
                ## Without reuse the check below exercises nothing: it would
                ## pass on the very code this test exists to catch.
                close_socket_info(pld.PrivleapdGlobal.socket_list.pop(0))
                second_socket.close()
                return

            fd_map: dict[int, Any]
            retry_needed: bool
            fd_map, retry_needed = pld.refresh_epoll_registrations(
                epoll_obj, registered
            )
            results.expect_eq(
                'no registration was left to retry', retry_needed, False
            )
            results.check(
                'the recreated socket is in the dispatch map',
                fd_map.get(second_fd) is not None,
            )

            client: socket.socket = socket.socket(socket.AF_UNIX)
            client.connect(str(socket_path))
            try:
                ready: list[int] = [x[0] for x in epoll_obj.poll(2.0)]
                results.check(
                    'epoll reports a connection to the recreated socket',
                    second_fd in ready,
                )
            finally:
                client.close()
            close_socket_info(pld.PrivleapdGlobal.socket_list.pop(0))
            second_socket.close()
        finally:
            epoll_obj.close()
            pld.PrivleapdGlobal.socket_list = saved_list


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


def test_control_thread_survives_a_failed_request(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    One failed control request must not cost the daemon its control socket.

    The control thread ran its request handling with nothing catching an
    unexpected exception, and nothing restarts that thread. A single failure
    ended it for good: privleapd carried on accepting comm connections and
    carried on telling systemd it was healthy, while every socket create,
    destroy and config reload from then on queued up unanswered. That is the
    worst shape this class of bug takes, because every external signal still
    says the daemon is fine.
    """

    print('== the control thread survives a failed request ==')
    user: str = current_username()
    daemon: InProcessDaemon = get_in_process_daemon(pl, pld, user)
    saved_handler: Any = pld.handle_control_session
    try:
        results.check(
            'the control socket answers before the failure',
            daemon.control_request(pl.PrivleapControlClientCreateMsg(user))
            is not None,
        )

        def poisoned_handler(control_session: Any) -> None:
            ## Restore immediately so exactly one request fails, then hang up
            ## on the client and fail the way an unexpected bug would.
            pld.handle_control_session = saved_handler
            try:
                control_session.close_session()
            except OSError:
                pass
            raise RuntimeError('unit-injected control handler failure')

        pld.handle_control_session = poisoned_handler
        daemon.control_request(pl.PrivleapControlClientDestroyMsg(user))

        results.check(
            'the control socket still answers after the failure',
            daemon.control_request(pl.PrivleapControlClientCreateMsg(user))
            is not None,
        )
        results.check(
            'the comm socket still answers after the failure',
            daemon.comm_socket_answers(),
        )
    finally:
        pld.handle_control_session = saved_handler


def test_live_daemon_keeps_heartbeat_while_serving(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    The main loop must keep proving it is alive while it is serving requests,
    not only while it is idle. A heartbeat that only advances between
    connections is exactly the coupling that let a burst of connection work
    overrun the watchdog deadline.
    """

    print('== the main loop keeps its heartbeat while serving requests ==')
    user: str = current_username()
    daemon: InProcessDaemon = get_in_process_daemon(pl, pld, user)
    daemon.control_request(pl.PrivleapControlClientCreateMsg(user))
    ## Measured against the wall clock, not against the previous reading. A
    ## heartbeat that stops moving keeps its last value, so comparing
    ## successive readings would report a gap of zero and pass while the main
    ## loop was in fact frozen.
    worst_staleness: float = 0.0
    advanced: bool = False
    first_seen: float = float(pld.PrivleapdGlobal.main_loop_heartbeat)
    deadline: float = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        daemon.comm_socket_answers(timeout_s=5.0)
        now_seen: float = float(pld.PrivleapdGlobal.main_loop_heartbeat)
        worst_staleness = max(worst_staleness, time.monotonic() - now_seen)
        if now_seen > first_seen:
            advanced = True
    results.check('the heartbeat advanced at all while serving', advanced)
    results.check(
        f"the heartbeat never went stale while serving (worst "
        f"{worst_staleness:.2f}s)",
        0 <= worst_staleness < 5.0,
    )


def test_destroyed_socket_is_unregistered(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A socket removed from the list must leave the dispatch map, so that a
    readiness event for it is never turned into an accept on a closed socket.
    """

    print('== a destroyed socket leaves the dispatch map ==')
    user: str = current_username()
    with StateDirSandbox(pl):
        saved_list: list[Any] = pld.PrivleapdGlobal.socket_list
        pld.PrivleapdGlobal.socket_list = []
        epoll_obj: select.epoll = select.epoll()
        registered: dict[Any, int] = {}
        try:
            comm_socket: Any = pl.PrivleapSocket(
                pl.PrivleapSocketType.COMMUNICATION, user
            )
            pld.socket_list_add(comm_socket)
            comm_fd: int = comm_socket.backend_socket.fileno()
            fd_map: dict[int, Any]
            fd_map, _retry = pld.refresh_epoll_registrations(
                epoll_obj, registered
            )
            results.check(
                'the live socket is in the dispatch map',
                fd_map.get(comm_fd) is not None,
            )
            close_socket_info(pld.PrivleapdGlobal.socket_list.pop(0))
            comm_socket.close()
            fd_map, _retry = pld.refresh_epoll_registrations(
                epoll_obj, registered
            )
            results.expect_eq(
                'the destroyed socket is gone from the dispatch map',
                fd_map.get(comm_fd),
                None,
            )
            results.expect_eq(
                'the destroyed socket is gone from the registration map',
                len(registered),
                0,
            )
        finally:
            epoll_obj.close()
            pld.PrivleapdGlobal.socket_list = saved_list


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------


def test_watchdog_ping_cadence(results: Results, pld: ModuleType) -> None:
    """
    The watchdog ping must leave headroom under the deadline.

    Pinging once per main loop iteration at half the deadline left no margin:
    any single slow iteration (an account database lookup, a thread start, a
    descheduled process on a loaded host) overran the deadline and systemd
    restarted a perfectly healthy daemon. The ping interval must be a
    comfortable fraction of the deadline, and the main loop must not block for
    longer than that fraction.
    """

    print('== watchdog ping cadence leaves headroom ==')
    saved: dict[str, Any] = _save_watchdog_state(pld)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        pld.PrivleapdGlobal.sdnotify_object.socket = left
        os.environ['WATCHDOG_USEC'] = '10000000'
        ## Poisoned first: left at their real defaults these would already sit
        ## inside the bounds asserted below, so a setup_sd_notify that did
        ## nothing at all would pass every check here.
        pld.PrivleapdGlobal.watchdog_ping_interval = -1.0
        pld.PrivleapdGlobal.watchdog_heartbeat_timeout = -1.0
        ## Poisoned HIGH, not low: the daemon only ever lowers this one, so a
        ## low sentinel would survive untouched and read as a pass.
        pld.PrivleapdGlobal.main_loop_poll_timeout = 999.0
        pld.setup_sd_notify()

        deadline_s: float = 10.0
        interval: float = pld.PrivleapdGlobal.watchdog_ping_interval
        results.check(
            'the ping interval is at most a quarter of the deadline',
            0 < interval <= deadline_s / 4,
        )
        results.check(
            'a stale main loop is detected well inside the deadline',
            0 < pld.PrivleapdGlobal.watchdog_heartbeat_timeout < deadline_s,
        )
        results.check(
            'the main loop never blocks for longer than a ping interval',
            0 < pld.PrivleapdGlobal.main_loop_poll_timeout <= interval,
        )
        results.expect_eq(
            'the notification socket is non-blocking', left.gettimeout(), 0.0
        )
    finally:
        left.close()
        right.close()
        _restore_watchdog_state(pld, saved)


def test_watchdog_disabled_without_systemd(
    results: Results, pld: ModuleType
) -> None:
    """
    With no watchdog configured, no ping thread must be started and the main
    loop must keep its ordinary poll timeout.
    """

    print('== no watchdog is configured when systemd asks for none ==')
    saved: dict[str, Any] = _save_watchdog_state(pld)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        pld.PrivleapdGlobal.sdnotify_object.socket = left
        pld.PrivleapdGlobal.watchdog_ping_interval = 0.0
        for value, label in (
            (None, 'unset'),
            ('0', 'zero'),
            ('not-a-number', 'unparseable'),
        ):
            if value is None:
                os.environ.pop('WATCHDOG_USEC', None)
            else:
                os.environ['WATCHDOG_USEC'] = value
            ## Poisoned to a value that is neither the expected result nor a
            ## plausible default, so "left untouched" cannot masquerade as
            ## "correctly decided not to run".
            pld.PrivleapdGlobal.watchdog_ping_interval = -1.0
            pld.setup_sd_notify()
            results.expect_eq(
                f"a {label} WATCHDOG_USEC leaves the ping interval unset",
                pld.PrivleapdGlobal.watchdog_ping_interval,
                -1.0,
            )
    finally:
        left.close()
        right.close()
        _restore_watchdog_state(pld, saved)


def test_watchdog_ping_never_blocks(results: Results, pld: ModuleType) -> None:
    """
    A ping must not block when systemd stops draining its notification socket.

    sdnotify sends on a blocking datagram socket, so a full notification
    socket (which is what a host under memory pressure produces) parks the
    sender. Parking the thread whose whole job is to prove the process is
    alive turns a transient stall into a watchdog kill.
    """

    print('== a watchdog ping does not block on a full notify socket ==')
    saved: dict[str, Any] = _save_watchdog_state(pld)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        right.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2048)
        pld.PrivleapdGlobal.sdnotify_object.socket = left
        pld.setup_sd_notify()
        ## Whatever setup_sd_notify decided is the thing under test, so it is
        ## captured before filling (which needs non-blocking mode of its own)
        ## and put back afterwards. Filling without restoring would leave the
        ## socket non-blocking regardless, and this test would then pass even
        ## for a daemon that never set it.
        mode_under_test: float | None = left.gettimeout()
        if not results.check(
            'the notification socket could be filled (precondition)',
            fill_datagram_socket(left),
        ):
            return
        left.settimeout(mode_under_test)
        results.expect_eq(
            'the socket is still in the mode the daemon chose',
            left.gettimeout(),
            mode_under_test,
        )
        finished, _r, exception = call_with_deadline(
            lambda: pld.sd_notify('WATCHDOG=1')
        )
        results.check('sd_notify returns on a full socket', finished)
        results.check(
            'sd_notify swallows the would-block condition', exception is None
        )
    finally:
        left.close()
        right.close()
        _restore_watchdog_state(pld, saved)


def test_startup_notification_is_not_dropped(
    results: Results, pld: ModuleType
) -> None:
    """
    A notification systemd is waiting on must not be dropped.

    Making the notification socket non-blocking is what stops a busy systemd
    from parking the watchdog thread, but it applies to every send. READY=1 is
    not optional: the unit is Type=notify, so systemd waits for exactly that
    message and fails the start outright if it never arrives. A ping may be
    dropped; a readiness notification may not.
    """

    print('== a notification systemd waits for is not dropped ==')
    saved: dict[str, Any] = _save_watchdog_state(pld)
    saved_retry: float = pld.PrivleapdGlobal.sd_notify_retry_seconds
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        right.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2048)
        pld.PrivleapdGlobal.sdnotify_object.socket = left
        pld.setup_sd_notify()
        mode_under_test: float | None = left.gettimeout()
        if not results.check(
            'the notification socket could be filled (precondition)',
            fill_datagram_socket(left),
        ):
            return
        left.settimeout(mode_under_test)

        ## Drain from the far end shortly after the send starts, standing in
        ## for a systemd that was briefly behind and then caught up.
        def drain_soon() -> None:
            time.sleep(0.2)
            _drain_datagrams(right)

        right.setblocking(False)
        threading.Thread(target=drain_soon, daemon=True).start()
        pld.PrivleapdGlobal.sd_notify_retry_seconds = 5.0
        finished, _r, exception = call_with_deadline(
            lambda: pld.sd_notify('READY=1', must_arrive=True)
        )
        results.check('sending READY=1 returns', finished)
        results.check('sending READY=1 does not raise', exception is None)
        results.check(
            'READY=1 reached systemd rather than being dropped',
            _drain_datagrams(right) > 0,
        )
    finally:
        left.close()
        right.close()
        pld.PrivleapdGlobal.sd_notify_retry_seconds = saved_retry
        _restore_watchdog_state(pld, saved)


def test_watchdog_without_notify_socket(
    results: Results, pld: ModuleType
) -> None:
    """
    Outside systemd there is no notification socket at all. Neither setup nor
    a ping may raise.
    """

    print('== the watchdog path is inert without a notification socket ==')
    saved: dict[str, Any] = _save_watchdog_state(pld)
    try:
        pld.PrivleapdGlobal.sdnotify_object.socket = None
        finished, _r, exception = call_with_deadline(pld.setup_sd_notify)
        results.check('setup_sd_notify returns', finished)
        results.check('setup_sd_notify does not raise', exception is None)
        finished, _r, exception = call_with_deadline(
            lambda: pld.sd_notify('READY=1')
        )
        results.check('sd_notify returns', finished)
        results.check('sd_notify does not raise', exception is None)
    finally:
        _restore_watchdog_state(pld, saved)


def test_watchdog_stops_pinging_when_wedged(
    results: Results, pld: ModuleType
) -> None:
    """
    Decoupling the ping from the main loop must not defeat the watchdog.

    A ping thread that pings unconditionally would tell systemd a wedged
    daemon is healthy. Pings must stop once the main loop's heartbeat goes
    stale, which is what still lets systemd restart a genuinely stuck daemon.
    """

    print('== the watchdog stops pinging a wedged main loop ==')
    saved: dict[str, Any] = _save_watchdog_state(pld)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    ## The daemon offers no way to stop its watchdog thread, so the socket
    ## pair it sends to has to outlive this test.
    _KEEPALIVE.extend([left, right])
    try:
        left.setblocking(False)
        right.setblocking(False)
        pld.PrivleapdGlobal.sdnotify_object.socket = left
        pld.PrivleapdGlobal.watchdog_ping_interval = 0.05
        pld.PrivleapdGlobal.watchdog_heartbeat_timeout = 0.5
        pld.PrivleapdGlobal.main_loop_heartbeat = time.monotonic()

        threading.Thread(target=pld.watchdog_loop, daemon=True).start()

        healthy_pings: int = 0
        deadline: float = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            pld.PrivleapdGlobal.main_loop_heartbeat = time.monotonic()
            time.sleep(0.05)
            healthy_pings += _drain_datagrams(right)
        results.check('a live main loop is pinged', healthy_pings > 0)

        ## Stop refreshing the heartbeat: the daemon now looks wedged.
        pld.PrivleapdGlobal.main_loop_heartbeat = time.monotonic() - 60
        time.sleep(0.3)
        _drain_datagrams(right)
        time.sleep(0.4)
        results.expect_eq(
            'a wedged main loop is not pinged', _drain_datagrams(right), 0
        )
    finally:
        ## Park the thread rather than leaving it spinning on a zero interval.
        pld.PrivleapdGlobal.watchdog_ping_interval = 3600.0
        pld.PrivleapdGlobal.main_loop_heartbeat = time.monotonic()
        saved['interval'] = 3600.0
        _restore_watchdog_state(pld, saved)


def _drain_datagrams(sock: socket.socket) -> int:
    """Count and discard everything queued on a non-blocking datagram socket."""

    count: int = 0
    while True:
        try:
            sock.recv(256)
            count += 1
        except BlockingIOError:
            return count


def _save_watchdog_state(pld: ModuleType) -> dict[str, Any]:
    return {
        'interval': pld.PrivleapdGlobal.watchdog_ping_interval,
        'timeout': pld.PrivleapdGlobal.watchdog_heartbeat_timeout,
        'poll': pld.PrivleapdGlobal.main_loop_poll_timeout,
        'heartbeat': pld.PrivleapdGlobal.main_loop_heartbeat,
        'socket': pld.PrivleapdGlobal.sdnotify_object.socket,
        'env': os.environ.get('WATCHDOG_USEC'),
    }


def _restore_watchdog_state(pld: ModuleType, saved: dict[str, Any]) -> None:
    pld.PrivleapdGlobal.sdnotify_object.socket = saved['socket']
    pld.PrivleapdGlobal.watchdog_ping_interval = saved['interval']
    pld.PrivleapdGlobal.watchdog_heartbeat_timeout = saved['timeout']
    pld.PrivleapdGlobal.main_loop_poll_timeout = saved['poll']
    pld.PrivleapdGlobal.main_loop_heartbeat = saved['heartbeat']
    if saved['env'] is None:
        os.environ.pop('WATCHDOG_USEC', None)
    else:
        os.environ['WATCHDOG_USEC'] = saved['env']


# ---------------------------------------------------------------------------
# Comm thread liveness
# ---------------------------------------------------------------------------


def test_notify_pipe_write_never_blocks(
    results: Results, pld: ModuleType
) -> None:
    """
    The control thread writes its wakeup byte while holding socket_list_lock.
    Only the main thread can clear that pipe, and the main thread may itself
    be waiting for the lock, so the write must never block.
    """

    print('== a wakeup pipe write does not block on a full pipe ==')
    read_fd, write_fd = os.pipe()
    os.set_blocking(write_fd, False)
    write_pipe: Any = os.fdopen(write_fd, 'wb', buffering=0)
    ## A full non-blocking pipe reports itself differently depending on how it
    ## is wrapped: a raw write returns None, a buffered one raises. The daemon
    ## must survive both, so both are exercised.
    buffered_pipe: Any = os.fdopen(os.dup(write_fd), 'wb')
    try:
        filled: bool = False
        for _ in range(200000):
            if write_pipe.write(b'\x00') is None:
                filled = True
                break
        if not results.check(
            'the wakeup pipe could be filled (precondition)', filled
        ):
            return
        finished, _r, exception = call_with_deadline(
            lambda: pld.notify_pipe_write(write_pipe)
        )
        results.check(
            'notify_pipe_write returns on a full raw pipe', finished
        )
        results.check(
            'notify_pipe_write swallows a raw would-block', exception is None
        )

        finished, _r, exception = call_with_deadline(
            lambda: pld.notify_pipe_write(buffered_pipe)
        )
        results.check(
            'notify_pipe_write returns on a full buffered pipe', finished
        )
        results.check(
            'notify_pipe_write swallows a buffered would-block',
            exception is None,
        )
    finally:
        ## Discarding the buffered wrapper's unwritten byte, so closing it
        ## cannot raise over a pipe the test is about to drop anyway.
        _discard_buffered(buffered_pipe)
        write_pipe.close()
        os.close(read_fd)


def _discard_buffered(buffered_pipe: Any) -> None:
    """
    Drop a buffered writer without flushing it. Closing normally would retry
    the buffered byte against a pipe that is still full.
    """

    try:
        buffered_pipe.detach().close()
    except Exception:  # nosec B110 # pylint: disable=broad-exception-caught
        ## Nothing to salvage: the pipe is about to be dropped either way.
        pass


def test_termination_notice_reaches_every_thread(
    results: Results, pld: ModuleType
) -> None:
    """
    The termination notice is a sticky broadcast, not a single-reader message.

    Several comm threads can be streaming actions for the same account, all
    epolling the same notification pipe. When one of them noticed termination
    it used to close that pipe, so its siblings never woke and kept running
    their actions to completion. The notice must stay visible to every thread.
    """

    print('== a termination notice reaches every waiting thread ==')
    sock_info: Any = make_socket_info(pld)
    session: FakeSession = FakeSession()
    try:
        sock_info.should_terminate = True
        pld.notify_pipe_write(sock_info.term_notify_write_pipe)

        observed: list[bool] = []
        acted: list[bool] = []
        for _ in range(3):
            epoll_obj: select.epoll = select.epoll()
            epoll_obj.register(sock_info.term_notify_read_fd, select.EPOLLIN)
            try:
                ready: list[int] = [x[0] for x in epoll_obj.poll(1.0)]
                observed.append(sock_info.term_notify_read_fd in ready)
            finally:
                epoll_obj.close()
            ## Whatever a comm thread does on noticing termination must not
            ## make the notice invisible to the next thread.
            acted.append(
                pld.check_early_action_terminate(
                    sock_info, [], session, 'unit-action'
                )
            )
        results.expect_eq(
            'every waiting thread sees the termination notice',
            observed,
            [True, True, True],
        )
        results.expect_eq(
            'every waiting thread acts on the notice', acted, [True, True, True]
        )
        results.check(
            'the notification pipes are still open',
            not sock_info.term_notify_read_pipe.closed
            and not sock_info.term_notify_write_pipe.closed,
        )
    finally:
        session.close_session()
        close_socket_info(sock_info)


def test_finished_stream_is_unregistered(
    results: Results, pld: ModuleType
) -> None:
    """
    A stream at end-of-file must leave the action output pump's epoll set.

    An end-of-file descriptor is permanently ready, so leaving it registered
    turned the pump into a busy loop that burned a core until the other stream
    closed too, starving the main thread of the interpreter lock.
    """

    print('== a finished output stream is unregistered ==')
    read_fd, write_fd = os.pipe()
    stream: Any = os.fdopen(read_fd, 'rb', buffering=0)
    epoll_obj: select.epoll = select.epoll()
    try:
        epoll_obj.register(read_fd, select.EPOLLIN)
        os.close(write_fd)
        results.expect_eq(
            'a stream at end-of-file is reported ready (precondition)',
            [x[0] for x in epoll_obj.poll(1.0)],
            [read_fd],
        )
        results.expect_eq(
            'marking a stream done reports it done',
            pld.mark_stream_done(epoll_obj, stream, False),
            True,
        )
        results.expect_eq(
            'the finished stream no longer wakes the pump',
            [x[0] for x in epoll_obj.poll(0.2)],
            [],
        )
        results.expect_eq(
            'marking an already finished stream is a no-op',
            pld.mark_stream_done(epoll_obj, stream, True),
            True,
        )
    finally:
        epoll_obj.close()
        stream.close()


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
    an unfixed tree a missing helper or a torn-down socket is exactly the
    kind of failure the suite exists to report, and the remaining tests still
    have findings to contribute.
    """

    try:
        test(results, *args)
    except BaseException as exc:  # pylint: disable=broad-exception-caught
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
    run_test(results, test_listener_accept_is_bounded, pl)
    run_test(results, test_stale_ready_event_does_not_hang_daemon, pl, pld)
    run_test(results, test_accept_failure_does_not_spin, pld)
    run_test(results, test_reused_descriptor_is_registered, pl, pld)
    run_test(results, test_destroyed_socket_is_unregistered, pl, pld)
    run_test(results, test_watchdog_ping_cadence, pld)
    run_test(results, test_watchdog_disabled_without_systemd, pld)
    run_test(results, test_watchdog_ping_never_blocks, pld)
    run_test(results, test_startup_notification_is_not_dropped, pld)
    run_test(results, test_watchdog_without_notify_socket, pld)
    run_test(results, test_notify_pipe_write_never_blocks, pld)
    run_test(results, test_termination_notice_reaches_every_thread, pld)
    run_test(results, test_finished_stream_is_unregistered, pld)
    run_test(results, test_action_output_pump_is_not_a_busy_loop, pld)
    run_test(results, test_auth_failure_reply_is_constant_time, pld)
    run_test(results, test_access_check_reply_is_constant_time, pld)
    ## Before the in-process daemon: its main loop refreshes the very
    ## heartbeat this test has to hold stale, so running it afterwards would
    ## be racing the thing under test.
    run_test(results, test_watchdog_stops_pinging_when_wedged, pld)
    run_test(results, test_live_daemon_answers_after_socket_recreate, pl, pld)
    run_test(results, test_control_thread_survives_a_failed_request, pl, pld)
    run_test(results, test_live_daemon_keeps_heartbeat_while_serving, pl, pld)

    print('')
    return results.report('daemon liveness test')


if __name__ == '__main__':
    sys.exit(main())
