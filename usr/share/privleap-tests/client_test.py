#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
In-process tests for the privleap client tools, leapctl and leaprun.

Both tools are pure protocol clients: they parse a command line, open one
socket, exchange messages, print something and pick an exit code. That makes
them testable in process against a scripted stand-in for privleapd, with no
root, no live daemon and no subprocess.

What is being checked is the part a user or a script actually depends on: that
every server reply the protocol allows is understood and mapped to the right
exit code and output, and that a hostile or broken server cannot make a client
hang, crash, or exit zero on failure. An unrecognised reply must be a clean
error, never a traceback.
"""

import argparse
import io
import os
import socket
import sys
import tempfile
import threading
import time
from contextlib import redirect_stderr, redirect_stdout
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
    import_privleap_module,
)


# pylint: disable=too-many-instance-attributes
# Rationale:
#   too-many-instance-attributes: a stand-in server needs its socket, its
#     thread, its stop flag, its scripted behaviour and its record of what it
#     saw; none of them collapse into another.
class ScriptedServer:
    """
    A stand-in privleapd: listens on the sandboxed socket path, accepts one
    connection at a time, reads whatever the client sends, and replies with a
    scripted list of messages.

    Replies are built by a callable rather than fixed, so a test can react to
    what the client actually sent. Everything the server sees is recorded, so
    a test can assert on the request as well as the response.
    """

    def __init__(
        self, pl: ModuleType, socket_path: str, is_control: bool
    ) -> None:
        self.pl: ModuleType = pl
        self.socket_path: str = socket_path
        self.is_control: bool = is_control
        self.received: list[Any] = []
        self.reply_for: Callable[[Any], list[Any]] = lambda _msg: []
        self.read_request: bool = True
        self.read_trailing: bool = False
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop: threading.Event = threading.Event()

    def __enter__(self) -> 'ScriptedServer':
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(self.socket_path)
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(5)
        if self.listener is not None:
            self.listener.close()

    def _serve(self) -> None:
        assert self.listener is not None  # nosec B101 -- test harness invariant
        while not self.stop.is_set():
            try:
                conn, _addr = self.listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                self._handle(conn)
            except Exception:  # nosec B110 # pylint: disable=broad-exception-caught
                ## A client that hangs up mid-exchange is a case under test,
                ## not a failure of the stand-in server, so it is discarded
                ## deliberately rather than reported.
                pass
            finally:
                conn.close()

    def wait_for(self, name: str, timeout_s: float = 5.0) -> bool:
        """
        Wait until a message of the given type has been seen. The client exits
        as soon as it has sent, so a test that looked straight after the run
        would be racing the server thread's read rather than checking it.
        """

        deadline: float = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if any(msg.name == name for msg in list(self.received)):
                return True
            time.sleep(0.05)
        return False

    def _handle(self, conn: socket.socket) -> None:
        session: Any = self.pl.PrivleapSession(
            conn, is_control_session=self.is_control
        )
        request: Any = None
        if self.read_request:
            request = session.get_msg()
            self.received.append(request)
        try:
            for reply in self.reply_for(request):
                session.send_msg(reply)
        except Exception:  # nosec B110 # pylint: disable=broad-exception-caught
            ## The client may already have hung up. That does not change what
            ## it sent us, which is what the trailing drain below records.
            pass
        if self.read_trailing:
            ## Keep reading whatever the client sends after the reply, so a
            ## test can assert on a follow-up message such as TERMINATE. The
            ## server-side read gives up quickly on silence, so this ends as
            ## soon as the client stops talking.
            while True:
                try:
                    self.received.append(session.get_msg())
                except Exception:  # nosec B112 # pylint: disable=broad-exception-caught
                    break


class ClientSandbox:
    """
    Redirects privleap's socket paths into a temporary directory so a client
    under test talks to the scripted server instead of the real daemon.
    """

    def __init__(self, pl: ModuleType) -> None:
        self.pl: ModuleType = pl
        self.tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.saved: dict[str, Any] = {}

    def __enter__(self) -> 'ClientSandbox':
        self.tmpdir = tempfile.TemporaryDirectory(prefix='privleap-client-')
        common: Any = self.pl.PrivleapCommon
        self.saved = {
            'state_dir': common.state_dir,
            'control_path': common.control_path,
            'comm_dir': common.comm_dir,
        }
        common.state_dir = self.pl.Path(self.tmpdir.name, 'privleapd')
        common.control_path = self.pl.Path(common.state_dir, 'control')
        common.comm_dir = self.pl.Path(common.state_dir, 'comm')
        common.comm_dir.mkdir(parents=True)
        return self

    def __exit__(self, *_exc: Any) -> None:
        common: Any = self.pl.PrivleapCommon
        for key, value in self.saved.items():
            setattr(common, key, value)
        if self.tmpdir is not None:
            self.tmpdir.cleanup()
            self.tmpdir = None


# pylint: disable=too-few-public-methods
class ClientRun:
    """The observable result of running a client tool: what it printed and
    what exit code it chose."""

    def __init__(self, exit_code: int, stdout: str, stderr: str) -> None:
        self.exit_code: int = exit_code
        self.stdout: str = stdout
        self.stderr: str = stderr

    def __repr__(self) -> str:
        return (
            f"ClientRun(exit_code={self.exit_code}, "
            f"stdout={self.stdout!r}, stderr={self.stderr!r})"
        )


def _capture_stream() -> tuple[Any, io.BytesIO]:
    """
    A stand-in for sys.stdout or sys.stderr that captures both text writes and
    the binary writes leaprun uses to forward an action's output byte for
    byte. A plain StringIO has no .buffer, so it would not see that output at
    all -- which is exactly the output these tests exist to check.
    """

    raw: io.BytesIO = io.BytesIO()
    return (
        io.TextIOWrapper(raw, encoding='utf-8', write_through=True),
        raw,
    )


def run_client(
    module: ModuleType, argv: list[str], reset: Callable[[], None]
) -> ClientRun:
    """
    Run a client tool's main() in process with a given command line, capturing
    its output and exit code. Every client path ends in sys.exit(), so a
    return without SystemExit is itself a finding and is reported as an
    impossible exit code rather than being silently accepted.
    """

    reset()
    saved_argv: list[str] = sys.argv
    ## Distinct from any real exit code: a client that returns instead of
    ## exiting would otherwise be indistinguishable from one that failed
    ## properly, and every 'this must fail' check below would accept it.
    out_text, out_raw = _capture_stream()
    err_text, err_raw = _capture_stream()
    exit_code: int = -1
    try:
        sys.argv = argv
        with redirect_stdout(out_text), redirect_stderr(err_text):
            try:
                module.main()
            except SystemExit as exc:
                ## sys.exit('message') is a failure exit whose code is the
                ## string; int() would raise and lose the whole case.
                if exc.code is None:
                    exit_code = 0
                elif isinstance(exc.code, int):
                    exit_code = exc.code
                else:
                    exit_code = 1
        out_text.flush()
        err_text.flush()
        stdout: str = out_raw.getvalue().decode('utf-8', errors='replace')
        stderr: str = err_raw.getvalue().decode('utf-8', errors='replace')
    finally:
        sys.argv = saved_argv
        ## Detached so that dropping the wrapper cannot close the buffer that
        ## was just read out of.
        out_text.detach()
        err_text.detach()
    return ClientRun(exit_code, stdout, stderr)


# ---------------------------------------------------------------------------
# leapctl
# ---------------------------------------------------------------------------


def leapctl_cases(pl: ModuleType) -> list[tuple[Any, ...]]:
    """
    Every server reply leapctl's protocol allows, with the exit code and the
    output fragment the caller is entitled to rely on.
    """

    return [
        ('--create', pl.PrivleapControlServerOkMsg(), 0, 'created'),
        (
            '--create',
            pl.PrivleapControlServerExistsMsg(),
            0,
            'already exists',
        ),
        (
            '--create',
            pl.PrivleapControlServerExpectedDisallowedUserMsg(),
            0,
            'as expected',
        ),
        (
            '--create',
            pl.PrivleapControlServerControlErrorMsg(),
            1,
            'encountered an error',
        ),
        (
            '--create',
            pl.PrivleapControlServerDisallowedUserMsg(),
            2,
            'not permitted',
        ),
        ('--destroy', pl.PrivleapControlServerOkMsg(), 0, 'destroyed'),
        (
            '--destroy',
            pl.PrivleapControlServerNouserMsg(),
            0,
            'does not exist',
        ),
        (
            '--destroy',
            pl.PrivleapControlServerPersistentUserMsg(),
            0,
            'persistent',
        ),
        (
            '--destroy',
            pl.PrivleapControlServerControlErrorMsg(),
            1,
            'encountered an error',
        ),
        ('--reload', pl.PrivleapControlServerOkMsg(), 0, 'reload successful'),
        (
            '--reload',
            pl.PrivleapControlServerControlErrorMsg(),
            1,
            'failed to reload',
        ),
        ## A reply that is legal on the wire but wrong for the request must be
        ## a clean error, not a crash and not a success.
        ('--create', pl.PrivleapControlServerNouserMsg(), 1, 'unexpected'),
        ('--destroy', pl.PrivleapControlServerExistsMsg(), 1, 'unexpected'),
        (
            '--reload',
            pl.PrivleapControlServerExistsMsg(),
            1,
            'unexpected',
        ),
    ]


def test_leapctl_replies(
    results: Results, pl: ModuleType, leapctl: ModuleType
) -> None:
    """Each server reply maps to the documented exit code and message."""

    print('== leapctl maps every server reply to an exit code ==')
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl, str(pl.PrivleapCommon.control_path), is_control=True
        ) as server:
            for action, reply, want_code, want_text in leapctl_cases(pl):
                server.reply_for = lambda _msg, reply=reply: [reply]
                argv: list[str] = ['leapctl', action]
                if action != '--reload':
                    argv.append(user)
                run: ClientRun = run_client(
                    leapctl, argv, _reset_leapctl(leapctl)
                )
                label: str = f"leapctl {action} + {reply.name}"
                results.expect_eq(
                    f"{label}: exit code", run.exit_code, want_code
                )
                results.check(
                    f"{label}: mentions {want_text!r}",
                    want_text in (run.stdout + run.stderr).lower()
                    or want_text in run.stdout + run.stderr,
                )


def test_leapctl_argument_handling(
    results: Results, pl: ModuleType, leapctl: ModuleType
) -> None:
    """
    A malformed command line must print usage and fail, never reach the
    daemon, and never exit zero.
    """

    print('== leapctl rejects malformed command lines ==')
    bad_argvs: list[list[str]] = [
        ['leapctl'],
        ['leapctl', '--create', 'someuser', 'extra'],
        ['leapctl', '--bogus', 'someuser'],
        ['leapctl', '--reload', 'someuser'],
    ]
    with ClientSandbox(pl):
        for argv in bad_argvs:
            run: ClientRun = run_client(
                leapctl, argv, _reset_leapctl(leapctl)
            )
            label: str = f"leapctl {' '.join(argv[1:]) or '(no arguments)'}"
            results.expect_eq(f"{label}: exit code", run.exit_code, 1)
            results.check(
                f"{label}: prints usage", 'leapctl <--create' in run.stdout
            )


def test_leapctl_unknown_account(
    results: Results, pl: ModuleType, leapctl: ModuleType
) -> None:
    """
    Creating a socket for an account that does not exist is an error, but
    destroying one is not: a deleted account's socket still has to be
    cleanable.
    """

    print('== leapctl handles an account that does not exist ==')
    missing: str = 'privleap-no-such-account'
    with ClientSandbox(pl):
        run: ClientRun = run_client(
            leapctl, ['leapctl', '--create', missing], _reset_leapctl(leapctl)
        )
        results.expect_eq('create for a missing account fails', run.exit_code, 1)
        results.check(
            'create for a missing account says so',
            'does not exist' in run.stderr,
        )

        server: ScriptedServer
        with ScriptedServer(
            pl, str(pl.PrivleapCommon.control_path), is_control=True
        ) as server:
            server.reply_for = lambda _msg: [pl.PrivleapControlServerOkMsg()]
            run = run_client(
                leapctl,
                ['leapctl', '--destroy', missing],
                _reset_leapctl(leapctl),
            )
            results.expect_eq(
                'destroy for a missing account succeeds', run.exit_code, 0
            )
            results.check(
                'destroy for a missing account reached the daemon',
                len(server.received) == 1,
            )


def test_leapctl_server_failures(
    results: Results, pl: ModuleType, leapctl: ModuleType
) -> None:
    """
    A daemon that is absent, or that hangs up without answering, must produce
    a clean non-zero exit rather than a traceback or a hang.
    """

    print('== leapctl survives a missing or silent daemon ==')
    user: str = current_username()
    with ClientSandbox(pl):
        ## No control socket at all. wait_for_control_socket polls for five
        ## seconds before giving up, which is the documented behaviour.
        run: ClientRun = run_client(
            leapctl, ['leapctl', '--reload'], _reset_leapctl(leapctl)
        )
        results.expect_eq('a missing daemon fails cleanly', run.exit_code, 1)
        results.check(
            'a missing daemon is reported',
            'Could not connect' in run.stderr,
        )

        server: ScriptedServer
        with ScriptedServer(
            pl, str(pl.PrivleapCommon.control_path), is_control=True
        ) as server:
            ## Accept, read the request, then hang up without replying.
            server.reply_for = lambda _msg: []
            for action, argv_tail in (
                ('--create', [user]),
                ('--destroy', [user]),
                ('--reload', []),
            ):
                run = run_client(
                    leapctl,
                    ['leapctl', action] + argv_tail,
                    _reset_leapctl(leapctl),
                )
                results.expect_eq(
                    f"leapctl {action}: a silent daemon fails cleanly",
                    run.exit_code,
                    1,
                )
                results.check(
                    f"leapctl {action}: a silent daemon is reported",
                    "didn't return a valid response" in run.stderr,
                )


def _reset_leapctl(leapctl: ModuleType) -> Callable[[], None]:
    """Clear leapctl's module state between runs."""

    def reset() -> None:
        leapctl.LeapctlGlobal.control_session = None

    return reset


# ---------------------------------------------------------------------------
# leaprun
# ---------------------------------------------------------------------------


def _reset_leaprun(leaprun: ModuleType, user: str) -> Callable[[], None]:
    """Clear leaprun's module state between runs."""

    def reset() -> None:
        leaprun.LeaprunGlobal.signal_name_list = []
        leaprun.LeaprunGlobal.check_mode = False
        leaprun.LeaprunGlobal.test_mode = False
        leaprun.LeaprunGlobal.output_msg = None
        leaprun.LeaprunGlobal.in_response_handler = False
        leaprun.LeaprunGlobal.terminate_session = False
        leaprun.LeaprunGlobal.comm_session = None
        leaprun.LeaprunGlobal.user_name = user

    return reset


def test_leaprun_argument_handling(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """A malformed command line prints usage and fails."""

    print('== leaprun rejects malformed command lines ==')
    user: str = current_username()
    bad_argvs: list[list[str]] = [
        ['leaprun'],
        ['leaprun', '--check'],
        ['leaprun', 'bad name'],
        ['leaprun', 'action-one', 'action-two'],
    ]
    with ClientSandbox(pl):
        for argv in bad_argvs:
            run: ClientRun = run_client(
                leaprun, argv, _reset_leaprun(leaprun, user)
            )
            label: str = f"leaprun {' '.join(argv[1:]) or '(no arguments)'}"
            results.check(f"{label}: fails", run.exit_code > 0)
            ## Without this the check proves nothing: no daemon is listening
            ## in the sandbox, so ANY command line fails. What is under test
            ## is that leaprun rejects the arguments itself, before it ever
            ## reaches for a socket.
            rejected_locally: bool = (
                'leaprun [-c|--check]' in run.stdout
                or 'is invalid' in run.stderr
            )
            results.check(
                f"{label}: is rejected by leaprun, not by the missing daemon",
                rejected_locally,
            )


def test_leaprun_action_run(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    A successful action run forwards the action's output verbatim to the right
    stream and adopts the action's exit code, which is what any script calling
    leaprun depends on.
    """

    print("== leaprun forwards an action's output and exit code ==")
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:
            server.reply_for = lambda _msg: [
                pl.PrivleapCommServerTriggerMsg(),
                pl.PrivleapCommServerResultStdoutMsg(b'out-payload\n'),
                pl.PrivleapCommServerResultStderrMsg(b'err-payload\n'),
                pl.PrivleapCommServerResultExitcodeMsg(7),
            ]
            run: ClientRun = run_client(
                leaprun, ['leaprun', 'act'], _reset_leaprun(leaprun, user)
            )
            results.expect_eq(
                "the action's exit code is adopted", run.exit_code, 7
            )
            results.check(
                "the action's stdout is forwarded",
                'out-payload' in run.stdout,
            )
            results.check(
                "the action's stderr is forwarded",
                'err-payload' in run.stderr,
            )
            results.check(
                'the request was a SIGNAL',
                len(server.received) == 1
                and server.received[0].name == 'SIGNAL',
            )


def test_leaprun_refusals(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    A refusal and a failed trigger must both be non-zero, and must not be
    reported as the action having run.
    """

    print('== leaprun reports refusals and trigger failures ==')
    user: str = current_username()
    cases: list[tuple[str, list[Any], str]] = [
        (
            'unauthorized',
            [pl.PrivleapCommServerUnauthorizedMsg(['act'])],
            'unauthorized',
        ),
        (
            'trigger error',
            [pl.PrivleapCommServerTriggerErrorMsg()],
            'error was encountered launching action',
        ),
    ]
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:
            for label, replies, want_text in cases:
                server.reply_for = lambda _msg, replies=replies: replies
                run: ClientRun = run_client(
                    leaprun, ['leaprun', 'act'], _reset_leaprun(leaprun, user)
                )
                results.check(
                    f"{label}: exit code is non-zero", run.exit_code > 0
                )
                results.check(
                    f"{label}: is reported to stderr",
                    want_text in run.stderr.lower(),
                )


def test_leaprun_access_check(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    An access check reports authorized and unauthorized actions separately,
    and fails overall if anything was refused.
    """

    print('== leaprun reports an access check ==')
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:
            server.reply_for = lambda _msg: [
                pl.PrivleapCommServerAuthorizedMsg(['act-yes']),
                pl.PrivleapCommServerUnauthorizedMsg(['act-no']),
                pl.PrivleapCommServerAccessCheckResultsEndMsg(),
            ]
            run: ClientRun = run_client(
                leaprun,
                ['leaprun', '--check', 'act-yes', 'act-no'],
                _reset_leaprun(leaprun, user),
            )
            results.check(
                'an authorized action is listed as authorized',
                'act-yes' in run.stdout and 'is authorized' in run.stdout,
            )
            results.check(
                'an unauthorized action is listed as unauthorized',
                'act-no' in run.stderr and 'unauthorized' in run.stderr,
            )
            results.check(
                'a partly refused check fails overall', run.exit_code > 0
            )
            results.check(
                'the request was an ACCESS_CHECK',
                len(server.received) == 1
                and server.received[0].name == 'ACCESS_CHECK',
            )

            server.received.clear()
            server.reply_for = lambda _msg: [
                pl.PrivleapCommServerAuthorizedMsg(['act-yes']),
                pl.PrivleapCommServerAccessCheckResultsEndMsg(),
            ]
            run = run_client(
                leaprun,
                ['leaprun', '--check', 'act-yes'],
                _reset_leaprun(leaprun, user),
            )
            results.expect_eq(
                'a fully authorized check succeeds', run.exit_code, 0
            )


def test_leaprun_server_failures(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    An absent daemon, a silent one, and one that answers with a message that
    is legal on the wire but wrong for the request must all end in a clean
    non-zero exit.
    """

    print('== leaprun survives a missing, silent or confused daemon ==')
    user: str = current_username()
    with ClientSandbox(pl):
        run: ClientRun = run_client(
            leaprun, ['leaprun', 'act'], _reset_leaprun(leaprun, user)
        )
        results.check('a missing daemon fails cleanly', run.exit_code > 0)

        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:
            server.reply_for = lambda _msg: []
            run = run_client(
                leaprun, ['leaprun', 'act'], _reset_leaprun(leaprun, user)
            )
            results.check('a silent daemon fails cleanly', run.exit_code > 0)

            ## An ACCESS_CHECK answer to a SIGNAL request: wrong, but legal on
            ## the wire, so the client must reject it rather than crash.
            server.reply_for = lambda _msg: [
                pl.PrivleapCommServerAccessCheckResultsEndMsg()
            ]
            run = run_client(
                leaprun, ['leaprun', 'act'], _reset_leaprun(leaprun, user)
            )
            results.check(
                'a mismatched reply fails cleanly', run.exit_code > 0
            )
            results.check(
                'a mismatched reply produced no traceback',
                'Traceback' not in run.stderr,
            )


def protocol_violation_cases(pl: ModuleType) -> list[tuple[str, list[str], list[Any]]]:
    """
    Message sequences that are individually well-formed but illegal in
    sequence. A client that acts on them would report an action as having run
    when it did not, or the reverse.
    """

    return [
        (
            'output before any TRIGGER',
            ['leaprun', 'act'],
            [pl.PrivleapCommServerResultStdoutMsg(b'early\n')],
        ),
        (
            'an error stream before any TRIGGER',
            ['leaprun', 'act'],
            [pl.PrivleapCommServerResultStderrMsg(b'early\n')],
        ),
        (
            'an exit code before any TRIGGER',
            ['leaprun', 'act'],
            [pl.PrivleapCommServerResultExitcodeMsg(0)],
        ),
        (
            'two TRIGGER messages',
            ['leaprun', 'act'],
            [
                pl.PrivleapCommServerTriggerMsg(),
                pl.PrivleapCommServerTriggerMsg(),
            ],
        ),
        (
            'UNAUTHORIZED after a TRIGGER',
            ['leaprun', 'act'],
            [
                pl.PrivleapCommServerTriggerMsg(),
                pl.PrivleapCommServerUnauthorizedMsg(['act']),
            ],
        ),
        (
            'AUTHORIZED outside check mode',
            ['leaprun', 'act'],
            [pl.PrivleapCommServerAuthorizedMsg(['act'])],
        ),
        (
            'a TRIGGER in check mode',
            ['leaprun', '--check', 'act'],
            [pl.PrivleapCommServerTriggerMsg()],
        ),
        (
            'a TRIGGER_ERROR in check mode',
            ['leaprun', '--check', 'act'],
            [pl.PrivleapCommServerTriggerErrorMsg()],
        ),
        (
            'two UNAUTHORIZED messages in check mode',
            ['leaprun', '--check', 'act'],
            [
                pl.PrivleapCommServerUnauthorizedMsg(['act']),
                pl.PrivleapCommServerUnauthorizedMsg(['act']),
            ],
        ),
        (
            'two AUTHORIZED messages in check mode',
            ['leaprun', '--check', 'act'],
            [
                pl.PrivleapCommServerAuthorizedMsg(['act']),
                pl.PrivleapCommServerAuthorizedMsg(['act']),
            ],
        ),
        (
            'results ending before any verdict',
            ['leaprun', '--check', 'act'],
            [pl.PrivleapCommServerAccessCheckResultsEndMsg()],
        ),
    ]


def test_leaprun_rejects_protocol_violations(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    Every illegal message sequence must end in a non-zero exit and a stated
    reason, never a traceback and never a success.
    """

    print('== leaprun rejects illegal message sequences ==')
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:
            for label, argv, replies in protocol_violation_cases(pl):
                server.reply_for = lambda _msg, replies=replies: replies
                run: ClientRun = run_client(
                    leaprun, argv, _reset_leaprun(leaprun, user)
                )
                results.check(
                    f"{label}: exit code is non-zero", run.exit_code > 0
                )
                results.check(
                    f"{label}: produced no traceback",
                    'Traceback' not in run.stderr,
                )
                results.check(
                    f"{label}: stated a reason", run.stderr.strip() != ''
                )


def test_leaprun_terminates_on_interrupt(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    An interrupted run must tell the daemon to stop the action rather than
    just walking away and leaving it running as root.
    """

    print('== an interrupted run asks the daemon to stop the action ==')
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:

            def reply_then_wait(_msg: Any) -> list[Any]:
                ## A TRIGGER and nothing more: the action is "running", so the
                ## client sits in its response loop where the interrupt lands.
                return [pl.PrivleapCommServerTriggerMsg()]

            server.reply_for = reply_then_wait
            server.read_trailing = True
            reset: Callable[[], None] = _reset_leaprun(leaprun, user)

            def reset_and_arm() -> None:
                reset()
                ## Stand in for the user pressing Ctrl+C while the action runs.
                leaprun.LeaprunGlobal.terminate_session = True

            run: ClientRun = run_client(
                leaprun, ['leaprun', 'act'], reset_and_arm
            )
            results.expect_eq(
                'an interrupted run exits with the interrupt code',
                run.exit_code,
                130,
            )
            results.check(
                'the daemon was told to terminate the action',
                server.wait_for('TERMINATE'),
            )


def test_leaprun_signal_handler(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    The interrupt handler must arm a terminate while an action is running, and
    exit outright when there is no action to stop.
    """

    print('== the interrupt handler picks the right response ==')
    _ = pl
    reset: Callable[[], None] = _reset_leaprun(leaprun, current_username())

    reset()
    leaprun.LeaprunGlobal.in_response_handler = True
    leaprun.signal_handler(2, None)
    results.check(
        'an interrupt during an action arms a terminate',
        leaprun.LeaprunGlobal.terminate_session,
    )

    reset()
    leaprun.LeaprunGlobal.in_response_handler = False
    exit_code: int | None = None
    try:
        leaprun.signal_handler(2, None)
    except SystemExit as exc:
        exit_code = int(exc.code or 0)
    results.expect_eq(
        'an interrupt with no action running exits immediately',
        exit_code,
        128,
    )


def test_leapctl_send_failure(
    results: Results, pl: ModuleType, leapctl: ModuleType
) -> None:
    """
    A daemon that accepts the connection and hangs up before the request is
    even sent must produce a clean error, not a traceback.
    """

    print('== leapctl survives a daemon that hangs up before the request ==')
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl, str(pl.PrivleapCommon.control_path), is_control=True
        ) as server:
            ## Accept and close immediately, without reading anything.
            server.read_request = False
            for action, argv_tail in (
                ('--create', [user]),
                ('--destroy', [user]),
                ('--reload', []),
            ):
                run: ClientRun = run_client(
                    leapctl,
                    ['leapctl', action] + argv_tail,
                    _reset_leapctl(leapctl),
                )
                results.check(
                    f"leapctl {action}: exit code is non-zero",
                    run.exit_code > 0,
                )
                results.check(
                    f"leapctl {action}: produced no traceback",
                    'Traceback' not in run.stderr,
                )


def test_leaprun_truncated_action_output(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    An action whose output stops arriving must not be reported as having
    finished. leaprun has no exit code at that point, so treating the
    truncation as success would hand the caller a silent partial result.
    """

    print('== leaprun reports an action whose output was cut off ==')
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:
            ## TRIGGER and some output, then hang up with no exit code.
            server.reply_for = lambda _msg: [
                pl.PrivleapCommServerTriggerMsg(),
                pl.PrivleapCommServerResultStdoutMsg(b'partial\n'),
            ]
            run: ClientRun = run_client(
                leaprun, ['leaprun', 'act'], _reset_leaprun(leaprun, user)
            )
            results.check(
                'a truncated action run fails', run.exit_code > 0
            )
            results.check(
                'the truncation is named, not reported as success',
                'before sending all output' in run.stderr,
            )
            results.check(
                'the output received so far is still shown',
                'partial' in run.stdout,
            )


def test_leaprun_option_parsing(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    An action name that looks like an option must still reach the daemon as a
    name. Without an end-of-options marker, an action called '--check' would
    silently become a mode switch.
    """

    print('== leaprun separates options from action names ==')
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:
            server.reply_for = lambda _msg: [
                pl.PrivleapCommServerTriggerMsg(),
                pl.PrivleapCommServerResultExitcodeMsg(0),
            ]
            run: ClientRun = run_client(
                leaprun,
                ['leaprun', '--', 'act'],
                _reset_leaprun(leaprun, user),
            )
            results.expect_eq(
                'an action name after -- runs', run.exit_code, 0
            )
            results.check(
                'it was sent as a SIGNAL, not treated as an option',
                len(server.received) == 1
                and server.received[0].name == 'SIGNAL',
            )

            server.received.clear()
            run = run_client(
                leaprun,
                ['leaprun', '--test', 'act'],
                _reset_leaprun(leaprun, user),
            )
            results.expect_eq(
                'the --test flag is accepted', run.exit_code, 0
            )
            results.check(
                'the --test flag is not sent as an action name',
                len(server.received) == 1
                and server.received[0].signal_name == 'act',
            )


def test_leaprun_terminate_send_failure(
    results: Results, pl: ModuleType, leaprun: ModuleType
) -> None:
    """
    If the daemon is already gone when the user interrupts, leaprun cannot
    ask it to stop the action. That must be reported: exiting as though the
    terminate was delivered would claim a root action had been stopped when
    nothing was told to stop it.
    """

    print('== a terminate that cannot be delivered is reported ==')
    user: str = current_username()
    with ClientSandbox(pl):
        server: ScriptedServer
        with ScriptedServer(
            pl,
            str(pl.Path(pl.PrivleapCommon.comm_dir, user)),
            is_control=False,
        ) as server:
            ## Accept, then hang up at once, so the terminate has nowhere to go.
            server.read_request = False
            server.reply_for = lambda _msg: []
            reset: Callable[[], None] = _reset_leaprun(leaprun, user)

            def reset_and_arm() -> None:
                reset()
                leaprun.LeaprunGlobal.terminate_session = True

            run: ClientRun = run_client(
                leaprun, ['leaprun', 'act'], reset_and_arm
            )
            results.check(
                'an undeliverable terminate fails', run.exit_code > 0
            )
            results.check(
                'an undeliverable terminate produced no traceback',
                'Traceback' not in run.stderr,
            )


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
        description='privleap client tool tests'
    )
    parser.add_argument(
        '--seed', type=int, default=1, help='accepted for interface parity'
    )
    parser.parse_args()

    pl: ModuleType = import_privleap()
    leapctl: ModuleType = import_privleap_module('leapctl')
    leaprun: ModuleType = import_privleap_module('leaprun')
    results: Results = Results()

    run_test(results, test_leapctl_argument_handling, pl, leapctl)
    run_test(results, test_leapctl_replies, pl, leapctl)
    run_test(results, test_leapctl_unknown_account, pl, leapctl)
    run_test(results, test_leapctl_server_failures, pl, leapctl)
    run_test(results, test_leaprun_argument_handling, pl, leaprun)
    run_test(results, test_leaprun_action_run, pl, leaprun)
    run_test(results, test_leaprun_refusals, pl, leaprun)
    run_test(results, test_leaprun_access_check, pl, leaprun)
    run_test(results, test_leaprun_server_failures, pl, leaprun)
    run_test(results, test_leaprun_rejects_protocol_violations, pl, leaprun)
    run_test(results, test_leaprun_terminates_on_interrupt, pl, leaprun)
    run_test(results, test_leaprun_signal_handler, pl, leaprun)
    run_test(results, test_leaprun_truncated_action_output, pl, leaprun)
    run_test(results, test_leaprun_option_parsing, pl, leaprun)
    run_test(results, test_leaprun_terminate_send_failure, pl, leaprun)
    run_test(results, test_leapctl_send_failure, pl, leapctl)

    print('')
    return results.report('client tool test')


if __name__ == '__main__':
    sys.exit(main())
