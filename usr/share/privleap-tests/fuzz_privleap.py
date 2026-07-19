#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris (libFuzzer) coverage-guided fuzz harness for privleap's SERVER-SIDE
wire-protocol parser -- the only code path an unprivileged local user can reach
by writing bytes to their own comm socket, and therefore the place a parser bug
could turn attacker input into a daemon crash (DoS) or a mis-parsed message.

This is the coverage-guided counterpart to parser_fuzz.py: instead of a
hand-rolled random/mutational generator, Atheris drives the REAL parser and
mutates inputs guided by the coverage it observes inside privleap.privleap, so
it reaches deep parser branches a blind generator would rarely hit.

Each input is split into a socket-direction bit and a raw frame, fed to a
genuine server-side PrivleapSession.get_msg() over a socketpair (half-closed so
the parser sees EOF, never a real timeout), and classified against the parser's
contract:

  * a CONTROLLED rejection (ValueError / ConnectionAbortedError /
    socket.timeout) or a legal, well-formed message -> not a finding;
  * any OTHER exception propagates, so Atheris reports it as a crash;
  * a returned message of a type illegal for that socket, or with fields that
    fail re-validation, is a type-confusion finding (raised explicitly).

libFuzzer's own -timeout catches a parser hang. No root, no network, no live
privleapd.

Local run (direct Atheris, needs `pip install atheris`):
    privleap-tests-fuzz-atheris            # 60s by default
    python3 fuzz_privleap.py -max_total_time=120 [corpus_dir]

The harness is ClusterFuzzLite-ready: a compile_python_fuzzer over
fuzz_privleap.py wraps it for OSS-Fuzz's Python runtime unchanged.
"""

import os
import socket
import sys

DEFAULT_REPO: str = "/home/user/derivative-maker/packages/kicksecure/privleap"
INSTALLED_PARENT: str = "/usr/lib/python3/dist-packages"


def _dist_packages_dir() -> str | None:
    """Resolve the directory to put on sys.path so ``import privleap.privleap``
    finds the target: PRIVLEAP_REPO, else installed, else the in-tree checkout."""

    repo: str | None = os.environ.get("PRIVLEAP_REPO")
    if repo:
        candidate: str = os.path.join(repo, "usr/lib/python3/dist-packages")
        if os.path.isfile(os.path.join(candidate, "privleap", "privleap.py")):
            return candidate
        return None
    if os.path.isfile(
        os.path.join(INSTALLED_PARENT, "privleap", "privleap.py")
    ):
        return INSTALLED_PARENT
    candidate = os.path.join(DEFAULT_REPO, "usr/lib/python3/dist-packages")
    if os.path.isfile(os.path.join(candidate, "privleap", "privleap.py")):
        return candidate
    return None


_PARENT: str | None = _dist_packages_dir()
if _PARENT is not None and _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

## Import Atheris if available so the target module is instrumented for
## coverage-guided fuzzing. When Atheris is absent the module still imports the
## (uninstrumented) parser, so main() can report a clean skip and so the
## contract logic remains importable for a lightweight self-check.
try:
    import atheris  # type: ignore

    _HAVE_ATHERIS: bool = True
except ImportError:
    _HAVE_ATHERIS = False

if _PARENT is not None:
    if _HAVE_ATHERIS:
        with atheris.instrument_imports():
            from privleap import privleap as pl  # noqa: E402
    else:
        from privleap import privleap as pl  # noqa: E402
else:
    pl = None  # type: ignore


## Message types legal to RECEIVE on each server-side socket. Anything else
## coming back from get_msg() is a type-confusion finding.
COMM_RECV: tuple[str, ...] = ("SIGNAL", "ACCESS_CHECK", "TERMINATE")
CONTROL_RECV: tuple[str, ...] = ("CREATE", "DESTROY", "RELOAD")


def _server_user() -> str:
    import pwd  # pylint: disable=import-outside-toplevel

    return pwd.getpwuid(os.getuid()).pw_name


def _fields_ok(msg: object) -> bool:
    """Re-validate an accepted message's fields with the senders' own rules; an
    accepted message must never carry a value the validator rejects."""

    vt = pl.PrivleapValidateType
    name: str = msg.name  # type: ignore[attr-defined]
    if name == "SIGNAL":
        return pl.PrivleapCommon.validate_id(
            msg.signal_name, vt.SIGNAL_NAME  # type: ignore[attr-defined]
        )
    if name in ("CREATE", "DESTROY"):
        return pl.PrivleapCommon.validate_id(
            msg.user_name, vt.USER_GROUP_NAME  # type: ignore[attr-defined]
        )
    if name == "ACCESS_CHECK":
        names = msg.signal_name_list  # type: ignore[attr-defined]
        ## Fail closed if the field is not the expected list of strings, so a
        ## single string cannot pass by validating each character separately.
        if not isinstance(names, list):
            return False
        if not 1 <= len(names) <= 63:
            return False
        return all(
            isinstance(n, str) and pl.PrivleapCommon.validate_id(
                n, vt.SIGNAL_NAME
            )
            for n in names
        )
    ## TERMINATE / RELOAD carry no fields; fail closed for anything unexpected.
    return name in ("TERMINATE", "RELOAD")


def _drive(raw: bytes, control: bool) -> None:
    """Feed ``raw`` to a real server-side parser and raise on a finding.

    Controlled rejections and legal, well-formed messages return normally; an
    uncontrolled exception propagates (Atheris reports it); a type confusion or
    an ill-formed accepted message is raised explicitly.
    """

    cli: socket.socket
    srv: socket.socket
    cli, srv = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            session = pl.PrivleapSession(
                srv,
                user_name=None if control else _server_user(),
                is_control_session=control,
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            ## Session construction does not depend on the fuzz input, so a
            ## failure here is a broken harness/environment, not a parser
            ## finding. Fail loudly rather than silently turning every input
            ## into a no-op that still reports "no crashes".
            raise RuntimeError("PrivleapSession setup failed") from exc

        try:
            cli.sendall(raw)
        except OSError:
            # best-effort socket op; the server may have closed
            pass
        try:
            cli.shutdown(socket.SHUT_WR)
        except OSError:
            # best-effort socket op; the server may have closed
            pass

        legal: tuple[str, ...] = CONTROL_RECV if control else COMM_RECV
        try:
            msg = session.get_msg()
        except (ValueError, ConnectionAbortedError, socket.timeout):
            return  ## controlled rejection -- the parser said "no" cleanly

        ## A message was returned: enforce the receive-side contract.
        if msg.name not in legal:
            raise RuntimeError(
                f"TYPE CONFUSION: received {msg.name!r} on a "
                f"{'control' if control else 'comm'} socket; input={raw!r}"
            )
        if not _fields_ok(msg):
            raise RuntimeError(
                f"ILL-FORMED accepted {msg.name!r} message; input={raw!r}"
            )
    finally:
        try:
            cli.close()
        finally:
            srv.close()


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    """Atheris entry point: one fuzz input -> one parse attempt."""

    fdp = atheris.FuzzedDataProvider(data)
    control: bool = fdp.ConsumeBool()
    well_framed: bool = fdp.ConsumeBool()
    body: bytes = fdp.ConsumeBytes(fdp.remaining_bytes())
    if well_framed:
        ## Prepend a correct length so the input always clears the framing /
        ## 4096-byte cap in __recv_msg_cautious and reaches the message
        ## tokenizer; the fuzzer then explores the body (type, arg count,
        ## arguments). Without this, random first-4-bytes are almost always a
        ## huge length rejected before the parser ever runs.
        raw: bytes = len(body).to_bytes(4, "big") + body
    else:
        ## Leave the bytes raw to also fuzz the length-prefix / framing path.
        raw = body
    _drive(raw, control)


def main() -> None:
    if _PARENT is None:
        print("SKIP: privleap library not found.")
        print("      set PRIVLEAP_REPO to a derivative-maker checkout root.")
        raise SystemExit(77)
    if not _HAVE_ATHERIS:
        print("SKIP: atheris is not installed (pip install atheris).")
        print("      this is the coverage-guided harness; for a no-dependency")
        print("      fuzz run use privleap-tests-fuzz instead.")
        raise SystemExit(77)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
