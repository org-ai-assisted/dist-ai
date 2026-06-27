#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
In-process fuzzer / property test for privleap's SERVER-SIDE wire-protocol
parser -- the only code path an unprivileged local user can reach by writing
bytes to their own comm socket, and therefore the primary place a parser bug
could turn attacker-controlled input into a daemon crash (DoS) or a
mis-parsed (and thus possibly mis-authorized) message.

It drives the REAL parser: a server-side privleap.PrivleapSession wrapped
around one end of a socketpair, with arbitrary fuzz bytes written to the
other end (then half-closed, so the parser sees a deterministic EOF and
never blocks on a real timeout). For each input it calls the genuine
session.get_msg() and classifies the outcome against a strict contract:

  ALLOWED outcomes:
    * a returned PrivleapMsg whose type is legal for that socket
      direction, and whose fields are well-formed (re-validated here), or
    * a CONTROLLED rejection: ValueError / ConnectionAbortedError /
      socket.timeout. These are the parser saying "no" cleanly.

  FINDINGS (a defect in the parser's robustness):
    * any OTHER exception type (IndexError, UnicodeDecodeError, KeyError,
      OverflowError, RecursionError, AssertionError, ...): the parser let
      malformed input reach code that was not expecting it.
    * a HANG: get_msg did not return within the watchdog window -- a
      potential denial-of-service loop.
    * a TYPE-CONFUSION: get_msg returned a message type that is not valid
      to receive on that socket, or a message whose fields fail
      re-validation. Either could defeat a downstream type check.

It also runs a round-trip property: everything the real serializer can emit
for a given direction MUST parse back to an equal message (a parser that
rejects valid traffic is an availability bug).

No root, no network, no live privleapd.
"""

# pylint: disable=too-many-branches,too-many-locals,too-many-statements

import argparse
import os
import random
import signal
import socket
import sys
from dataclasses import dataclass
from types import FrameType, ModuleType
from typing import Any, Callable

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import Results, current_username  # noqa: E402


## Set by main() after (optional) coverage has started, so that privleap's
## own import / def lines are counted in the coverage report.
pl: ModuleType  # the privleap.privleap module


class _Hang(Exception):
    """Raised by the watchdog alarm when get_msg overruns its time budget."""


def _alarm_handler(_sig: int, _frame: FrameType | None) -> None:
    raise _Hang()


## Message types that are legal to RECEIVE on each server-side socket. A
## returned message outside its set is a type-confusion finding.
COMM_RECV_TYPES: tuple[str, ...] = ("SIGNAL", "ACCESS_CHECK", "TERMINATE")
CONTROL_RECV_TYPES: tuple[str, ...] = ("CREATE", "DESTROY", "RELOAD")


@dataclass
class Outcome:
    """Classification of a single get_msg() call."""

    kind: str  # "msg" | "reject" | "FINDING"
    detail: str
    msg: Any = None


def frame(body: bytes) -> bytes:
    """Prefix a message body with privleap's 4-byte big-endian length header."""

    return len(body).to_bytes(4, byteorder="big") + body


def drive(raw: bytes, control: bool, watchdog_s: float = 2.0) -> Outcome:
    """
    Feed ``raw`` to a real server-side parser and classify the result.

    ``control`` selects a control socket (CREATE/DESTROY/RELOAD) vs a comm
    socket (SIGNAL/ACCESS_CHECK/TERMINATE). The write end is half-closed so
    the parser sees EOF rather than blocking.
    """

    cli: socket.socket
    srv: socket.socket
    cli, srv = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            session: Any = pl.PrivleapSession(
                srv,
                user_name=None if control else current_username(),
                is_control_session=control,
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return Outcome("FINDING", f"session setup raised {exc!r}")

        try:
            cli.sendall(raw)
        except OSError:
            ## Buffer full on a pathologically large input; not a parser fault.
            pass
        cli.shutdown(socket.SHUT_WR)

        legal_types: tuple[str, ...] = (
            CONTROL_RECV_TYPES if control else COMM_RECV_TYPES
        )

        signal.setitimer(signal.ITIMER_REAL, watchdog_s)
        try:
            msg: Any = session.get_msg()
        except _Hang:
            return Outcome("FINDING", "HANG: get_msg exceeded watchdog window")
        except (ValueError, ConnectionAbortedError, socket.timeout) as exc:
            return Outcome("reject", type(exc).__name__)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return Outcome(
                "FINDING",
                f"uncontrolled {type(exc).__name__}: {exc}",
            )
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

        ## A message was returned: enforce the receive-side contract.
        if msg.name not in legal_types:
            return Outcome(
                "FINDING",
                f"TYPE-CONFUSION: received '{msg.name}' on a "
                f"{'control' if control else 'comm'} socket",
                msg,
            )
        if not _fields_well_formed(msg):
            return Outcome(
                "FINDING",
                f"ill-formed fields on accepted '{msg.name}' message",
                msg,
            )
        return Outcome("msg", msg.name, msg)
    finally:
        try:
            cli.close()
        finally:
            srv.close()


def _fields_well_formed(msg: Any) -> bool:
    """
    Re-validate the fields of an accepted message with the same rules the
    senders use. An accepted message must never carry a value the validator
    rejects.
    """

    vt = pl.PrivleapValidateType
    if msg.name == "SIGNAL":
        return pl.PrivleapCommon.validate_id(msg.signal_name, vt.SIGNAL_NAME)
    if msg.name in ("CREATE", "DESTROY"):
        return pl.PrivleapCommon.validate_id(
            msg.user_name, vt.USER_GROUP_NAME
        )
    if msg.name == "ACCESS_CHECK":
        names: list[str] = msg.signal_name_list
        if not 1 <= len(names) <= 63:
            return False
        return all(
            pl.PrivleapCommon.validate_id(name, vt.SIGNAL_NAME)
            for name in names
        )
    ## TERMINATE / RELOAD carry no fields.
    return True


# ---------------------------------------------------------------------------
# Valid-traffic corpus (for the round-trip property) and bad-input corpus.
# ---------------------------------------------------------------------------


def valid_comm_frames() -> list[tuple[bytes, str]]:
    """Framed messages a legitimate client sends on a comm socket."""

    out: list[tuple[bytes, str]] = []
    out.append((frame(pl.PrivleapCommClientSignalMsg("act").serialize()),
                "SIGNAL"))
    out.append((frame(pl.PrivleapCommClientSignalMsg(
        "a-long.action_NAME-123").serialize()), "SIGNAL"))
    out.append((frame(
        pl.PrivleapCommClientAccessCheckMsg(["one"]).serialize()),
        "ACCESS_CHECK"))
    out.append((frame(pl.PrivleapCommClientAccessCheckMsg(
        [f"act{n}" for n in range(63)]).serialize()), "ACCESS_CHECK"))
    out.append((frame(pl.PrivleapCommClientTerminateMsg().serialize()),
                "TERMINATE"))
    return out


def valid_control_frames() -> list[tuple[bytes, str]]:
    """Framed messages a legitimate client sends on a control socket."""

    user: str = current_username()
    out: list[tuple[bytes, str]] = []
    out.append((frame(pl.PrivleapControlClientCreateMsg(user).serialize()),
                "CREATE"))
    out.append((frame(pl.PrivleapControlClientDestroyMsg(user).serialize()),
                "DESTROY"))
    out.append((frame(pl.PrivleapControlClientReloadMsg().serialize()),
                "RELOAD"))
    return out


## Directed bad-input vectors. These mirror and extend the malformed inputs
## the upstream autopkgtest checks (control characters, wrong length headers,
## arg-count mismatches), plus boundary cases around the 4096-byte server cap.
def directed_bad_inputs() -> list[bytes]:
    """A hand-built corpus of malformed frames; each must be rejected."""

    out: list[bytes] = [
        b"",                                 # nothing
        b"\x00",                             # 1/4 header
        b"\x00\x00\x00",                     # 3/4 header
        b"\x00\x00\x00\x00",                 # zero-length body
        frame(b"SIGNAL"),                    # missing arg-count + arg
        frame(b"SIGNAL 1"),                  # arg count but no arg
        frame(b"SIGNAL 1 "),                 # trailing space, empty arg
        frame(b"SIGNAL 1  act"),             # double space
        frame(b"SIGNAL 2 act"),              # count says 2, one given
        frame(b"SIGNAL 0 act"),              # count says 0, one given (trailing)
        frame(b"SIGNAL 1 a b"),              # extra token past last string
        frame(b"BOGUS 0"),                   # unrecognized type
        frame(b"\x1bSIGNAL 1 act"),          # ESC in type field
        frame(b"SIGNAL\x1b 1 act"),          # ESC after type
        frame(b"SIGNAL 1 ac\x1bt"),          # ESC in arg
        frame(b"SIGNAL 1 ac\x7ft"),          # DEL in arg
        frame(b"SIGNAL 1 ac\x00t"),          # NUL in arg
        frame(b"SIGNAL 1 ac\xc3\xa9t"),      # non-ASCII (UTF-8 e-acute)
        frame(b"SIGNAL ! act"),              # bad arg-count digit '!'
        frame(b"SIGNAL   act"),              # arg-count is a space
        frame(b"ACCESS_CHECK 0 "),           # below lower bound (0 < 1)
        frame(b"RELOAD 1 x"),                # arg count over RELOAD's bound
        frame(b"CREATE 1 ../etc"),           # path-ish username (must reject)
        frame(b"CREATE 1 " + b"a" * 200),    # over the 100-char id limit
    ]
    ## Length header that lies: declares > 4096 (server cap). Must reject,
    ## never read 5000 bytes nor return a message.
    out.append((5000).to_bytes(4, "big") + b"SIGNAL 1 act")
    ## Exactly at the cap boundary with a huge but ASCII signal name: the
    ## name busts the 100-char id limit, so it must reject, not accept.
    big_name: bytes = b"a" * 4000
    out.append(frame(b"SIGNAL 1 " + big_name))
    ## A frame whose declared length exceeds what is actually sent.
    out.append((50).to_bytes(4, "big") + b"SIGNAL 1 act")
    return out


# ---------------------------------------------------------------------------
# Random / mutational generators.
# ---------------------------------------------------------------------------

TYPE_TOKENS: tuple[bytes, ...] = (
    b"SIGNAL", b"ACCESS_CHECK", b"TERMINATE", b"CREATE", b"DESTROY",
    b"RELOAD", b"TRIGGER", b"AUTHORIZED", b"UNAUTHORIZED", b"OK",
    b"BOGUS", b"", b"signal", b"SIGNAL2",
)
ARGCNT_CHARS: tuple[bytes, ...] = tuple(
    bytes([c]) for c in b"0123456789ABZaz+/!= \x00\x1b\x7f"
)


def gen_random(rng: random.Random) -> bytes:
    """A 4-byte length header (often a lie) followed by random bytes."""

    body_len: int = rng.randint(0, 80)
    body: bytes = bytes(rng.getrandbits(8) for _ in range(body_len))
    header_choice: int = rng.randint(0, 3)
    if header_choice == 0:
        header = len(body).to_bytes(4, "big")          # honest
    elif header_choice == 1:
        header = rng.randint(0, 4095).to_bytes(4, "big")  # under cap
    elif header_choice == 2:
        header = rng.randint(4097, 1 << 24).to_bytes(4, "big")  # over cap
    else:
        header = bytes(rng.getrandbits(8) for _ in range(4))    # random
    return header + body


def gen_structured(rng: random.Random) -> bytes:
    """A plausibly-shaped 'TYPE ARGCNT ARGS' message with fuzzed pieces."""

    token: bytes = rng.choice(TYPE_TOKENS)
    argcnt: bytes = rng.choice(ARGCNT_CHARS)
    nargs: int = rng.randint(0, 5)
    args: list[bytes] = []
    alphabet: bytes = b"-A-Za-z0-9_.abc"
    for _ in range(nargs):
        arg_len: int = rng.randint(0, 8)
        args.append(bytes(rng.choice(alphabet) for _ in range(arg_len)))
    sep: bytes = rng.choice((b" ", b"  ", b" \x1b", b""))
    body: bytes = token + b" " + argcnt + (b" " if args else b"") + \
        sep.join(args)
    if rng.random() < 0.15:
        body += bytes([rng.choice((0x00, 0x1b, 0x7f, 0xff))])
    return frame(body)


def gen_mutated(rng: random.Random, seeds: list[bytes]) -> bytes:
    """Take a valid frame and apply a few random byte-level mutations."""

    data: bytearray = bytearray(rng.choice(seeds))
    for _ in range(rng.randint(1, 4)):
        if not data:
            data = bytearray(b"\x00")
        op: int = rng.randint(0, 3)
        pos: int = rng.randrange(len(data))
        if op == 0:                       # flip a bit
            data[pos] ^= 1 << rng.randint(0, 7)
        elif op == 1:                     # replace a byte
            data[pos] = rng.getrandbits(8)
        elif op == 2:                     # delete a byte
            del data[pos]
        else:                             # insert a byte
            data.insert(pos, rng.getrandbits(8))
    return bytes(data)


# ---------------------------------------------------------------------------
# Test phases.
# ---------------------------------------------------------------------------


def phase_roundtrip(results: Results) -> None:
    """Every serializer output must parse back to an equal-typed message."""

    print("== round-trip: valid traffic must parse (no false rejects) ==")
    for raw, expected in valid_comm_frames():
        outcome: Outcome = drive(raw, control=False)
        results.expect_eq(f"comm {expected} round-trips", outcome.kind, "msg")
        if outcome.kind == "msg":
            results.expect_eq(
                f"comm {expected} type", outcome.msg.name, expected
            )
    for raw, expected in valid_control_frames():
        outcome = drive(raw, control=True)
        results.expect_eq(
            f"control {expected} round-trips", outcome.kind, "msg"
        )
        if outcome.kind == "msg":
            results.expect_eq(
                f"control {expected} type", outcome.msg.name, expected
            )


def phase_directed(results: Results) -> None:
    """Hand-built malformed frames must each be cleanly rejected."""

    print("== directed: malformed frames are rejected, never accepted ==")
    for raw in directed_bad_inputs():
        for control in (False, True):
            outcome: Outcome = drive(raw, control=control)
            label: str = (
                f"{'control' if control else 'comm'} rejects {raw[:24]!r}"
            )
            ## "msg" would mean a malformed frame was accepted; "FINDING" is a
            ## crash/hang/type-confusion. Only "reject" is acceptable here.
            results.check(label, outcome.kind == "reject")
            if outcome.kind == "FINDING":
                print(f"    -> {outcome.detail}")


def phase_strictness(results: Results) -> None:
    """
    Surface a known parser laxity honestly: privleap stops parsing a zero-arg
    message as soon as it has read the argument-count digit, so trailing bytes
    after e.g. 'TERMINATE 0' are silently ignored rather than rejected.

    This is lax but NOT a confusion vector: the frame still parses as exactly
    TERMINATE with no fields, so an attacker cannot smuggle a different type,
    extra arguments, or a length/blob mismatch through the ignored tail. The
    safe property asserted here is that the outcome stays benign (a correct
    no-field TERMINATE, or a clean reject) and never a FINDING.
    """

    print("== strictness note: trailing data after a zero-arg count ==")
    raw: bytes = frame(b"TERMINATE 0 this-tail-is-ignored")
    outcome: Outcome = drive(raw, control=False)
    if outcome.kind == "msg" and outcome.msg.name == "TERMINATE":
        print(
            "  NOTE: trailing bytes after 'TERMINATE 0' are ignored and the "
            "frame is accepted as a bare TERMINATE -- lax, not a confusion "
            "vector (no extra fields, type, or blob can be smuggled in)."
        )
    results.check(
        "zero-arg trailing data stays benign (TERMINATE or clean reject)",
        outcome.kind != "FINDING"
        and (outcome.kind == "reject" or outcome.msg.name == "TERMINATE"),
    )


def phase_random(
    results: Results, rng: random.Random, iterations: int
) -> None:
    """Random, structured, and mutational inputs must never crash or hang."""

    print(f"== randomized: {iterations} iterations, no crash/hang/confusion ==")
    seeds: list[bytes] = [raw for raw, _ in valid_comm_frames()]
    seeds += [raw for raw, _ in valid_control_frames()]
    generators: list[Callable[[random.Random], bytes]] = [
        gen_random,
        gen_structured,
        lambda r: gen_mutated(r, seeds),
    ]
    findings: int = 0
    for i in range(iterations):
        gen: Callable[[random.Random], bytes] = generators[i % len(generators)]
        raw: bytes = gen(rng)
        control: bool = bool(rng.getrandbits(1))
        outcome: Outcome = drive(raw, control=control)
        if outcome.kind == "FINDING":
            findings += 1
            if findings <= 20:
                print(
                    f"  FINDING [{'control' if control else 'comm'}] "
                    f"{outcome.detail}\n    input={raw!r}"
                )
    results.check(
        f"no parser findings over {iterations} randomized inputs",
        findings == 0,
    )
    if findings > 20:
        print(f"  ... {findings} findings total (first 20 shown)")


def run(seed: int, iterations: int, results: Results) -> None:
    """Run all parser phases with the given RNG seed and iteration count."""

    rng: random.Random = random.Random(seed)
    ## Install the watchdog once; drive() arms/disarms the timer per call.
    signal.signal(signal.SIGALRM, _alarm_handler)
    phase_roundtrip(results)
    phase_directed(results)
    phase_strictness(results)
    phase_random(results, rng, iterations)


def main() -> int:
    """Standalone entry point."""

    parser = argparse.ArgumentParser(
        description="privleap wire-protocol parser fuzzer (server side)"
    )
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--iterations", type=int, default=4000)
    parser.add_argument("--coverage", action="store_true")
    args = parser.parse_args()

    seed: int = (
        args.seed if args.seed is not None else random.randrange(1 << 30)
    )

    cov: Any = None
    if args.coverage:
        try:
            import coverage  # pylint: disable=import-outside-toplevel

            cov = coverage.Coverage(include=[f"*{os.sep}privleap{os.sep}*.py"])
            cov.start()
        except ImportError:
            print("(python3-coverage not installed; skipping coverage)")

    ## Import the target only now so coverage accounts for its def lines.
    global pl  # pylint: disable=global-statement
    from pl_testlib import import_privleap  # pylint: disable=import-outside-toplevel

    pl = import_privleap()

    print(f"privleap parser fuzzer: seed={seed} iterations={args.iterations}")
    results: Results = Results()
    run(seed, args.iterations, results)

    if cov is not None:
        cov.stop()
        print("\n== coverage (privleap library) ==")
        try:
            cov.report(
                include=[f"*{os.sep}privleap{os.sep}privleap.py"],
                show_missing=True,
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            print(f"(coverage report failed: {exc!r})")

    print()
    code: int = results.report("parser fuzzer")
    if code == 0:
        print(f"(reproduce this run with --seed {seed})")
    else:
        print(f"REPRODUCE: --seed {seed} --iterations {args.iterations}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
