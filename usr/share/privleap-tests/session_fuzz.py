#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Stateful, concurrent SESSION fuzzer for the live privleapd.

The parser fuzzers (parser_fuzz.py, fuzz_privleap.py) fuzz a single frame
through get_msg(). This fuzzes the daemon's multi-message session state machine
and its threading instead -- the part an unprivileged client actually drives:
handle_comm_session -> SIGNAL -> TRIGGER -> stdout/stderr streaming over epoll
-> RESULT_EXITCODE, the TERMINATE path, ACCESS_CHECK with adversarial name
lists, and out-of-order / partial / interleaved message sequences, all from
many concurrent connections at once.

It runs the real /usr/bin/privleapd as a subprocess inside a private mount
namespace (sudo + unshare --mount; tmpfs over /run and /etc/privleap, so the
host privleapd is never touched), then hammers its comm socket with random and
directed message sequences across several worker threads. After every batch and
at the end it checks the invariants that matter for avoiding arbitrary code
execution:

  * the daemon never crashes or wedges (it stays alive and still answers);
  * an action the caller is NOT authorized for is NEVER executed, no matter how
    the messages are ordered, split, or interleaved (sentinel-file absence);
  * an authorized action still works and an unauthorized one is still denied
    after the barrage (authorization state is intact).

Run it from a NORMAL user account (not root): the harness re-execs under sudo
and attributes requests to the invoking user (SUDO_USER).

  privleap-tests-session-fuzz [--iterations N] [--threads N] [--seed N]
"""

# pylint: disable=too-many-locals

import argparse
import os
import pwd
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import ModuleType
from typing import Callable

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
import e2e_lib  # noqa: E402

e2e_lib.reexec_under_mount_namespace("PRIVLEAP_SESSION_FUZZ_INSIDE")

from pl_testlib import Results, current_username  # noqa: E402

pl: ModuleType = e2e_lib.import_target()

## Action names in the test config (e2e_lib.config_text): e2e-allow and
## e2e-rootenv are authorized for the caller, e2e-deny only for root, plus an
## undefined name to exercise the not-found path.
ACTIONS: list[str] = ["e2e-allow", "e2e-rootenv", "e2e-deny", "no-such-action"]


def _frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body


def _malformed(rng: random.Random) -> bytes:
    choice: int = rng.randint(0, 2)
    if choice == 0:
        return rng.randint(0, 1 << 24).to_bytes(4, "big") + bytes(
            rng.getrandbits(8) for _ in range(rng.randint(0, 40))
        )
    if choice == 1:
        tok: bytes = rng.choice(
            [b"SIGNAL", b"ACCESS_CHECK", b"TERMINATE", b"BOGUS", b"CREATE"]
        )
        argc: bytes = bytes([rng.choice(b"0123456789AZ !=\x1b")])
        args: bytes = bytes(
            rng.choice(b"-abcAZ09._ ") for _ in range(rng.randint(0, 12))
        )
        return _frame(tok + b" " + argc + b" " + args)
    return _frame(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 30))))


def _random_frame(rng: random.Random) -> bytes:
    roll: float = rng.random()
    if roll < 0.35:
        return _frame(f"SIGNAL 1 {rng.choice(ACTIONS)}".encode("ascii"))
    if roll < 0.55:
        count: int = rng.randint(1, 6)
        names: str = " ".join(rng.choice(ACTIONS) for _ in range(count))
        cnt_chr: str = pl.PrivleapCommon.int_to_msg_arg_count(count)
        return _frame(f"ACCESS_CHECK {cnt_chr} {names}".encode("ascii"))
    if roll < 0.68:
        return _frame(b"TERMINATE 0")
    return _malformed(rng)


## Directed adversarial sequences (frame bodies) that exercise specific
## state-machine transitions in handle_comm_session / handle_signal_message.
DIRECTED: list[list[bytes]] = [
    [b"TERMINATE 0"],                                  # TERMINATE as 1st msg
    [b"SIGNAL 1 e2e-allow", b"TERMINATE 0"],           # premature terminate
    [b"ACCESS_CHECK 1 e2e-allow", b"SIGNAL 1 e2e-allow"],  # check then signal
    [b"SIGNAL 1 e2e-allow", b"SIGNAL 1 e2e-allow"],    # double signal
    [b"SIGNAL 1 e2e-deny"],                            # unauthorized signal
    [b"SIGNAL 1 e2e-rootenv", b"TERMINATE 0"],
    [b"ACCESS_CHECK 1 e2e-deny", b"ACCESS_CHECK 1 e2e-allow"],
    [b"SIGNAL 1 e2e-allow"],                           # signal, no read, close
]


def _run_session(
    sock_path: str, frames: list[bytes], rng: random.Random
) -> None:
    """Open one connection, send a sequence of (possibly split) frames with
    random interleaved reads, then close. Connection errors are expected."""

    try:
        sock: socket.socket = socket.socket(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        sock.settimeout(0.5)
        sock.connect(sock_path)
    except OSError:
        return
    try:
        for fr in frames:
            if rng.random() < 0.3 and len(fr) > 2:
                mid: int = rng.randint(1, len(fr) - 1)
                sock.sendall(fr[:mid])
                time.sleep(rng.uniform(0.0, 0.004))
                sock.sendall(fr[mid:])
            else:
                sock.sendall(fr)
            if rng.random() < 0.35:
                try:
                    sock.recv(512)
                except OSError:
                    pass
        if rng.random() < 0.5:
            try:
                sock.recv(1024)
            except OSError:
                pass
    except OSError:
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


class _Worker(threading.Thread):
    """Runs a batch of random + directed sessions against the comm socket."""

    def __init__(
        self, sock_path: str, count: int, seed: int, alive: Callable[[], bool]
    ) -> None:
        super().__init__(daemon=True)
        self.sock_path = sock_path
        self.count = count
        self.rng = random.Random(seed)
        self.alive = alive
        self.unexpected = 0
        self.ran = 0

    def run(self) -> None:
        for _ in range(self.count):
            if not self.alive():
                return
            try:
                if self.rng.random() < 0.25:
                    frames = [
                        _frame(b)
                        for b in self.rng.choice(DIRECTED)
                    ]
                else:
                    frames = [
                        _random_frame(self.rng)
                        for _ in range(self.rng.randint(1, 5))
                    ]
                _run_session(self.sock_path, frames, self.rng)
            except Exception:  # pylint: disable=broad-exception-caught
                ## _run_session swallows expected socket errors; anything
                ## escaping is an unexpected client-side fault, not a daemon
                ## crash, but worth surfacing.
                self.unexpected += 1
            self.ran += 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="privleap stateful session fuzzer (live daemon)"
    )
    parser.add_argument("--iterations", type=int, default=400)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    seed: int = (
        args.seed if args.seed is not None else random.randrange(1 << 30)
    )

    user: str = current_username()
    try:
        info: pwd.struct_passwd = pwd.getpwnam(user)
    except KeyError:
        print(f"FATAL: caller account '{user}' does not exist.", file=sys.stderr)
        return 2
    if info.pw_uid == 0:
        print("FATAL: refusing to attribute requests to root.", file=sys.stderr)
        return 2

    print("privleap stateful session fuzzer (namespace backend)")
    print(f"caller (attributed) account: {user} (uid {info.pw_uid})")
    print(
        f"seed={seed} iterations={args.iterations} threads={args.threads} "
        f"privleapd={e2e_lib.privleapd_path()}"
    )
    print()

    workdir: str = tempfile.mkdtemp(prefix="privleap-sessfuzz-")
    deny_sentinel: str = os.path.join(workdir, "DENIED_RAN")
    allow_sentinel: str = os.path.join(workdir, "ALLOWED_RAN")

    e2e_lib.mount_tmpfs("/run")
    os.makedirs("/etc/privleap", exist_ok=True)
    e2e_lib.mount_tmpfs("/etc/privleap")
    e2e_lib.write_config("/etc/privleap/conf.d", user, workdir)

    sock_path: str = f"/run/privleapd/comm/{user}"
    log_path: str = os.path.join(workdir, "privleapd.log")
    results: Results = Results()

    # pylint: disable=consider-using-with
    log_handle = open(log_path, "wb")
    proc: subprocess.Popen[bytes] = subprocess.Popen(
        [e2e_lib.privleapd_path(), "--test"],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        env=e2e_lib.daemon_env(),
    )

    def alive() -> bool:
        return proc.poll() is None

    try:
        if not e2e_lib.wait_for_socket(sock_path):
            print("FATAL: privleapd did not create the comm socket in time.")
            return 2

        print(
            f"== fuzzing {args.iterations} sessions across {args.threads} "
            "concurrent workers =="
        )
        ## Distribute exactly args.iterations sessions across the workers so
        ## the reported count is honest even when it does not divide evenly.
        base: int
        remainder: int
        base, remainder = divmod(args.iterations, args.threads)
        workers: list[_Worker] = [
            _Worker(
                sock_path,
                base + (1 if i < remainder else 0),
                seed ^ (i * 0x9E3779B1),
                alive,
            )
            for i in range(args.threads)
        ]
        died_during: bool = False
        for worker in workers:
            worker.start()
        ## Watch liveness while the workers run so a mid-run crash is caught.
        while any(worker.is_alive() for worker in workers):
            if not alive():
                died_during = True
                break
            time.sleep(0.05)
        for worker in workers:
            worker.join(timeout=10)

        total_ran: int = sum(worker.ran for worker in workers)
        unexpected: int = sum(worker.unexpected for worker in workers)

        results.check(
            "daemon never crashed during the session barrage",
            not died_during and alive(),
        )
        results.check(
            "comm socket still present after the barrage",
            os.path.exists(sock_path),
        )
        results.check(
            "unauthorized action NEVER executed during fuzzing (anti-ACE)",
            not os.path.exists(deny_sentinel),
        )
        results.check(
            "no unexpected client-side faults", unexpected == 0
        )

        ## Authorization state must be intact: an authorized action still runs,
        ## an unauthorized one is still denied.
        print("== post-fuzz: authorization state intact ==")
        ## The barrage itself may have run e2e-allow, so clear the sentinel
        ## first; otherwise its mere existence would not prove the post-fuzz
        ## run actually executed the command.
        try:
            os.unlink(allow_sentinel)
        except FileNotFoundError:
            pass
        post_allow, _ = e2e_lib.run_signal(user, "e2e-allow")
        results.check(
            "authorized action still works after fuzzing",
            "RESULT_EXITCODE" in post_allow and os.path.exists(allow_sentinel),
        )
        post_deny, _ = e2e_lib.run_signal(user, "e2e-deny")
        results.check(
            "unauthorized action still denied after fuzzing",
            "UNAUTHORIZED" in post_deny and not os.path.exists(deny_sentinel),
        )
        print(
            f"   ran {total_ran} sessions; daemon alive; "
            f"unexpected faults: {unexpected}"
        )
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # pylint: disable=broad-exception-caught
            proc.kill()
        log_handle.close()
        shutil.rmtree(workdir, ignore_errors=True)

    print()
    code: int = results.report("session fuzzer")
    if code != 0:
        print(f"REPRODUCE: --seed {seed} --iterations {args.iterations} "
              f"--threads {args.threads}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
