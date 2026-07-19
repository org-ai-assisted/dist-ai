#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Shared logic for the privleap live-daemon end-to-end harnesses.

The security assertions (A: authorized runs, B: unauthorized never executes,
C: a malformed-frame barrage neither crashes nor corrupts the daemon, D: PAM /
environment injection never reaches a root action) are identical regardless of
HOW the daemon is brought up. Two backends share this code:

  * e2e.py          -- privleapd as a subprocess inside a private mount
                       namespace (no host mutation; needs only sudo).
  * e2e_systemd.py  -- the REAL privleapd.service driven by systemd, for a
                       production-faithful run (real Type=notify env, watchdog,
                       unit sandboxing); it mutates and then restores the live
                       service.

A backend builds the config, optionally plants env-injection bait, brings the
daemon up, and calls run_security_phases() with an ``alive_check`` callable
that reports whether the daemon is still healthy (the meaning of "healthy"
differs per backend, so the check is injected).
"""

import os
import random
import socket
import subprocess
import sys
import time
from types import ModuleType
from typing import Any, Callable

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import import_privleap  # noqa: E402


## The privleap library module, set by import_target().
pl: ModuleType


def import_target() -> ModuleType:
    """Import the privleap client library and cache it for run_signal()."""

    global pl  # pylint: disable=global-statement
    pl = import_privleap()
    return pl


def reexec_under_mount_namespace(inside_env_var: str) -> None:
    """Re-exec the calling script as root in a private mount namespace via
    sudo + unshare, unless already inside one. ``inside_env_var`` is the marker
    each backend uses so it does not loop. Run from a normal user account."""

    if os.geteuid() == 0:
        ## Validate we were entered via sudo from a normal user BEFORE trusting
        ## the loop marker, so a stale/exported marker cannot let the suite run
        ## directly as root and skip this guard.
        if not os.environ.get("SUDO_USER"):
            print(
                "FATAL: run this from a normal user account, not root, so the "
                "daemon can attribute requests to an unprivileged caller.",
                file=sys.stderr,
            )
            raise SystemExit(2)
        if os.environ.get(inside_env_var) == "1":
            return
    env_args: list[str] = [f"{inside_env_var}=1"]
    if os.environ.get("PRIVLEAP_REPO"):
        env_args.append(f"PRIVLEAP_REPO={os.environ['PRIVLEAP_REPO']}")
    cmd: list[str] = (
        ["sudo", "unshare", "--mount", "--propagation", "private", "--", "env"]
        + env_args
        + [sys.executable, os.path.abspath(sys.argv[0])]
        + sys.argv[1:]
    )
    os.execvp("sudo", cmd)


def mount_tmpfs(path: str) -> None:
    subprocess.run(["mount", "-t", "tmpfs", "tmpfs", path], check=True)


def privleapd_path() -> str:
    """Locate the privleapd binary (PRIVLEAP_REPO override, else installed)."""

    repo: str | None = os.environ.get("PRIVLEAP_REPO")
    if repo:
        candidate: str = os.path.join(repo, "usr/bin/privleapd")
        if os.path.isfile(candidate):
            return candidate
    return "/usr/bin/privleapd"


def daemon_env() -> dict[str, str]:
    """Environment for the privleapd subprocess: when testing a checkout, give
    the daemon the same module path the in-process client resolved."""

    env: dict[str, str] = dict(os.environ)
    repo: str | None = os.environ.get("PRIVLEAP_REPO")
    if repo:
        repo_pp: str = os.path.join(repo, "usr/lib/python3/dist-packages")
        existing: str = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{repo_pp}{os.pathsep}{existing}" if existing else repo_pp
        )
    return env


## Variables an attacker would love to smuggle into a root action: a code-exec
## hook for non-interactive bash, the dynamic-linker preload, and plain markers.
INJECT_PAMENV: str = "EVIL_PAMENV"
INJECT_ETCENV: str = "EVIL_ETCENV"


def config_text(user: str, workdir: str) -> str:
    """The test privleap configuration: the caller may run e2e-allow and
    e2e-rootenv, only root may run e2e-deny; each command leaves a distinct
    trace."""

    allow_sentinel: str = os.path.join(workdir, "ALLOWED_RAN")
    deny_sentinel: str = os.path.join(workdir, "DENIED_RAN")
    return f"""[persistent-users]
User={user}

[allowed-users]
User={user}

[action:e2e-allow]
Command=touch {allow_sentinel}
AuthorizedUsers={user}

[action:e2e-deny]
Command=touch {deny_sentinel}
AuthorizedUsers=root

[action:e2e-rootenv]
Command=env
AuthorizedUsers={user}
"""


def write_config(conf_dir: str, user: str, workdir: str) -> None:
    """Write the test config into conf_dir as a root-owned 0644 file."""

    os.makedirs(conf_dir, exist_ok=True)
    os.chmod(conf_dir, 0o755)
    conf_path: str = os.path.join(conf_dir, "e2e-test.conf")
    with open(conf_path, "w", encoding="utf-8") as handle:
        handle.write(config_text(user, workdir))
    os.chown(conf_path, 0, 0)
    os.chmod(conf_path, 0o644)


def wait_for_socket(sock_path: str, timeout_s: float = 10.0) -> bool:
    deadline: float = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if os.path.exists(sock_path):
            return True
        time.sleep(0.05)
    return False


def run_signal(user: str, action: str) -> tuple[list[str], bytes]:
    """Drive a real SIGNAL to completion via the genuine client API; return
    the ordered server message-type names and the action's concatenated
    stdout."""

    names: list[str] = []
    stdout: bytearray = bytearray()
    session: Any = pl.PrivleapSession(user, is_control_session=False)
    try:
        session.send_msg(pl.PrivleapCommClientSignalMsg(action))
        while True:
            try:
                msg: Any = session.get_msg()
            except (ConnectionAbortedError, OSError, ValueError):
                break
            names.append(msg.name)
            if msg.name == "RESULT_STDOUT":
                stdout += msg.stdout_bytes
            if msg.name in ("RESULT_EXITCODE", "UNAUTHORIZED", "TRIGGER_ERROR"):
                break
    finally:
        try:
            session.close_session()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    return names, bytes(stdout)


def fuzz_socket_once(sock_path: str, payload: bytes) -> None:
    """Open a raw connection to the comm socket, dump a malformed frame, and
    close. Errors here are the point of the exercise, not failures."""

    try:
        raw: socket.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw.settimeout(0.5)
        raw.connect(sock_path)
        raw.sendall(payload)
        raw.shutdown(socket.SHUT_WR)
        try:
            raw.recv(256)
        except OSError:
            # socket already torn down; teardown is best-effort
            pass
        raw.close()
    except OSError:
        # socket already torn down; teardown is best-effort
        pass


def fuzz_corpus(rng: random.Random, count: int) -> list[bytes]:
    """A batch of malformed frames for the live barrage."""

    def frame(body: bytes) -> bytes:
        return len(body).to_bytes(4, "big") + body

    fixed: list[bytes] = [
        b"",
        b"\x00\x00\x00",
        frame(b"SIGNAL"),
        frame(b"SIGNAL 1 "),
        frame(b"SIGNAL 1  x"),
        frame(b"BOGUS 0"),
        frame(b"SIGNAL 1 ac\x1bt"),
        frame(b"ACCESS_CHECK 0 "),
        frame(b"CREATE 1 root"),
        (5000).to_bytes(4, "big") + b"SIGNAL 1 act",
        (1 << 30).to_bytes(4, "big") + b"x",
    ]
    out: list[bytes] = list(fixed)
    tokens: list[bytes] = [b"SIGNAL", b"ACCESS_CHECK", b"TERMINATE", b"BOGUS"]
    while len(out) < count:
        choice: int = rng.randint(0, 2)
        if choice == 0:
            body_len: int = rng.randint(0, 60)
            out.append(
                rng.randint(0, 1 << 24).to_bytes(4, "big")
                + bytes(rng.getrandbits(8) for _ in range(body_len))
            )
        elif choice == 1:
            tok: bytes = rng.choice(tokens)
            argc: bytes = bytes([rng.choice(b"0123456789AZ!= \x1b")])
            args: bytes = bytes(
                rng.choice(b"-abcAZ09._ ") for _ in range(rng.randint(0, 12))
            )
            out.append(frame(tok + b" " + argc + b" " + args))
        else:
            out.append(frame(bytes(rng.getrandbits(8) for _ in range(
                rng.randint(0, 40)))))
    return out


# pylint: disable=too-many-arguments,too-many-locals,too-many-statements
# pylint: disable=too-many-positional-arguments
def run_security_phases(
    user: str,
    sock_path: str,
    workdir: str,
    planted: set[str],
    bashenv_sentinel: str,
    results: Any,
    alive_check: Callable[[], bool],
    fuzz_count: int = 250,
) -> None:
    """Run the A/B/C/D security phases against an already-running daemon.

    ``alive_check`` returns True while the daemon is healthy; its meaning is
    backend-specific (subprocess liveness, or systemd active + no restart).
    """

    allow_sentinel: str = os.path.join(workdir, "ALLOWED_RAN")
    deny_sentinel: str = os.path.join(workdir, "DENIED_RAN")

    print("== A/B: authorized runs, unauthorized does NOT run ==")
    allow_msgs, _ = run_signal(user, "e2e-allow")
    results.check("authorized action returns TRIGGER", "TRIGGER" in allow_msgs)
    results.check(
        "authorized action reports exit code", "RESULT_EXITCODE" in allow_msgs
    )
    results.check(
        "authorized action's command actually ran",
        os.path.exists(allow_sentinel),
    )

    deny_msgs, _ = run_signal(user, "e2e-deny")
    results.check(
        "unauthorized action returns UNAUTHORIZED", "UNAUTHORIZED" in deny_msgs
    )
    results.check(
        "unauthorized action returns no TRIGGER", "TRIGGER" not in deny_msgs
    )
    results.check(
        "unauthorized action's command did NOT run (anti-ACE)",
        not os.path.exists(deny_sentinel),
    )

    print("== C: malformed-frame barrage must not crash/corrupt daemon ==")
    rng: random.Random = random.Random(1)
    for payload in fuzz_corpus(rng, fuzz_count):
        fuzz_socket_once(sock_path, payload)
        if not alive_check():
            break
    results.check("daemon still alive after fuzz barrage", alive_check())
    results.check(
        "comm socket still present after barrage", os.path.exists(sock_path)
    )

    if os.path.exists(allow_sentinel):
        os.unlink(allow_sentinel)
    post_allow, _ = run_signal(user, "e2e-allow")
    results.check(
        "authorized action still works after barrage",
        "RESULT_EXITCODE" in post_allow and os.path.exists(allow_sentinel),
    )
    post_deny, _ = run_signal(user, "e2e-deny")
    results.check(
        "unauthorized action still denied after barrage",
        "UNAUTHORIZED" in post_deny and not os.path.exists(deny_sentinel),
    )

    print("== D: PAM / env injection must not reach a root action ==")
    print(f"   (planted in: {', '.join(sorted(planted)) or 'nothing'})")
    env_msgs, env_out = run_signal(user, "e2e-rootenv")
    env_text: str = env_out.decode("utf-8", errors="replace")
    results.check(
        "root action ran and returned its environment",
        "RESULT_EXITCODE" in env_msgs and "USER=root" in env_text,
    )
    for marker in (INJECT_PAMENV, INJECT_ETCENV, "LD_PRELOAD", "BASH_ENV"):
        present: bool = any(
            line.split("=", 1)[0] == marker for line in env_text.splitlines()
        )
        results.check(
            f"injected '{marker}' absent from root action env", not present
        )
    results.check(
        "attacker BASH_ENV hook was NOT sourced by the action",
        not os.path.exists(bashenv_sentinel),
    )
    env_keys: list[str] = sorted(
        {
            line.split("=", 1)[0]
            for line in env_text.splitlines()
            if "=" in line
        }
    )
    print(f"   root action received env keys: {', '.join(env_keys)}")
    return env_text
