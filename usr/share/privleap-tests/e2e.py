#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Live-daemon end-to-end test for privleap. Unlike the in-process harnesses,
this runs the REAL /usr/bin/privleapd as root and talks to it over a REAL
comm socket, proving at the integration level the two things that matter for
"avoid arbitrary code execution":

  A. An UNAUTHORIZED action is NOT executed. A non-root user requesting an
     action restricted to root gets UNAUTHORIZED and the action's command
     never runs (asserted by the absence of a sentinel file). This is the
     anti-ACE invariant, end to end through the genuine socket / auth /
     shim.py / PAM path.

  B. An AUTHORIZED action IS executed and reports success.

  C. A barrage of malformed wire frames does not crash, hang, or corrupt the
     daemon: after the fuzzing it is still alive and STILL enforces A and B.

ISOLATION: the whole test runs inside a private mount namespace (sudo +
unshare --mount) with a fresh tmpfs over /run and over /etc/privleap. The
host's real privleapd, its state dir, and its configuration are therefore
never touched, and all of it disappears automatically when the namespace
exits -- nothing to clean up on the host.

Run it from a NORMAL user account (not root): the harness re-execs itself
under sudo, and attributes requests to the invoking user (SUDO_USER), so the
daemon sees a normal unprivileged caller even though the namespace is root.

  privleap-tests-e2e
"""

# pylint: disable=too-many-locals,too-many-branches,too-many-statements

import os
import pwd
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from types import ModuleType
from typing import Any

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

INSIDE_ENV: str = "PRIVLEAP_E2E_INSIDE"


def reexec_under_namespace() -> None:
    """Re-exec self as root in a private mount namespace via sudo + unshare."""

    if os.geteuid() == 0 and os.environ.get(INSIDE_ENV) == "1":
        return
    if not os.environ.get("SUDO_USER") and os.geteuid() == 0:
        print(
            "FATAL: run privleap-tests-e2e from a normal user account, not "
            "root, so the daemon can attribute requests to an unprivileged "
            "caller.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    env_args: list[str] = [f"{INSIDE_ENV}=1"]
    if os.environ.get("PRIVLEAP_REPO"):
        env_args.append(f"PRIVLEAP_REPO={os.environ['PRIVLEAP_REPO']}")
    cmd: list[str] = (
        ["sudo", "unshare", "--mount", "--propagation", "private", "--", "env"]
        + env_args
        + [sys.executable, os.path.abspath(__file__)]
        + sys.argv[1:]
    )
    os.execvp("sudo", cmd)


reexec_under_namespace()

# pylint: disable=wrong-import-position
from pl_testlib import Results, current_username, import_privleap  # noqa: E402

pl: ModuleType = import_privleap()


def privleapd_path() -> str:
    """Locate the privleapd binary (PRIVLEAP_REPO override, else installed)."""

    repo: str | None = os.environ.get("PRIVLEAP_REPO")
    if repo:
        candidate: str = os.path.join(repo, "usr/bin/privleapd")
        if os.path.isfile(candidate):
            return candidate
    return "/usr/bin/privleapd"


def mount_tmpfs(path: str) -> None:
    subprocess.run(
        ["mount", "-t", "tmpfs", "tmpfs", path], check=True
    )


def write_config(conf_dir: str, user: str, workdir: str) -> None:
    """Write a minimal test config: the caller may run e2e-allow, only root
    may run e2e-deny; both commands drop a distinct sentinel file."""

    os.makedirs(conf_dir, exist_ok=True)
    os.chmod(conf_dir, 0o755)
    allow_sentinel: str = os.path.join(workdir, "ALLOWED_RAN")
    deny_sentinel: str = os.path.join(workdir, "DENIED_RAN")
    config: str = f"""[persistent-users]
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
    conf_path: str = os.path.join(conf_dir, "e2e-test.conf")
    with open(conf_path, "w", encoding="utf-8") as handle:
        handle.write(config)
    os.chown(conf_path, 0, 0)
    os.chmod(conf_path, 0o644)


def wait_for_socket(sock_path: str, timeout_s: float = 8.0) -> bool:
    deadline: float = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if os.path.exists(sock_path):
            return True
        time.sleep(0.05)
    return False


def run_signal(user: str, action: str) -> tuple[list[str], bytes]:
    """Drive a real SIGNAL to completion via the genuine client API; return
    the ordered list of server message type names received and the action's
    concatenated stdout."""

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
            pass
        raw.close()
    except OSError:
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


def daemon_alive(proc: subprocess.Popen[bytes]) -> bool:
    return proc.poll() is None


## Environment variables an attacker would love to smuggle into a root action:
## a code-exec hook for non-interactive bash, the dynamic-linker preload, and a
## plain marker. We plant them in every place an unprivileged user could write
## that a PAM stack *might* read, then prove none of them reach the action.
INJECT_PAMENV: str = "EVIL_PAMENV"
INJECT_ETCENV: str = "EVIL_ETCENV"


def setup_env_injection(user: str, workdir: str) -> tuple[set[str], str]:
    """
    Plant environment-injection attempts in the calling user's
    ~/.pam_environment and in /etc/environment (both isolated to this mount
    namespace), and a BASH_ENV hook script. Returns the set of markers that
    were actually planted and the path of the BASH_ENV sentinel that the hook
    would touch if bash ever sourced it.
    """

    planted: set[str] = set()
    info: pwd.struct_passwd = pwd.getpwnam(user)
    bashenv_script: str = os.path.join(workdir, "bashenv.sh")
    bashenv_sentinel: str = os.path.join(workdir, "BASHENV_SOURCED")
    with open(bashenv_script, "w", encoding="utf-8") as handle:
        handle.write(f"#!/bin/sh\ntouch {bashenv_sentinel}\n")
    os.chmod(bashenv_script, 0o755)

    ## ~/.pam_environment, isolated by a tmpfs over the user's home.
    home: str = info.pw_dir
    if os.path.isdir(home):
        try:
            mount_tmpfs(home)
            os.chown(home, info.pw_uid, info.pw_gid)
            os.chmod(home, 0o700)
            pam_env_path: str = os.path.join(home, ".pam_environment")
            with open(pam_env_path, "w", encoding="utf-8") as handle:
                handle.write(f"{INJECT_PAMENV} DEFAULT=injected\n")
                handle.write(f"BASH_ENV DEFAULT={bashenv_script}\n")
                handle.write("LD_PRELOAD DEFAULT=/nonexistent/evil.so\n")
            os.chown(pam_env_path, info.pw_uid, info.pw_gid)
            os.chmod(pam_env_path, 0o600)
            planted.add("pam_environment")
        except OSError:
            pass

    ## /etc/environment, isolated by bind-mounting a marker file over it (only
    ## if it already exists, so the host is never altered).
    if os.path.isfile("/etc/environment"):
        fake_env: str = os.path.join(workdir, "fake_environment")
        with open(fake_env, "w", encoding="utf-8") as handle:
            handle.write(f"{INJECT_ETCENV}=injected\n")
        try:
            subprocess.run(
                ["mount", "--bind", fake_env, "/etc/environment"], check=True
            )
            planted.add("etc_environment")
        except subprocess.CalledProcessError:
            pass

    return planted, bashenv_sentinel


def main() -> int:
    user: str = current_username()
    try:
        info: pwd.struct_passwd = pwd.getpwnam(user)
    except KeyError:
        print(f"FATAL: caller account '{user}' does not exist.", file=sys.stderr)
        return 2
    if info.pw_uid == 0:
        print(
            "FATAL: refusing to attribute requests to root; run as a normal "
            "user via sudo.",
            file=sys.stderr,
        )
        return 2

    print("privleap live-daemon e2e test")
    print(f"caller (attributed) account: {user} (uid {info.pw_uid})")
    print(f"privleapd: {privleapd_path()}")
    print("(running inside a private mount namespace; host privleapd untouched)")
    print()

    workdir: str = tempfile.mkdtemp(prefix="privleap-e2e-")
    allow_sentinel: str = os.path.join(workdir, "ALLOWED_RAN")
    deny_sentinel: str = os.path.join(workdir, "DENIED_RAN")

    ## Isolate /run and /etc/privleap with fresh tmpfs in this namespace only.
    mount_tmpfs("/run")
    os.makedirs("/etc/privleap", exist_ok=True)
    mount_tmpfs("/etc/privleap")
    write_config("/etc/privleap/conf.d", user, workdir)
    planted, bashenv_sentinel = setup_env_injection(user, workdir)

    sock_path: str = f"/run/privleapd/comm/{user}"
    log_path: str = os.path.join(workdir, "privleapd.log")
    results: Results = Results()

    # pylint: disable=consider-using-with
    log_handle = open(log_path, "wb")
    proc: subprocess.Popen[bytes] = subprocess.Popen(
        [privleapd_path(), "--test"],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    try:
        if not wait_for_socket(sock_path):
            print("FATAL: privleapd did not create the comm socket in time.")
            print("---- privleapd log ----")
            with open(log_path, "r", encoding="utf-8", errors="replace") as lh:
                print(lh.read())
            return 2

        print("== A/B: authorized runs, unauthorized does NOT run ==")
        allow_msgs, _ = run_signal(user, "e2e-allow")
        results.check(
            "authorized action returns TRIGGER", "TRIGGER" in allow_msgs
        )
        results.check(
            "authorized action reports exit code",
            "RESULT_EXITCODE" in allow_msgs,
        )
        results.check(
            "authorized action's command actually ran",
            os.path.exists(allow_sentinel),
        )

        deny_msgs, _ = run_signal(user, "e2e-deny")
        results.check(
            "unauthorized action returns UNAUTHORIZED",
            "UNAUTHORIZED" in deny_msgs,
        )
        results.check(
            "unauthorized action returns no TRIGGER",
            "TRIGGER" not in deny_msgs,
        )
        results.check(
            "unauthorized action's command did NOT run (anti-ACE)",
            not os.path.exists(deny_sentinel),
        )

        print("== C: malformed-frame barrage must not crash/corrupt daemon ==")
        rng: random.Random = random.Random(1)
        corpus: list[bytes] = fuzz_corpus(rng, 250)
        for payload in corpus:
            fuzz_socket_once(sock_path, payload)
            if not daemon_alive(proc):
                break
        results.check("daemon still alive after fuzz barrage",
                      daemon_alive(proc))
        results.check("comm socket still present after barrage",
                      os.path.exists(sock_path))

        ## Re-assert A and B after fuzzing: auth state must be intact.
        if os.path.exists(allow_sentinel):
            os.unlink(allow_sentinel)
        post_allow, _ = run_signal(user, "e2e-allow")
        results.check(
            "authorized action still works after barrage",
            "RESULT_EXITCODE" in post_allow
            and os.path.exists(allow_sentinel),
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
        ## None of the attacker-planted variables may appear in the root
        ## action's environment, and the BASH_ENV hook must never be sourced.
        for marker in (INJECT_PAMENV, INJECT_ETCENV, "LD_PRELOAD", "BASH_ENV"):
            present: bool = any(
                line.split("=", 1)[0] == marker
                for line in env_text.splitlines()
            )
            results.check(
                f"injected '{marker}' absent from root action env",
                not present,
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
        print(
            "   (base env is privleapd's launch env -- here the harness's, in "
            "production systemd's; the assertions above are specifically that "
            "no attacker-planted variable appears in it.)"
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
    return results.report("live-daemon e2e")


if __name__ == "__main__":
    raise SystemExit(main())
