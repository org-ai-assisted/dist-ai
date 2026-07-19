#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Live-daemon end-to-end test for privleap, SYSTEMD backend -- the
production-faithful run.

Instead of launching privleapd as a bare subprocess, this drives the REAL
privleapd.service through systemd, so the daemon comes up exactly as it does in
production: Type=notify (the READY handshake must succeed for the start to
return), WatchdogSec, Restart=always, the unit's environment, and any unit
sandboxing. Actions therefore run with the genuine service environment
(NOTIFY_SOCKET, WATCHDOG_USEC, ...), which the namespace backend cannot
reproduce.

Because there can only be one privleapd (it owns /run/privleapd), this MUTATES
the live service: it stops privleapd, moves the real /etc/privleap/conf.d aside,
installs a throwaway test config, starts the service, runs the A/B/C/D security
phases plus a systemd-environment phase, and then restores everything and
restarts the original service. Restoration is registered with atexit and with
SIGINT/SIGTERM handlers, so the live service is brought back even if the run is
interrupted.

The shared security assertions live in e2e_lib. Needs sudo; run it from a
NORMAL user account so requests are attributed to an unprivileged caller
(SUDO_USER). Set PRIVLEAP_REPO to drive a checkout's privleapd under systemd
(installed via a transient drop-in).

  privleap-tests-e2e-systemd
"""

# pylint: disable=too-many-locals,too-many-statements,too-many-branches

import atexit
import os
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
from types import FrameType

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

INSIDE_ENV: str = "PRIVLEAP_E2E_SYSTEMD"
CONF_DIR: str = "/etc/privleap/conf.d"
CONF_BAK: str = "/etc/privleap/conf.d.e2e-bak"
DROPIN_DIR: str = "/etc/systemd/system/privleapd.service.d"
DROPIN_FILE: str = os.path.join(DROPIN_DIR, "e2e-repo.conf")
ETC_ENVIRONMENT: str = "/etc/environment"


def reexec_under_sudo() -> None:
    """Re-exec self under sudo (real root, no namespace) if not already root."""

    if os.geteuid() == 0 and os.environ.get(INSIDE_ENV) == "1":
        return
    if os.geteuid() == 0 and not os.environ.get("SUDO_USER"):
        print(
            "FATAL: run privleap-tests-e2e-systemd from a normal user account "
            "(via sudo), not as root directly, so the daemon can attribute "
            "requests to an unprivileged caller.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    env_args: list[str] = [f"{INSIDE_ENV}=1"]
    if os.environ.get("PRIVLEAP_REPO"):
        env_args.append(f"PRIVLEAP_REPO={os.environ['PRIVLEAP_REPO']}")
    cmd: list[str] = (
        ["sudo", "env"]
        + env_args
        + [sys.executable, os.path.abspath(__file__)]
        + sys.argv[1:]
    )
    os.execvp("sudo", cmd)


reexec_under_sudo()

# pylint: disable=wrong-import-position
import e2e_lib  # noqa: E402
from pl_testlib import Results, current_username  # noqa: E402

e2e_lib.import_target()


def sh(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command capturing text output."""

    return subprocess.run(
        args, check=check, capture_output=True, text=True
    )


def svc_is_active() -> bool:
    return sh(["systemctl", "is-active", "privleapd"], check=False).stdout \
        .strip() == "active"


def svc_nrestarts() -> int:
    out: str = sh(
        ["systemctl", "show", "privleapd", "-p", "NRestarts", "--value"],
        check=False,
    ).stdout.strip()
    try:
        return int(out)
    except ValueError:
        return -1


def svc_prop(name: str) -> str:
    return sh(
        ["systemctl", "show", "privleapd", "-p", name, "--value"], check=False
    ).stdout.strip()


class Restorer:
    """LIFO stack of restore callbacks, fired on normal exit or a signal so the
    live service is always brought back."""

    def __init__(self) -> None:
        self._actions: list[tuple[str, object]] = []
        self._done: bool = False
        atexit.register(self.run)
        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)

    def push(self, label: str, fn: object) -> None:
        self._actions.append((label, fn))

    def _on_signal(self, _sig: int, _frame: FrameType | None) -> None:
        self.run()
        raise SystemExit(130)

    def run(self) -> None:
        if self._done:
            return
        self._done = True
        for label, fn in reversed(self._actions):
            try:
                fn()  # type: ignore[operator]
            except Exception as exc:  # pylint: disable=broad-exception-caught
                print(f"  WARN: restore step '{label}' failed: {exc!r}",
                      file=sys.stderr)


def setup_env_injection(
    user: str, workdir: str, restorer: Restorer
) -> tuple[set[str], str]:
    """Plant env-injection bait in the REAL ~/.pam_environment and
    /etc/environment, backing each up for restore. Returns markers planted and
    the BASH_ENV sentinel path."""

    planted: set[str] = set()
    info: pwd.struct_passwd = pwd.getpwnam(user)
    bashenv_script: str = os.path.join(workdir, "bashenv.sh")
    bashenv_sentinel: str = os.path.join(workdir, "BASHENV_SOURCED")
    with open(bashenv_script, "w", encoding="utf-8") as handle:
        handle.write(f"#!/bin/sh\ntouch {bashenv_sentinel}\n")
    os.chmod(bashenv_script, 0o755)

    pam_env_path: str = os.path.join(info.pw_dir, ".pam_environment")
    if os.path.isdir(info.pw_dir):
        backup: str = os.path.join(workdir, "pam_environment.bak")
        had_file: bool = os.path.exists(pam_env_path)
        if had_file:
            shutil.copy2(pam_env_path, backup)

        def restore_pam() -> None:
            if had_file:
                shutil.move(backup, pam_env_path)
            else:
                if os.path.exists(pam_env_path):
                    os.unlink(pam_env_path)

        restorer.push("~/.pam_environment", restore_pam)
        with open(pam_env_path, "w", encoding="utf-8") as handle:
            handle.write(f"{e2e_lib.INJECT_PAMENV} DEFAULT=injected\n")
            handle.write(f"BASH_ENV DEFAULT={bashenv_script}\n")
            handle.write("LD_PRELOAD DEFAULT=/nonexistent/evil.so\n")
        os.chown(pam_env_path, info.pw_uid, info.pw_gid)
        os.chmod(pam_env_path, 0o600)
        planted.add("pam_environment")

    if os.path.isfile(ETC_ENVIRONMENT):
        env_backup: str = os.path.join(workdir, "etc_environment.bak")
        shutil.copy2(ETC_ENVIRONMENT, env_backup)

        def restore_etcenv() -> None:
            shutil.move(env_backup, ETC_ENVIRONMENT)

        restorer.push("/etc/environment", restore_etcenv)
        with open(ETC_ENVIRONMENT, "a", encoding="utf-8") as handle:
            handle.write(f"\n{e2e_lib.INJECT_ETCENV}=injected\n")
        planted.add("etc_environment")

    return planted, bashenv_sentinel


def install_repo_dropin(repo: str, restorer: Restorer) -> None:
    """Make systemd run the checkout's privleapd with the matching PYTHONPATH,
    via a transient drop-in that is removed on restore."""

    repo_bin: str = os.path.join(repo, "usr/bin/privleapd")
    repo_pp: str = os.path.join(repo, "usr/lib/python3/dist-packages")
    dropin_preexisted: bool = os.path.isdir(DROPIN_DIR)
    os.makedirs(DROPIN_DIR, exist_ok=True)
    with open(DROPIN_FILE, "w", encoding="utf-8") as handle:
        handle.write(
            "[Service]\n"
            "ExecStart=\n"
            f"ExecStart={repo_bin}\n"
            f"Environment=PYTHONPATH={repo_pp}\n"
        )

    def restore_dropin() -> None:
        if os.path.exists(DROPIN_FILE):
            os.unlink(DROPIN_FILE)
        if not dropin_preexisted and os.path.isdir(DROPIN_DIR):
            try:
                os.rmdir(DROPIN_DIR)
            except OSError:
                # best-effort cleanup; the resource may already be gone
                pass
        sh(["systemctl", "daemon-reload"], check=False)

    restorer.push("repo drop-in", restore_dropin)
    sh(["systemctl", "daemon-reload"])


def main() -> int:
    user: str = current_username()
    try:
        info: pwd.struct_passwd = pwd.getpwnam(user)
    except KeyError:
        print(f"FATAL: caller account '{user}' does not exist.", file=sys.stderr)
        return 2
    if info.pw_uid == 0:
        print("FATAL: refusing to attribute requests to root.", file=sys.stderr)
        return 2

    ## The service must exist.
    if sh(["systemctl", "cat", "privleapd"], check=False).returncode != 0:
        print("SKIP: privleapd.service not found on this system.")
        return 77

    repo: str | None = os.environ.get("PRIVLEAP_REPO")
    print("privleap live-daemon e2e test (systemd backend)")
    print(f"caller (attributed) account: {user} (uid {info.pw_uid})")
    print(f"service: privleapd.service (Type={svc_prop('Type')}, "
          f"NotifyAccess={svc_prop('NotifyAccess')}, "
          f"WatchdogUSec={svc_prop('WatchdogUSec')})")
    if repo:
        print(f"PRIVLEAP_REPO={repo} (installed via transient drop-in)")
    print("WARNING: this stops/reconfigures/restarts the real privleapd.service;"
          " it is restored on exit.")
    print()

    workdir: str = tempfile.mkdtemp(prefix="privleap-e2e-sysd-")
    results: Results = Results()
    restorer: Restorer = Restorer()
    restorer.push("rmtree workdir", lambda: shutil.rmtree(
        workdir, ignore_errors=True))

    was_active: bool = svc_is_active()

    ## Bring the service down before swapping its config.
    sh(["systemctl", "stop", "privleapd"], check=False)

    def restart_original() -> None:
        if was_active:
            sh(["systemctl", "start", "privleapd"], check=False)
        else:
            sh(["systemctl", "stop", "privleapd"], check=False)

    restorer.push("restart original service", restart_original)

    ## Displace the real config and install the test config.
    if os.path.exists(CONF_BAK):
        shutil.rmtree(CONF_BAK)
    if os.path.isdir(CONF_DIR):
        shutil.move(CONF_DIR, CONF_BAK)

        def restore_config() -> None:
            if os.path.isdir(CONF_DIR):
                shutil.rmtree(CONF_DIR)
            if os.path.isdir(CONF_BAK):
                shutil.move(CONF_BAK, CONF_DIR)

        restorer.push("restore /etc/privleap/conf.d", restore_config)
    e2e_lib.write_config(CONF_DIR, user, workdir)

    planted, bashenv_sentinel = setup_env_injection(user, workdir, restorer)

    if repo:
        install_repo_dropin(repo, restorer)

    ## Start the real service (Type=notify: this returns only after privleapd
    ## sends READY=1, so a clean start also proves the notify handshake).
    start: subprocess.CompletedProcess[str] = sh(
        ["systemctl", "start", "privleapd"], check=False
    )
    results.check("real privleapd.service started (notify handshake ok)",
                  start.returncode == 0 and svc_is_active())
    if start.returncode != 0:
        print("FATAL: could not start privleapd.service:")
        print(sh(["systemctl", "status", "privleapd", "--no-pager"],
                 check=False).stdout)
        print(sh(["journalctl", "-u", "privleapd", "-n", "30", "--no-pager"],
                 check=False).stdout)
        return results.report("live-daemon e2e (systemd)")

    sock_path: str = f"/run/privleapd/comm/{user}"
    if not e2e_lib.wait_for_socket(sock_path):
        print("FATAL: privleapd did not create the comm socket in time.")
        return results.report("live-daemon e2e (systemd)")

    baseline_restarts: int = svc_nrestarts()

    def alive_check() -> bool:
        ## Restart=always means a crash is masked by an automatic restart;
        ## detect it via NRestarts climbing above the baseline.
        return svc_is_active() and svc_nrestarts() == baseline_restarts

    env_text: str = e2e_lib.run_security_phases(
        user=user,
        sock_path=sock_path,
        workdir=workdir,
        planted=planted,
        bashenv_sentinel=bashenv_sentinel,
        results=results,
        alive_check=alive_check,
    )

    ## E: systemd-environment observations -- the realism payoff. Under the real
    ## service the action inherits the manager's notify/watchdog variables.
    print("== E: real systemd service environment reaches the action ==")
    has_notify: bool = any(
        line.split("=", 1)[0] == "NOTIFY_SOCKET"
        for line in env_text.splitlines()
    )
    results.check(
        "action ran under the real systemd service env (PATH present)",
        any(line.startswith("PATH=") for line in env_text.splitlines()),
    )
    if has_notify:
        print(
            "   NOTE: the action inherited systemd's NOTIFY_SOCKET (and "
            "WATCHDOG_* if set). Not exploitable -- NotifyAccess=main makes "
            "systemd reject notifications from the action's PID -- but "
            "shim.py could scrub these for defence in depth."
        )
    else:
        print("   NOTE: NOTIFY_SOCKET did not reach the action.")
    results.check(
        "no attacker-planted variable in the real systemd action env",
        not any(
            line.split("=", 1)[0] in (e2e_lib.INJECT_PAMENV, e2e_lib.INJECT_ETCENV,
                                      "LD_PRELOAD", "BASH_ENV")
            for line in env_text.splitlines()
        ),
    )

    print()
    code: int = results.report("live-daemon e2e (systemd)")
    ## Restore happens via the Restorer (atexit); report afterwards.
    restorer.run()
    print("restored: original privleapd.service config and state.")
    print(f"service now: {sh(['systemctl', 'is-active', 'privleapd'], check=False).stdout.strip()}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
