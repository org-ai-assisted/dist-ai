#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Live-daemon end-to-end test for privleap, NAMESPACE backend.

Runs the real /usr/bin/privleapd as a subprocess and a real comm-socket client
inside a PRIVATE MOUNT NAMESPACE (sudo + unshare --mount) with a fresh tmpfs
over /run and /etc/privleap. The host's real privleapd, its state, and its
configuration are therefore never touched, and everything disappears when the
namespace exits -- nothing to clean up on the host. This is the safe,
no-host-mutation backend; for a production-faithful run under the real
privleapd.service use e2e_systemd.py (privleap-tests-e2e-systemd).

The security assertions (A/B/C/D) live in e2e_lib so both backends share them.

Run it from a NORMAL user account (not root): the harness re-execs itself under
sudo and attributes requests to the invoking user (SUDO_USER).

  privleap-tests-e2e
"""

# pylint: disable=too-many-locals

import os
import pwd
import shutil
import subprocess
import sys
import tempfile

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
import e2e_lib  # noqa: E402

e2e_lib.reexec_under_mount_namespace("PRIVLEAP_E2E_INSIDE")

from e2e_lib import INJECT_ETCENV, INJECT_PAMENV  # noqa: E402
from pl_testlib import Results, current_username  # noqa: E402

e2e_lib.import_target()


def setup_env_injection(user: str, workdir: str) -> tuple[set[str], str]:
    """Plant env-injection bait in the calling user's ~/.pam_environment and in
    /etc/environment (both isolated to this namespace -- a tmpfs over the home
    and a bind-mount over /etc/environment), plus a BASH_ENV hook script.
    Returns the markers planted and the BASH_ENV sentinel path."""

    planted: set[str] = set()
    info: pwd.struct_passwd = pwd.getpwnam(user)
    bashenv_script: str = os.path.join(workdir, "bashenv.sh")
    bashenv_sentinel: str = os.path.join(workdir, "BASHENV_SOURCED")
    with open(bashenv_script, "w", encoding="utf-8") as handle:
        handle.write(f"#!/bin/sh\ntouch {bashenv_sentinel}\n")
    os.chmod(bashenv_script, 0o755)

    home: str = info.pw_dir
    if os.path.isdir(home):
        try:
            e2e_lib.mount_tmpfs(home)
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

    print("privleap live-daemon e2e test (namespace backend)")
    print(f"caller (attributed) account: {user} (uid {info.pw_uid})")
    print(f"privleapd: {e2e_lib.privleapd_path()}")
    print("(running inside a private mount namespace; host privleapd untouched)")
    print()

    workdir: str = tempfile.mkdtemp(prefix="privleap-e2e-")

    ## Isolate /run and /etc/privleap with fresh tmpfs in this namespace only.
    e2e_lib.mount_tmpfs("/run")
    os.makedirs("/etc/privleap", exist_ok=True)
    e2e_lib.mount_tmpfs("/etc/privleap")
    e2e_lib.write_config("/etc/privleap/conf.d", user, workdir)
    planted, bashenv_sentinel = setup_env_injection(user, workdir)

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
    try:
        if not e2e_lib.wait_for_socket(sock_path):
            print("FATAL: privleapd did not create the comm socket in time.")
            print("---- privleapd log ----")
            with open(log_path, "r", encoding="utf-8", errors="replace") as lh:
                print(lh.read())
            return 2

        e2e_lib.run_security_phases(
            user=user,
            sock_path=sock_path,
            workdir=workdir,
            planted=planted,
            bashenv_sentinel=bashenv_sentinel,
            results=results,
            alive_check=lambda: proc.poll() is None,
        )
        print(
            "   (base env is privleapd's launch env -- here the harness's, in "
            "production systemd's; the assertions above are specifically that "
            "no attacker-planted variable appears in it. For a run under the "
            "real systemd service env, use privleap-tests-e2e-systemd.)"
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
    return results.report("live-daemon e2e (namespace)")


if __name__ == "__main__":
    raise SystemExit(main())
