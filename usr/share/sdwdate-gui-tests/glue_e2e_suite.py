#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
End-to-end harness for the sdwdate-gui Qubes BASH glue -- the one untrusted
surface the Python suite cannot reach:
  etc/qubes-rpc/sdwdate-gui.ConnectCheck
  usr/libexec/sdwdate-gui/sdwdate-gui-qubes-proxy
  usr/libexec/sdwdate-gui/sdwdate-gui-qubes-proxy-helper

Each case runs the REAL script (no synthetic copy) inside
`unshare --user --mount --map-root-user` with a private tmpfs /run, the
checkout's real config-read + scripts bind-mounted over the installed copy, a
crafted /etc/sdwdate-gui.d, and PATH stubs for the qrexec-client-vm /
qubesdb-read externals (qubesdb-read and a live gateway are the only things
that genuinely cannot run here). It then asserts the script's y/n/q verdict,
its EXIT CODE, the qrexec target VM, and the /run side effects (including that
the .Connect endpoint is a SYMLINK to the server socket). This pins the fixes
for issues #7 (ln -s --force restart-safety), #9 (2>/dev/null, no stderr
false-disable) and #12 (ConnectCheck gives up when run_server_in_qubes is not
true), and fuzzes the proxy's ConnectCheck-result handling for new
false-disable / hang edges.

NOT discovered by the core/coverage runners (they use --pattern 'test_*.py';
this module is deliberately NOT so named). The glue entrypoint runs it
explicitly through run-unittest.py.
"""

# pylint: disable=invalid-name,subprocess-run-check

import base64
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.join(HERE, "qubes_glue_runner.bash")
MKSOCK = os.path.join(HERE, "glue_mksock")

## GLUE_UID is pinned to 0 (mapped-root in the userns), so the gateway server
## socket the proxy-helper symlinks .Connect to is this fixed path.
SERVER_SOCK = "/run/user/0/sdwdate-gui/sdwdate-gui-server.socket"
GATEWAY = "sys-whonix"


def _subject() -> str:
    repo = os.environ.get("SDWDATE_GUI_REPO", "").rstrip("/")
    pkg = "usr/lib/python3/dist-packages/sdwdate_gui"
    if repo and os.path.isdir(os.path.join(repo, pkg)):
        return repo
    return ""


SUBJECT = _subject()

QREXEC_STUB = """#!/bin/bash
## Stateful qrexec-client-vm stub. $1=target_vm $2=service.
## Records every call's target VM (one per line) so the test can assert the
## proxy talks to the CONFIGURED gateway, not an attacker VM.
## ConnectCheck: 1st call emits GLUE_CC_OUT/RC (+optional stderr), later calls
## emit GLUE_CC_OUT2/RC2 (default 'q') so an 'n' retry terminates.
## Connect: records that the proxy tried to proxy to the gateway.
printf '%s\\n' "$1" >> /run/.qrexec_targets
svc="$2"
case "${svc}" in
  sdwdate-gui.ConnectCheck)
    n=0; [ -f /run/.cc_calls ] && n="$(cat /run/.cc_calls)"
    printf '%s' "$((n + 1))" > /run/.cc_calls
    [ -n "${GLUE_CC_STDERR:-}" ] && printf '%s' "${GLUE_CC_STDERR}" >&2
    if [ "${n}" -eq 0 ]; then
      printf '%s' "${GLUE_CC_OUT:-}"; exit "${GLUE_CC_RC:-0}"
    fi
    printf '%s' "${GLUE_CC_OUT2:-q}"; exit "${GLUE_CC_RC2:-0}"
    ;;
  sdwdate-gui.Connect)
    : > /run/.connect_called; exit 0
    ;;
esac
exit 0
"""

QUBESDB_STUB = """#!/bin/bash
printf '%s\\n' "${GLUE_DEFAULT_USER:-root}"
"""

## A no-op systemd_notify so the socket-activated proxy can source it and call
## `--ready` with no live systemd. Bound over the real helper-scripts file.
SYSTEMD_NOTIFY_STUB = "systemd_notify=(true)\n"


def _clean_env() -> dict[str, str]:
    ## Drop GLUE_* (so no ambient GLUE_* steers a result) and BASH_ENV / ENV /
    ## exported shell functions (so an inherited `mount`/`mkdir` shadow cannot
    ## run in the runner before the real binaries, and pollute the host /run).
    return {
        k: v for k, v in os.environ.items()
        if not k.startswith(("GLUE_", "BASH_FUNC_"))
        and k not in ("BASH_ENV", "ENV")
    }


def _userns_available() -> bool:
    try:
        res = subprocess.run(
            ["unshare", "--user", "--mount", "--map-root-user",
             "bash", "-c", "mount -t tmpfs tmpfs /run"],
            capture_output=True, env=_clean_env(),
        )
        return res.returncode == 0
    except OSError:
        return False


class GlueCase:
    """Parsed result of one glue-script run."""

    def __init__(self, raw: str) -> None:
        self.rc = -1
        self.out = ""
        self.flags: dict[str, int] = {}
        self.connect_link_target = ""
        self.qrexec_targets: list[str] = []
        for line in raw.splitlines():
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            if key == "RESULT_RC":
                self.rc = int(val)
            elif key == "RESULT_OUT_B64":
                self.out = base64.b64decode(val).decode("ascii", "replace")
            elif key == "CONNECT_LINK_TARGET_B64":
                self.connect_link_target = base64.b64decode(val).decode(
                    "ascii", "replace")
            elif key == "QREXEC_TARGETS_B64":
                text = base64.b64decode(val).decode("ascii", "replace")
                self.qrexec_targets = text.split("\n") if text else []
            elif key in (
                "PROXY_SHOULD_RUN", "SHOULD_PROXY_FLAG", "DISABLED_FLAG",
                "CONNECT_ENDPOINT", "CONNECT_CALLED", "CONNECT_IS_SYMLINK",
            ):
                self.flags[key] = int(val)


@unittest.skipUnless(SUBJECT, "SDWDATE_GUI_REPO not set to a checkout")
@unittest.skipUnless(_userns_available(), "user namespaces unavailable")
class QubesGlueE2E(unittest.TestCase):
    """Drive the real glue scripts; assert y/n/q, exit, and side effects."""

    def run_glue(
        self,
        script_rel: str,
        conf: str,
        *,
        cc_out: str = "",
        cc_rc: int = 0,
        cc_out2: str = "q",
        cc_rc2: int = 0,
        cc_stderr: str = "",
        default_user: str = "root",
        precreate_connect: bool = False,
        precreate_connect_symlink: bool = False,
        precreate_server_sock: bool = False,
        precreate_proxy_flag: bool = False,
    ) -> GlueCase:
        tmp = tempfile.mkdtemp(prefix="glue.")
        self.addCleanup(_rmtree, tmp)
        confdir = os.path.join(tmp, "etc")
        stubdir = os.path.join(tmp, "bin")
        os.makedirs(confdir)
        os.makedirs(stubdir)
        with open(os.path.join(confdir, "50_test.conf"), "w") as fh:
            fh.write(conf)
        _write_exec(os.path.join(stubdir, "qrexec-client-vm"), QREXEC_STUB)
        _write_exec(os.path.join(stubdir, "qubesdb-read"), QUBESDB_STUB)
        notify_stub = os.path.join(tmp, "systemd-notify.bsh")
        with open(notify_stub, "w") as fh:
            fh.write(SYSTEMD_NOTIFY_STUB)

        ## Start from a sanitized environment (no ambient GLUE_* / BASH_ENV /
        ## exported functions); every input the runner/stubs read is set here.
        env = _clean_env()
        env.update(
            GLUE_SCRIPT=os.path.join(SUBJECT, script_rel),
            GLUE_SUBJECT=SUBJECT,
            GLUE_STUBDIR=stubdir,
            GLUE_CONFDIR=confdir,
            GLUE_MKSOCK=MKSOCK,
            GLUE_UID="0",
            GLUE_SYSTEMD_NOTIFY_STUB=notify_stub,
            GLUE_CC_OUT=cc_out,
            GLUE_CC_RC=str(cc_rc),
            GLUE_CC_OUT2=cc_out2,
            GLUE_CC_RC2=str(cc_rc2),
            GLUE_CC_STDERR=cc_stderr,
            GLUE_DEFAULT_USER=default_user,
            GLUE_PRECREATE_CONNECT="1" if precreate_connect else "0",
            GLUE_PRECREATE_CONNECT_SYMLINK=(
                "1" if precreate_connect_symlink else "0"
            ),
            GLUE_PRECREATE_SERVER_SOCK="1" if precreate_server_sock else "0",
            GLUE_PRECREATE_PROXY_FLAG="1" if precreate_proxy_flag else "0",
        )
        res = subprocess.run(
            ["unshare", "--user", "--mount", "--map-root-user",
             "bash", RUNNER],
            capture_output=True, text=True, env=env, timeout=120,
        )
        self.assertEqual(
            res.returncode, 0,
            f"runner failed rc={res.returncode}\nstdout={res.stdout}\n"
            f"stderr={res.stderr}",
        )
        return GlueCase(res.stdout)

    ## --- ConnectCheck (gateway): y / n / q ---------------------------------
    CC = "etc/qubes-rpc/sdwdate-gui.ConnectCheck"

    def test_connectcheck_socket_present_is_y(self) -> None:
        c = self.run_glue(self.CC, "disable=false\n", precreate_connect=True)
        self.assertEqual(c.out, "y")
        self.assertEqual(c.rc, 0)

    def test_connectcheck_cached_flag_is_n(self) -> None:
        c = self.run_glue(
            self.CC, "disable=false\nrun_server_in_qubes=false\n",
            precreate_proxy_flag=True,
        )
        self.assertEqual(c.out, "n")
        self.assertEqual(c.rc, 0)

    def test_connectcheck_enabled_is_n_and_caches(self) -> None:
        c = self.run_glue(
            self.CC, "disable=false\nrun_server_in_qubes=true\n"
        )
        self.assertEqual(c.out, "n")
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["PROXY_SHOULD_RUN"], 1)

    def test_connectcheck_run_server_false_is_q(self) -> None:
        ## Issue #12: run_server_in_qubes=false must give up ('q'), not 'n'.
        c = self.run_glue(
            self.CC, "disable=false\nrun_server_in_qubes=false\n"
        )
        self.assertEqual(c.out, "q")
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["PROXY_SHOULD_RUN"], 0)

    def test_connectcheck_disabled_is_q(self) -> None:
        c = self.run_glue(
            self.CC, "disable=true\nrun_server_in_qubes=true\n"
        )
        self.assertEqual(c.out, "q")
        self.assertEqual(c.rc, 0)

    def test_connectcheck_run_server_unset_is_q(self) -> None:
        c = self.run_glue(self.CC, "disable=false\n")
        self.assertEqual(c.out, "q")
        self.assertEqual(c.rc, 0)

    ## --- proxy (workstation): ConnectCheck-result handling -----------------
    PROXY = "usr/libexec/sdwdate-gui/sdwdate-gui-qubes-proxy"

    def test_proxy_y_connects(self) -> None:
        c = self.run_glue(self.PROXY, 'gateway="sys-whonix"\n', cc_out="y")
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["CONNECT_CALLED"], 1)
        self.assertEqual(c.flags["DISABLED_FLAG"], 0)
        ## Every qrexec call must target the CONFIGURED gateway.
        self.assertTrue(c.qrexec_targets)
        self.assertEqual(set(c.qrexec_targets), {GATEWAY})

    def test_proxy_q_disables(self) -> None:
        c = self.run_glue(self.PROXY, 'gateway="sys-whonix"\n', cc_out="q")
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["CONNECT_CALLED"], 0)
        self.assertEqual(c.flags["DISABLED_FLAG"], 1)

    def test_proxy_y_with_stderr_still_connects(self) -> None:
        ## Issue #9: stderr on an otherwise-'y' must NOT false-disable
        ## (the call is now 2>/dev/null).
        c = self.run_glue(
            self.PROXY, 'gateway="sys-whonix"\n',
            cc_out="y", cc_stderr="qrexec-client-vm: a notice\n",
        )
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["CONNECT_CALLED"], 1)
        self.assertEqual(c.flags["DISABLED_FLAG"], 0)
        self.assertEqual(set(c.qrexec_targets), {GATEWAY})

    def test_proxy_n_then_q_keeps_waiting_then_disables(self) -> None:
        c = self.run_glue(
            self.PROXY, 'gateway="sys-whonix"\n', cc_out="n", cc_out2="q"
        )
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["CONNECT_CALLED"], 0)
        self.assertEqual(c.flags["DISABLED_FLAG"], 1)

    def test_proxy_garbage_disables(self) -> None:
        c = self.run_glue(
            self.PROXY, 'gateway="sys-whonix"\n', cc_out="unexpected"
        )
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["CONNECT_CALLED"], 0)
        self.assertEqual(c.flags["DISABLED_FLAG"], 1)

    ## --- proxy-helper (gateway/workstation): enable / symlink --------------
    HELPER = "usr/libexec/sdwdate-gui/sdwdate-gui-qubes-proxy-helper"

    def test_helper_workstation_drops_proxy_flag(self) -> None:
        c = self.run_glue(self.HELPER, "run_server_in_qubes=false\n")
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["SHOULD_PROXY_FLAG"], 1)

    def test_helper_disabled_exits_without_symlink(self) -> None:
        c = self.run_glue(
            self.HELPER, "run_server_in_qubes=true\ndisable=true\n"
        )
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["CONNECT_ENDPOINT"], 0)
        self.assertEqual(c.flags["CONNECT_IS_SYMLINK"], 0)

    def test_helper_creates_connect_symlink(self) -> None:
        c = self.run_glue(
            self.HELPER, "run_server_in_qubes=true\ndisable=false\n",
            precreate_server_sock=True,
        )
        self.assertEqual(c.rc, 0)
        ## #6: the endpoint must be a SYMLINK to the server socket, not merely
        ## a path that exists (a bare `touch` would satisfy existence).
        self.assertEqual(c.flags["CONNECT_IS_SYMLINK"], 1)
        self.assertEqual(c.connect_link_target, SERVER_SOCK)

    def test_helper_restart_safe_over_stale_symlink(self) -> None:
        ## Issue #7: `ln -s --force` must overwrite a pre-existing endpoint on
        ## restart, not fail the unit (the old `ln -s` without -f did).
        c = self.run_glue(
            self.HELPER, "run_server_in_qubes=true\ndisable=false\n",
            precreate_server_sock=True, precreate_connect_symlink=True,
        )
        self.assertEqual(c.rc, 0)
        self.assertEqual(c.flags["CONNECT_IS_SYMLINK"], 1)
        self.assertEqual(c.connect_link_target, SERVER_SOCK)


def _write_exec(path: str, content: str) -> None:
    with open(path, "w") as fh:
        fh.write(content)
    os.chmod(path, 0o755)


def _rmtree(path: str) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
