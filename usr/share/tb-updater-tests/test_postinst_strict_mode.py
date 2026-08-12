#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Behavioral guard for the tb-updater postinst maintainer script's strict mode.

The postinst runs under the full strict-mode block (errexit, nounset, pipefail,
errtrace, inherit_errexit, shift_verbose). 'set -o nounset' is the sharp edge:
the script references config variables that are simply UNSET on an ordinary
'apt install' (anon_shared_inst_tb, tb_onion, tb_disable_anon_ws_dns_conf,
tb_reenable_anon_ws_dns_conf; the dpkg DPKG_MAINTSCRIPT_* env; the positional
"$1"). A single unguarded reference aborts the postinst with 'unbound variable'
-- i.e. the package fails to configure. Each such reference must be guarded with
'${var:-}'.

These tests RUN the real shipped postinst end to end under its own strict block
(not a copy, not a grep): the real helper-scripts are required (skip if absent),
and only the root / network externals it shells out to are stubbed on PATH
(adduser, mkdir, ischroot, update-torbrowser, update-mullvadbrowser) -- the
category dist-ai permits stubbing. If a guard is dropped, the run aborts with an
unbound-variable error and the test fails.
"""

import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tb_updater_testlib as T  # noqa: E402

try:
    POSTINST = T.postinst_script()
except SystemExit:
    pytest.skip("tb-updater postinst not available", allow_module_level=True)

## The postinst sources these by absolute path (a dpkg maintainer script has no
## checkout-relative base). They are a real dependency, not something to stub;
## skip honestly when they are not installed.
PRE_BSH = "/usr/libexec/helper-scripts/pre.bsh"
LOG_RUN_DIE = "/usr/libexec/helper-scripts/log_run_die.sh"
if not (os.path.isfile(PRE_BSH) and os.path.isfile(LOG_RUN_DIE)):
    pytest.skip(f"helper-scripts not installed ({PRE_BSH}); skipping",
                allow_module_level=True)

## The postinst's logging shells out to the real stecho / sanitize-string; they
## sit next to sanitize-string, which the testlib resolves from the checkout
## (HELPER_SCRIPTS_PATH) or a system install. Require them -- an ordinary
## postinst run dies early without them.
HELPER_BINDIR = T.sanitize_string_bindir()
if not (HELPER_BINDIR and os.path.isfile(os.path.join(HELPER_BINDIR, "stecho"))
        and os.path.isfile(os.path.join(HELPER_BINDIR, "sanitize-string"))):
    if not (os.path.isfile("/usr/bin/stecho")
            and os.path.isfile("/usr/bin/sanitize-string")):
        pytest.skip("stecho / sanitize-string not available; skipping",
                    allow_module_level=True)
    HELPER_BINDIR = "/usr/bin"

## Config variables that an ordinary 'apt install' leaves unset -- the whole
## point of the nounset audit. Cleared from the child env so a stray value in
## the runner's environment cannot mask a missing guard.
UNSET_VARS = (
    "anon_shared_inst_tb",
    "tb_onion",
    "tb_disable_anon_ws_dns_conf",
    "tb_reenable_anon_ws_dns_conf",
    "DPKG_MAINTSCRIPT_PACKAGE",
    "DPKG_MAINTSCRIPT_NAME",
)

## Root / network externals the postinst shells out to, stubbed so no user is
## created, no /var/cache is touched, and no Tor Browser is downloaded.
## 'ischroot' honours TEST_IN_CHROOT; 'update-torbrowser' honours
## TEST_UPDATE_RC, so a single stub set drives both the chroot and non-chroot
## paths and the download success / failure branches.
STUBS = {
    "adduser": "#!/bin/bash\nexit 0\n",
    "mkdir": "#!/bin/bash\nexit 0\n",
    "ischroot": '#!/bin/bash\n[ "${TEST_IN_CHROOT:-0}" = "1" ] && exit 0\nexit 1\n',
    "update-torbrowser": '#!/bin/bash\nexit "${TEST_UPDATE_RC:-0}"\n',
    "update-mullvadbrowser": '#!/bin/bash\nexit "${TEST_UPDATE_RC:-0}"\n',
}


def _run(tmp_path, arg, extra_env=None):
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    for name, body in STUBS.items():
        path = stub_bin / name
        path.write_text(body)
        path.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in UNSET_VARS}
    ## The postinst's logging (log_run_die.sh) calls the real helper-scripts
    ## binaries stecho / sanitize-string by bare name. When helper-scripts is a
    ## checkout rather than a system install (the CI dist-ai-tests job), they
    ## live in HELPER_SCRIPTS_PATH/usr/bin, not /usr/bin -- put that on PATH so
    ## the REAL tools resolve (the gui_mode_wiring suite does the same).
    path_parts = [str(stub_bin)]
    if HELPER_BINDIR:
        path_parts.append(HELPER_BINDIR)
    env["PATH"] = os.pathsep.join(path_parts + [env.get("PATH", "")])
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", POSTINST, arg],
        capture_output=True, text=True, env=env, check=False)


def _assert_no_unbound(proc):
    combined = proc.stdout + proc.stderr
    assert "unbound variable" not in combined, (
        "postinst hit an unbound variable under 'set -o nounset':\n"
        + combined)


def test_strict_mode_block_present():
    ## Fails on the pre-strict postinst (which carried only 'set -e'): the full
    ## block is the canary that the conversion happened.
    text = T.read(POSTINST)
    for directive in (
        "set -o errexit", "set -o nounset", "set -o pipefail",
        "set -o errtrace", "shopt -s inherit_errexit", "shopt -s shift_verbose",
    ):
        assert directive in text, f"missing strict-mode directive: {directive!r}"


def test_configure_not_in_chroot(tmp_path):
    ## The common case: 'apt install' outside a chroot, every config var unset.
    ## Exercises the BEGIN banner (DPKG_* guards), the download() loop with an
    ## EMPTY chroot_args array under nounset, and the top-level var banners.
    proc = _run(tmp_path, "configure", {"TEST_IN_CHROOT": "0"})
    _assert_no_unbound(proc)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_configure_in_chroot_download_fails(tmp_path):
    ## Chroot path with a failing downloader: reaches the fail branch guard
    ## '[ "${anon_shared_inst_tb:-}" = closed ]' and the tb_disable_anon_ws_dns
    ## / tb_reenable_anon_ws_dns guards, all with the vars unset. Not
    ## anon_shared_inst_tb=closed, so it warns and exits 0.
    proc = _run(tmp_path, "configure",
                {"TEST_IN_CHROOT": "1", "TEST_UPDATE_RC": "1"})
    _assert_no_unbound(proc)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_unknown_argument(tmp_path):
    ## The '*)' branch references ${DPKG_MAINTSCRIPT_NAME:-} and ${1:-}; assert
    ## it fails closed (exit 1) without an unbound-variable abort first.
    proc = _run(tmp_path, "badarg")
    _assert_no_unbound(proc)
    assert proc.returncode == 1, proc.stdout + proc.stderr


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
