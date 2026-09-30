#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: sandbox-update-torbrowser must acquire its self-lock even with no
## systemd-logind (a package-build chroot), i.e. when root has neither an
## XDG_RUNTIME_DIR nor a /run/user/0. It used to die at helper-scripts'
## lockfile.sh with "no per-user runtime dir, cannot create a lock directory!",
## failing the Whonix Workstation image build at 3500_install-packages
## (tb-updater's postinst bundles Tor Browser). The fix provisions root's own
## 0700 /run/user/0 before the lock in that case only.
##
## Faithful: runs the REAL sandbox-update-torbrowser as root (the postinst entry
## point) with /run/user/0 absent. Positive control: the fix must CREATE
## /run/user/0 (proving execution reached the lock) AND the lock error must be
## absent. The script fails later (no Tor Browser download / tb-updater account
## in the test env) -- irrelevant here; only the pre-account self-lock is under
## test.

import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tb_updater_testlib as T  # noqa: E402

try:
    SANDBOX_BIN = T.sandbox_update_torbrowser_script()
except SystemExit:
    pytest.skip("sandbox-update-torbrowser not available",
                allow_module_level=True)

## The fix branch runs only as root (it creates root's /run/user/0); a non-root
## run cannot reproduce the no-logind condition meaningfully.
if os.geteuid() != 0:
    pytest.skip("must run as root to reproduce the no-logind lock condition",
                allow_module_level=True)

## The script sources helper-scripts (wc-test, has, log_run_die, light_sleep,
## lockfile) BEFORE the lock; without them it dies earlier and this test would
## pass vacuously. Require lockfile.sh to be resolvable the same way the script
## resolves it (HELPER_SCRIPTS_PATH prefix, else /usr).
_HS = os.environ.get("HELPER_SCRIPTS_PATH", "").strip()
LOCKFILE = os.path.join(_HS or "/",
                        "usr/libexec/helper-scripts/lockfile.sh")
if not os.path.isfile(LOCKFILE):
    pytest.skip(f"helper-scripts lockfile.sh not available ({LOCKFILE})",
                allow_module_level=True)

## Only meaningful where /run/user/0 is genuinely absent (a build chroot / the CI
## container). On a real logind system it exists and the bug cannot occur; skip
## honestly rather than remove a dir logind owns.
if os.path.isdir("/run/user/0"):
    pytest.skip("/run/user/0 already exists (logind present); cannot reproduce",
                allow_module_level=True)

LOCK_ERROR = "no per-user runtime dir"


def test_self_lock_without_logind():
    """The real script must get past its self-lock with no /run/user/0."""
    try:
        proc = subprocess.run(
            [SANDBOX_BIN, "--postinst"],
            capture_output=True,
            text=True,
            check=False,
            env=dict(os.environ, XDG_RUNTIME_DIR=""),
        )
        output = proc.stdout + proc.stderr
        ## Positive control: the fix must have created root's runtime dir, which
        ## proves execution reached the lock (not an earlier source failure).
        assert os.path.isdir("/run/user/0"), (
            "sandbox-update-torbrowser did not provision /run/user/0 before its "
            f"self-lock; it likely died earlier. Output:\n{output}")
        ## The regression itself: the lock must not have failed.
        assert LOCK_ERROR not in output, (
            "sandbox-update-torbrowser still fails its self-lock without logind "
            f"({LOCK_ERROR!r} present):\n{output}")
    finally:
        shutil.rmtree("/run/user/0", ignore_errors=True)
