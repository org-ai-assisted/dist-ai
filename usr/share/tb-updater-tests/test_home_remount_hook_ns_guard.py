#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Structural regression tests for the PAM session hook tb-home-remount-exec.

The hook hardcodes /home/<user> and overrides PATH, so a faithful end-to-end
drive is left to the sandbox e2e. These pin the two security properties that
must never silently regress (both FAIL against the pre-guard hook):

  * NAMESPACE GUARD: the hook remounts ONLY when its mount namespace is unshared
    from init (pam_namespace active). Without it, pam_exec runs in the init
    namespace and the bind-remount is system-wide and permanent (close_session
    does not umount), and a user-planted symlink could make an arbitrary noexec
    path exec for the whole system. The guard (compare /proc/self/ns/mnt to
    /proc/1/ns/mnt, exit on equal) must sit BEFORE any remount.
  * The hook must create via the shared helper's prepare_owner (privilege-
    dropped creation, pinned behaviorally in test_remount_exec_lib.py), never a
    direct root mkdir/chown in the hook itself.
"""

import re

import pytest

import tb_updater_testlib as T

try:
    HOOK = T.read(T.home_remount_hook())
except SystemExit:
    pytest.skip("tb-home-remount-exec not available", allow_module_level=True)


def _strip_comments(text: str) -> str:
    ## Drop full-line '##'/'#' comments so a property is asserted on CODE, not a
    ## comment that merely mentions it.
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


CODE = _strip_comments(HOOK)


def test_ns_guard_compares_self_to_init_and_exits():
    ## readlink of both namespace links, compared, with an exit in the equal arm.
    assert re.search(r"readlink\b[^\n]*/proc/self/ns/mnt", CODE), CODE
    assert re.search(r"readlink\b[^\n]*/proc/1/ns/mnt", CODE), CODE
    guard = re.search(
        r"if\s*\[\s*\"\$\(\s*readlink[^\n]*/proc/self/ns/mnt[^\n]*\)\"\s*=\s*"
        r"\"\$\(\s*readlink[^\n]*/proc/1/ns/mnt[^\n]*\)\"\s*\][^\n]*;\s*then"
        r"(?P<body>.*?)\bfi\b",
        CODE,
        re.DOTALL,
    )
    assert guard is not None, "ns guard 'if' not found in hook code"
    assert re.search(r"\bexit\s+0\b", guard.group("body")), guard.group("body")


def test_ns_guard_precedes_the_remount():
    ## The guard must gate the remount: its 'exit 0' skip comes BEFORE the first
    ## tb_remount_exec_apply, or a system-wide remount runs before the check.
    self_ns = CODE.index("/proc/self/ns/mnt")
    apply_at = re.search(r"\btb_remount_exec_apply\b", CODE)
    assert apply_at is not None, "hook never calls tb_remount_exec_apply"
    assert self_ns < apply_at.start(), "ns guard does not precede the remount"


def test_creation_goes_through_prepare_owner_not_direct_root():
    ## Creation is delegated to the shared helper (privilege-dropped there); the
    ## hook must not add its own root mkdir/chown back in.
    assert "tb_remount_exec_prepare_owner" in CODE, CODE
    assert not re.search(r"(^|\s)mkdir\b", CODE), "hook must not mkdir directly"
    assert not re.search(r"(^|\s)chown\b", CODE), "hook must not chown directly"
