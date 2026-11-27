#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for the shared exec-remount helper tb-remount-exec.bsh.

The library is a PURE source-able fragment (functions only, no strict preamble,
no auto-run guard); it is sourced by the PAM session hook (tb-home-remount-exec)
and the Qubes DispVM setup (dispvm). The two consumers are exercised end-to-end
elsewhere; here each function's contract is pinned directly:

  * tb_remount_exec_refuse_symlinks -- returns non-zero (fatal to the caller) on
    a symlink at ANY target, zero otherwise. A missing path is NOT a symlink and
    passes (the dirs may not exist yet at call time).
  * tb_remount_exec_prepare_owner -- mkdir --parents and chown --no-dereference
    owner:owner for each directory.
  * tb_remount_exec_apply -- remounts a directory exec ONLY when its covering
    mount is noexec (the idempotency gate: a second caller, or an already-exec
    dir, must NOT stack another bind mount), dropping noexec while keeping
    nosuid,nodev. A findmnt failure reads as "no noexec seen" -> no-op (the
    launch-time check_noexec backstop refuses a still-noexec home).

The real library is sourced; only the root/system externals (mount, findmnt,
mkdir, chown) are stubbed as shell functions that record their arguments.
"""

import os
import subprocess

import tb_updater_testlib as T

LIB = T.remount_exec_lib()


def _run(body, env=None):
    """Source the REAL library and run `body` against it, strict mode off (the
    library owns no strict preamble, and these fixtures leave vars unset)."""
    script = (
        "set +o errexit +o nounset +o pipefail\n"
        'source "$1" || { echo "SOURCE-FAIL" >&2; exit 3; }\n'
        + body
    )
    child_env = dict(os.environ)
    if env:
        child_env.update(env)
    return subprocess.run(
        ["bash", "-c", script, "bash", LIB],
        capture_output=True,
        text=True,
        env=child_env,
        timeout=60,
        check=False,
    )


def test_refuse_symlinks_passes_plain_and_missing(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    proc = _run(
        f'tb_remount_exec_refuse_symlinks "{real}" "{tmp_path}/missing"\n'
    )
    assert proc.returncode == 0, proc.stderr


def test_refuse_symlinks_rejects_a_symlink(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    link = tmp_path / "link"
    link.symlink_to(victim)
    proc = _run(
        f'tb_remount_exec_refuse_symlinks "{tmp_path}/plain" "{link}"\n'
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "refusing unexpected symlink" in proc.stderr
    assert str(link) in proc.stderr


def test_prepare_owner_creates_and_chowns(tmp_path):
    rec = tmp_path / "rec"
    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    body = (
        'mkdir() { printf "MKDIR %s\\n" "$*" >> "${REC}"; }\n'
        'chown() { printf "CHOWN %s\\n" "$*" >> "${REC}"; }\n'
        f'tb_remount_exec_prepare_owner alice "{d1}" "{d2}"\n'
    )
    proc = _run(body, env={"REC": str(rec)})
    assert proc.returncode == 0, proc.stderr
    text = rec.read_text()
    for d in (d1, d2):
        assert f"MKDIR --parents -- {d}" in text, text
        assert f"CHOWN --no-dereference -- alice:alice {d}" in text, text


def test_apply_remounts_when_noexec(tmp_path):
    rec = tmp_path / "rec"
    body = (
        'findmnt() { printf "rw,noexec,relatime\\n"; }\n'
        "mountpoint() { return 1; }\n"  # not its own mount -> self-bind first
        'mount() { printf "MOUNT %s\\n" "$*" >> "${REC}"; }\n'
        f'tb_remount_exec_apply "{tmp_path}/dir"\n'
    )
    proc = _run(body, env={"REC": str(rec)})
    assert proc.returncode == 0, proc.stderr
    lines = rec.read_text().splitlines()
    assert len(lines) == 2, lines
    assert "--bind" in lines[0], lines
    ## The remount must carry an explicit 'exec' (',exec,' -- never 'noexec') or
    ## the kernel keeps the inherited noexec; also keep nosuid,nodev.
    assert "remount" in lines[1] and "nosuid,nodev" in lines[1], lines
    assert ",exec," in lines[1] and ",noexec," not in lines[1], lines


def test_apply_skips_selfbind_when_already_a_mount(tmp_path):
    ## The Qubes DispVM setup binds the cache onto the dir before calling apply,
    ## so the dir is already its own mount -- apply must NOT stack a second bind,
    ## only remount it exec.
    rec = tmp_path / "rec"
    body = (
        'findmnt() { printf "rw,noexec,relatime\\n"; }\n'
        "mountpoint() { return 0; }\n"  # already its own mount
        'mount() { printf "MOUNT %s\\n" "$*" >> "${REC}"; }\n'
        f'tb_remount_exec_apply "{tmp_path}/dir"\n'
    )
    proc = _run(body, env={"REC": str(rec)})
    assert proc.returncode == 0, proc.stderr
    lines = rec.read_text().splitlines()
    assert len(lines) == 1, lines
    assert "remount" in lines[0] and ",exec," in lines[0], lines


def test_apply_is_noop_when_already_exec(tmp_path):
    rec = tmp_path / "rec"
    rec.write_text("")
    body = (
        'findmnt() { printf "rw,relatime\\n"; }\n'
        'mount() { printf "MOUNT %s\\n" "$*" >> "${REC}"; }\n'
        f'tb_remount_exec_apply "{tmp_path}/dir"\n'
    )
    proc = _run(body, env={"REC": str(rec)})
    assert proc.returncode == 0, proc.stderr
    assert rec.read_text() == "", "must not remount an already-exec directory"


def test_apply_is_noop_when_findmnt_fails(tmp_path):
    rec = tmp_path / "rec"
    rec.write_text("")
    body = (
        "findmnt() { return 1; }\n"
        'mount() { printf "MOUNT %s\\n" "$*" >> "${REC}"; }\n'
        f'tb_remount_exec_apply "{tmp_path}/dir"\n'
    )
    proc = _run(body, env={"REC": str(rec)})
    assert proc.returncode == 0, proc.stderr
    assert rec.read_text() == "", "findmnt failure must read as no-op, not remount"
