#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Unit tests for tb-updater's TOCTOU-safe bind-mount helper (dispvm-bind-mount).

The security-critical part is path resolution: open_nofollow_directory() must
walk every component with O_NOFOLLOW so a symlink ANYWHERE in the path is
refused, never followed. That is what stops a root 'mount --bind' from being
redirected through an attacker-planted symlink. These tests exercise that
resolver directly (no root, no real mount): a real directory resolves to a fd;
a symlink as the final OR an intermediate component is refused (SystemExit via
die()).
"""

import importlib.machinery
import importlib.util
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tb_updater_testlib as T  # noqa: E402

try:
    HELPER = T.dispvm_bind_mount_script()
except SystemExit:
    pytest.skip("tb-updater dispvm-bind-mount not available",
                allow_module_level=True)


def _load_helper():
    """Import the extension-less helper script as a module (its guarded
    __main__ does not run on import)."""
    loader = importlib.machinery.SourceFileLoader("dispvm_bind_mount", HELPER)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


MOD = _load_helper()


def test_resolves_a_real_directory(tmp_path):
    """A path of only real directories resolves to a usable directory fd."""
    target = tmp_path / "a" / "b" / "c"
    target.mkdir(parents=True)
    fd = MOD.open_nofollow_directory(str(target))
    try:
        assert os.path.samestat(os.fstat(fd), os.stat(target))
    finally:
        os.close(fd)


def test_refuses_symlink_final_component(tmp_path):
    """A symlink as the final component is refused, not followed."""
    victim = tmp_path / "victim"
    victim.mkdir()
    link = tmp_path / "link"
    link.symlink_to(victim)
    with pytest.raises(SystemExit) as exc:
        MOD.open_nofollow_directory(str(link))
    assert exc.value.code == 1


def test_refuses_symlink_intermediate_component(tmp_path):
    """A symlink as a non-final component is refused, not followed."""
    real = tmp_path / "real"
    (real / "sub").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(SystemExit) as exc:
        MOD.open_nofollow_directory(str(link / "sub"))
    assert exc.value.code == 1


def test_refuses_relative_path():
    """A non-absolute path is refused outright."""
    with pytest.raises(SystemExit) as exc:
        MOD.open_nofollow_directory("home/user/.tb")
    assert exc.value.code == 1


def _umount_quietly(path):
    subprocess.run(["umount", "--lazy", "--", str(path)],
                   capture_output=True, check=False)


@pytest.mark.skipif(os.geteuid() != 0,
                    reason="real bind mount requires root (sandbox)")
def test_root_binds_real_dir_nosuid_nodev_and_refuses_symlink(tmp_path):
    """End-to-end as root: the helper binds a real directory with nosuid,nodev,
    and refuses a symlinked mount point instead of mounting over its target."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "marker").write_text("tb")

    target = tmp_path / "target"
    target.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    link = tmp_path / "link"
    link.symlink_to(victim)

    try:
        ## Real directory target: bind succeeds, marker is visible, nosuid+nodev.
        proc = subprocess.run([HELPER, str(source), str(target)],
                              capture_output=True, text=True, check=False)
        assert proc.returncode == 0, f"bind failed: {proc.stderr}"
        assert (target / "marker").is_file(), "bind did not expose the source"
        flags = os.statvfs(target).f_flag
        assert flags & os.ST_NOSUID, "mount missing nosuid"
        assert flags & os.ST_NODEV, "mount missing nodev"

        ## Symlinked target: refused, and the victim is NOT mounted over.
        proc = subprocess.run([HELPER, str(source), str(link)],
                              capture_output=True, text=True, check=False)
        assert proc.returncode != 0, "helper followed a symlinked mount point"
        assert not (victim / "marker").exists(), "root followed the symlink"
    finally:
        _umount_quietly(target)
        _umount_quietly(victim)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
