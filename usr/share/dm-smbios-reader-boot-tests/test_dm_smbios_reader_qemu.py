#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Contract tests for dm-smbios-reader-qemu --emit-cmdline.

--emit-cmdline is the SINGLE SOURCE of the SMBIOS 'dm-cmdline=' kernel-cmdline
payload: the qemu serial boot path doubles its commas for qemu's -smbios value
parser, and dm-smbios-reader-vbox injects the SAME raw string through VBox DMI
(which takes the value verbatim). These tests pin the payload content AND prove
the two emitters cannot drift -- the emit-argv -smbios value must equal the
emit-cmdline payload with every comma doubled.

Build-only: --emit-cmdline / --emit-argv never boot qemu, so this needs no VM.
Drives the real script in place (no copy), per the dist-ai test convention.
"""

import os
import subprocess
from pathlib import Path

QEMU = Path(__file__).resolve().parent / 'dm-smbios-reader-qemu'
SMBIOS_MARKER = 'type=1,serial=dm-cmdline='

## The pinned --test-console payload (see test_emit_cmdline_test_console_payload).
TEST_CONSOLE_PAYLOAD = (
    'console=ttyS0,115200n8 loglevel=3 systemd.debug_shell=ttyS0'
    ' systemd.mask=serial-getty@ttyS0.service')


def _emit_cmdline(*extra):
    result = subprocess.run(
        [str(QEMU), '--emit-cmdline', '--iso', '/dev/null', '--arch', 'amd64',
         '--test-console', *extra],
        check=True, capture_output=True, text=True)
    return result.stdout.strip('\n')


def _path_without_qemu(tmp_path):
    """A PATH that reproduces the dm-smbios-reader-vbox environment: every tool
    on the real PATH symlinked into one dir EXCEPT qemu-img and qemu-system-*
    (the vbox backend installs no qemu). Nothing else is removed, so the
    --emit-cmdline path cannot fail for a missing legitimate dependency."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    seen = set()
    for entry in os.environ.get('PATH', '').split(os.pathsep):
        if not entry or not os.path.isdir(entry):
            continue
        for name in os.listdir(entry):
            if name in seen:
                continue
            if name == 'qemu-img' or name.startswith('qemu-system-'):
                continue
            try:
                ## Absolute target: a relative PATH entry (e.g. '.') would otherwise
                ## symlink to a relative path that resolves inside bindir -- a self-loop.
                (bindir / name).symlink_to(os.path.abspath(os.path.join(entry, name)))
                seen.add(name)
            except OSError:
                pass
    return str(bindir)


def _emit_argv_smbios(*extra):
    result = subprocess.run(
        [str(QEMU), '--emit-argv', '--iso', '/dev/null', '--arch', 'amd64',
         '--test-console', *extra],
        check=True, capture_output=True, text=True)
    tokens = result.stdout.split('\n')
    ## one token per line; the token AFTER '-smbios' carries the dm-cmdline value.
    value = tokens[tokens.index('-smbios') + 1]
    assert value.startswith(SMBIOS_MARKER), value
    return value[len(SMBIOS_MARKER):]


def test_qemu_present():
    assert QEMU.is_file(), f"dm-smbios-reader-qemu not found: {QEMU}"


def test_emit_cmdline_test_console_payload():
    """The --test-console payload binds a login-free root serial shell and masks
    the getty; pinned so a change to the automation channel is deliberate."""
    assert _emit_cmdline() == TEST_CONSOLE_PAYLOAD


def test_emit_cmdline_appends_smbios_append():
    payload = _emit_cmdline('--smbios-append',
                            'boot-role=sysmaint systemd.unit=sysmaint-boot.target')
    assert payload.startswith('console=ttyS0,115200n8 loglevel=3')
    assert payload.endswith(
        ' boot-role=sysmaint systemd.unit=sysmaint-boot.target')


def test_emit_cmdline_single_commas_emit_argv_doubles():
    """No drift: the emit-argv -smbios value is EXACTLY the emit-cmdline payload
    with every comma doubled (qemu -smbios escaping). The VBox DMI path injects
    the single-comma form, so both backends share one payload source."""
    for extra in ((), ('--smbios-append', 'extra=a,b,c')):
        raw = _emit_cmdline(*extra)
        argv_value = _emit_argv_smbios(*extra)
        assert 'ttyS0,115200n8' in raw          # raw keeps single commas
        assert 'ttyS0,,115200n8' in argv_value  # argv doubles them
        assert argv_value == raw.replace(',', ',,')


def test_emit_cmdline_without_qemu_binary(tmp_path):
    """--emit-cmdline is a pure payload-print path the VBox backend depends on,
    and --backend vbox installs NO qemu. So emitting the cmdline must NOT need
    qemu-system-* on PATH."""
    env = dict(os.environ, PATH=_path_without_qemu(tmp_path))
    result = subprocess.run(
        [str(QEMU), '--emit-cmdline', '--iso', '/dev/null', '--arch', 'amd64',
         '--test-console'],
        env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip('\n') == TEST_CONSOLE_PAYLOAD


def test_emit_cmdline_disk_without_qemu_img(tmp_path):
    """--disk without --disk-format must NOT trigger the qemu-img presence check
    or 'qemu-img info' when only emitting the cmdline: start_vbox_backend passes
    neither --disk-format nor ships qemu-img."""
    env = dict(os.environ, PATH=_path_without_qemu(tmp_path))
    result = subprocess.run(
        [str(QEMU), '--emit-cmdline', '--disk', '/dev/null', '--arch', 'amd64',
         '--test-console'],
        env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip('\n') == TEST_CONSOLE_PAYLOAD


def test_emit_cmdline_still_validates_enum_flags():
    """Skipping qemu setup must NOT skip argument validation: a bad --firmware or
    --accel value is rejected (exit 2) even on the build-only --emit-cmdline path."""
    for bad in (['--firmware', 'definitely-invalid'], ['--accel', 'definitely-invalid']):
        result = subprocess.run(
            [str(QEMU), '--emit-cmdline', '--iso', '/dev/null', '--arch', 'amd64',
             '--test-console', *bad],
            capture_output=True, text=True)
        assert result.returncode == 2, (bad, result.returncode, result.stdout)
