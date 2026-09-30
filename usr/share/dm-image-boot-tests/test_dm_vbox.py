#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for the dm-vbox VirtualBox backend that need no VM.

The real VirtualBox host is not up yet, so these guard the PURE logic that can
be exercised anywhere: VBoxManage argv building, keyboard scancode encoding,
tolerant screen matching + OCR decisions on synthesized PNGs, and Calamares
step sequencing. The functions that actually invoke VBoxManage / tesseract are
deferred to the real host and are not called here.

Loaded the same way dm-image-test's tests load their harness: via
SourceFileLoader, because dm-vbox is an executable with no .py extension.
"""

import importlib.machinery
import importlib.util
import subprocess
from pathlib import Path

import pytest

## PIL (like imagehash below) is only needed for the VirtualBox screenshot
## checks; importorskip so a host without python3-pil skips this module instead
## of aborting pytest collection for every boot-test leg (vbox legs are
## currently disabled, and the CI boot image installs no python3-pil).
Image = pytest.importorskip('PIL.Image')

BACKEND = Path(__file__).resolve().parent / 'dm-vbox'


def _load():
    loader = importlib.machinery.SourceFileLoader(
        'dm_vbox_under_test', str(BACKEND))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


M = _load()


def test_backend_present():
    assert BACKEND.is_file(), f"backend not found: {BACKEND}"


## --- VBoxManage argv builders -----------------------------------------------

def test_screenshot_argv_is_exact():
    ## The headless capture path -- the byte-exact argv the RUN path shells out.
    assert M.build_screenshot_argv('kick', '/t/shot.png') == [
        'VBoxManage', 'controlvm', 'kick', 'screenshotpng', '/t/shot.png']


def test_keyboard_argv_appends_codes():
    ## keyboardputscancode takes each hex byte as its own argv token.
    assert M.build_keyboard_argv('kick', ['1e', '9e']) == [
        'VBoxManage', 'controlvm', 'kick', 'keyboardputscancode', '1e', '9e']


def test_import_and_startvm_argv():
    assert M.build_import_argv('/img/Kicksecure.ova', 'kick') == [
        'VBoxManage', 'import', '/img/Kicksecure.ova', '--vsys', '0',
        '--vmname', 'kick']
    ## Headless boot -- no host GPU/display server.
    assert M.build_startvm_argv('kick') == [
        'VBoxManage', 'startvm', 'kick', '--type', 'headless']


def test_createvm_argv_basefolder_optional():
    assert M.build_createvm_argv('kick', 'Debian_64') == [
        'VBoxManage', 'createvm', '--name', 'kick', '--ostype', 'Debian_64',
        '--register']
    assert '--basefolder' in M.build_createvm_argv(
        'kick', 'Debian_64', basefolder='/vms')


@pytest.mark.parametrize('firmware,expect_value,secure_boot', [
    ('bios', 'bios', False),
    ('efi', 'efi', False),
    ('efi-secureboot', 'efi', True),
])
def test_modifyvm_firmware_mapping(firmware, expect_value, secure_boot):
    ## Harness firmware name -> VBoxManage --firmware value; efi-secureboot also
    ## flips --secure-boot on. A wrong map silently boots the wrong firmware.
    argv = M.build_modifyvm_argv('kick', firmware=firmware)
    idx = argv.index('--firmware')
    assert argv[idx + 1] == expect_value
    assert ('--secure-boot' in argv) is secure_boot


def test_modifyvm_intnet_wins_over_nic():
    ## The Whonix pair isolates on a per-user internal network; intnet must take
    ## precedence and set both --nic1 intnet and the named --intnet1.
    argv = M.build_modifyvm_argv('kick', nic='nat', intnet='dm-user1')
    assert '--intnet1' in argv and 'dm-user1' in argv
    assert argv[argv.index('--nic1') + 1] == 'intnet'
    assert 'nat' not in argv


def test_storage_and_medium_argv():
    assert M.build_storageattach_argv(
        'kick', 'SATA', 0, 0, 'dvddrive', '/img/live.iso') == [
        'VBoxManage', 'storageattach', 'kick', '--storagectl', 'SATA',
        '--port', '0', '--device', '0', '--type', 'dvddrive',
        '--medium', '/img/live.iso']
    assert M.build_createmedium_argv('/vms/d.vdi', 20480) == [
        'VBoxManage', 'createmedium', 'disk', '--filename', '/vms/d.vdi',
        '--size', '20480', '--format', 'VDI']
    assert M.build_storagectl_argv('kick', 'SATA', 'sata', 'IntelAhci') == [
        'VBoxManage', 'storagectl', 'kick', '--name', 'SATA', '--add', 'sata',
        '--controller', 'IntelAhci']
    assert M.build_poweroff_argv('kick') == [
        'VBoxManage', 'controlvm', 'kick', 'poweroff']


def test_vboxmanage_binary_is_overridable():
    ## Every builder threads an overridable binary so a test/host can point it
    ## elsewhere without editing the module.
    assert M.build_screenshot_argv('kick', '/t.png', vboxmanage='/opt/vbm')[0] \
        == '/opt/vbm'


## --- keyboard scancode encoding ---------------------------------------------

def test_encode_scancodes_known_answers():
    ## AT set-1: make byte then break byte (make | 0x80). Hand-verified.
    assert M.encode_scancodes('a') == ['1e', '9e']
    ## Uppercase wraps the key in Left-Shift down/up.
    assert M.encode_scancodes('A') == ['2a', '1e', '9e', 'aa']
    ## A shifted symbol reuses its base key's scancode under Shift.
    assert M.encode_scancodes('!') == ['2a', '02', '82', 'aa']
    assert M.encode_scancodes(' ') == ['39', 'b9']


def test_encode_key_named_and_extended():
    assert M.encode_key('enter') == ['1c', '9c']
    ## Extended (arrow) keys carry the 0xe0 prefix on both make and break.
    assert M.encode_key('up') == ['e0', '48', 'e0', 'c8']


def test_encode_passphrase_round_trips_exactly():
    ## CANARY: the LUKS-unlock path types the passphrase then Enter. This locks
    ## the exact byte stream 'ab'+Enter -> the harness cannot silently emit a
    ## wrong/empty sequence at the encrypted-boot prompt (= lockout).
    assert M.encode_passphrase('ab') == [
        '1e', '9e',   # a
        '30', 'b0',   # b
        '1c', '9c']   # Enter


def test_encode_char_rejects_unmapped():
    ## A character with no US-layout scancode must fail loud, not emit garbage.
    with pytest.raises(ValueError):
        M.encode_char('\t')


## --- screen matching (synthesized PNG fixtures) -----------------------------

def _png(path, size, color):
    Image.new('RGB', size, color).save(path)


def test_screen_matches_identical(tmp_path):
    a = tmp_path / 'a.png'
    b = tmp_path / 'b.png'
    _png(a, (64, 64), (255, 255, 255))
    _png(b, (64, 64), (255, 255, 255))
    assert M.image_diff_ratio(str(a), str(b)) == 0.0
    assert M.screen_matches(str(a), str(b))


def test_screen_matches_rejects_wrong_desktop(tmp_path):
    ## CANARY: a deliberately-wrong screen (white vs black) must NOT match, so a
    ## boot/desktop assertion actually fires instead of passing vacuously.
    a = tmp_path / 'white.png'
    b = tmp_path / 'black.png'
    _png(a, (64, 64), (255, 255, 255))
    _png(b, (64, 64), (0, 0, 0))
    assert M.image_diff_ratio(str(a), str(b)) == pytest.approx(1.0)
    assert not M.screen_matches(str(a), str(b))


def test_screen_matches_tolerant_of_minor_jitter(tmp_path):
    ## A few differing pixels (anti-aliasing/cursor) stay under the tolerance.
    base = tmp_path / 'base.png'
    cand = tmp_path / 'cand.png'
    _png(base, (100, 100), (255, 255, 255))
    img = Image.new('RGB', (100, 100), (255, 255, 255))
    for x in range(10):
        img.putpixel((x, 0), (0, 0, 0))
    img.save(cand)
    assert M.screen_matches(str(base), str(cand))


def test_screen_matches_resizes_on_geometry_change(tmp_path):
    ## Same content at a different resolution is still a match.
    a = tmp_path / 'small.png'
    b = tmp_path / 'big.png'
    _png(a, (32, 32), (10, 120, 200))
    _png(b, (128, 96), (10, 120, 200))
    assert M.screen_matches(str(a), str(b))


def test_phash_distance(tmp_path):
    pytest.importorskip('imagehash')
    a = tmp_path / 'a.png'
    b = tmp_path / 'b.png'
    _png(a, (64, 64), (255, 255, 255))
    _png(b, (64, 64), (255, 255, 255))
    assert M.phash_distance(str(a), str(b)) == 0
    img = Image.new('RGB', (64, 64), (255, 255, 255))
    for y in range(32):
        for x in range(64):
            img.putpixel((x, y), (0, 0, 0))
    img.save(b)
    assert M.phash_distance(str(a), str(b)) > 0


## --- OCR decision -----------------------------------------------------------

def test_ocr_text_contains():
    out = 'Welcome to the\nKicksecure  Installer '
    assert M.ocr_text_contains(out, 'kicksecure installer')
    assert not M.ocr_text_contains(out, 'fatal error')
    ## A list requires every marker to be present.
    assert M.ocr_text_contains(out, ['welcome', 'installer'])
    assert not M.ocr_text_contains(out, ['welcome', 'missing'])


## --- Calamares step sequencing ----------------------------------------------

def _step(seq, name):
    for step in seq:
        if step.name == name:
            return step
    raise AssertionError(f'no step named {name!r} in {[s.name for s in seq]}')


def test_calamares_erase_vs_replace_differ():
    ## CANARY: empty-disk vs reinstall-over-existing must diverge at the
    ## partition page; a mode-insensitive sequence would wipe a disk it should
    ## replace (or vice versa).
    erase = M.calamares_step_sequence('erase')
    replace = M.calamares_step_sequence('replace')
    assert _step(erase, 'partition').action == 'select:erase'
    assert _step(replace, 'partition').action == 'select:replace'


def test_calamares_encrypt_inserts_passphrase_step():
    plain = M.calamares_step_sequence('erase', encrypt=False)
    crypt = M.calamares_step_sequence('erase', encrypt=True)
    assert 'encrypt' not in [s.name for s in plain]
    enc = _step(crypt, 'encrypt')
    assert enc.action == 'type:passphrase'


def test_calamares_sequence_shape():
    seq = M.calamares_step_sequence('erase')
    assert seq[0].name == 'welcome'
    assert seq[-1].name == 'finish'


def test_calamares_rejects_unknown_mode():
    with pytest.raises(ValueError):
        M.calamares_step_sequence('nuke')


## --- CLI (subprocess: the real backend, argv-emit surface) ------------------

def test_cli_emit_screenshot():
    proc = subprocess.run(
        [str(BACKEND), 'emit-argv', '--op', 'screenshot', '--vm', 'kick',
         '--png', '/t/shot.png'],
        capture_output=True, text=True, check=True)
    assert proc.stdout.split('\n')[:5] == [
        'VBoxManage', 'controlvm', 'kick', 'screenshotpng', '/t/shot.png']


def test_cli_emit_keyboard_from_text():
    proc = subprocess.run(
        [str(BACKEND), 'emit-argv', '--op', 'keyboard', '--vm', 'kick',
         '--text', 'a'],
        capture_output=True, text=True, check=True)
    tokens = proc.stdout.split()
    assert tokens == [
        'VBoxManage', 'controlvm', 'kick', 'keyboardputscancode', '1e', '9e']


def test_cli_capabilities_runs():
    proc = subprocess.run(
        [str(BACKEND), 'capabilities'],
        capture_output=True, text=True, check=True)
    assert 'VBoxManage:' in proc.stdout


## dm-image-test's SETUP exit code -- a usage error must map here, never a
## Python traceback (exit 1) and never a silent PASS with a bad argv.
SETUP_RC = 2


def test_cli_keyboard_requires_key_or_text():
    ## CANARY: --op keyboard with neither flag previously crashed with a
    ## TypeError (exit 1). It must be a controlled SETUP error, no traceback.
    proc = subprocess.run(
        [str(BACKEND), 'emit-argv', '--op', 'keyboard', '--vm', 'kick'],
        capture_output=True, text=True, check=False)
    assert proc.returncode == SETUP_RC, (proc.returncode, proc.stderr)
    assert 'Traceback' not in proc.stderr, proc.stderr
    assert '--key' in proc.stderr and '--text' in proc.stderr


@pytest.mark.parametrize('op,flag', [
    ('import', '--ova'),
    ('storageattach', '--medium'),
    ('createmedium', '--medium'),
])
def test_cli_missing_required_flag_is_setup_not_none(op, flag):
    ## CANARY: a missing required path flag previously emitted the literal
    ## 'None' into the argv and still exited 0 (PASS) -- feeding VBoxManage a
    ## path named 'None'. It must fail SETUP with no argv on stdout.
    proc = subprocess.run(
        [str(BACKEND), 'emit-argv', '--op', op, '--vm', 'kick'],
        capture_output=True, text=True, check=False)
    assert proc.returncode == SETUP_RC, (proc.returncode, proc.stdout)
    assert 'None' not in proc.stdout
    assert flag in proc.stderr
