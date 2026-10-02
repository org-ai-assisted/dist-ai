#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for the dm-smbios-reader-vbox VirtualBox backend that need no VM.

The real VirtualBox host is not up yet, so these guard the PURE logic that can
be exercised anywhere: VBoxManage argv building, keyboard scancode encoding,
tolerant screen matching + OCR decisions on synthesized PNGs, and Calamares
step sequencing. The functions that actually invoke VBoxManage / tesseract are
deferred to the real host and are not called here.

Loaded the same way dm-smbios-reader-image-test's tests load their harness: via
SourceFileLoader, because dm-smbios-reader-vbox is an executable with no .py extension.
"""

import importlib.machinery
import importlib.util
import subprocess
import types
from pathlib import Path

import pytest

## PIL (like imagehash below) is only needed for the VirtualBox screenshot
## checks; importorskip so a host without python3-pil skips this module instead
## of aborting pytest collection for every boot-test leg (vbox legs are
## currently disabled, and the CI boot image installs no python3-pil).
Image = pytest.importorskip('PIL.Image')

BACKEND = Path(__file__).resolve().parent / 'dm-smbios-reader-vbox'


def _load():
    loader = importlib.machinery.SourceFileLoader(
        'dm_vbox_under_test', str(BACKEND))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


M = _load()

GUESTCTL = Path(__file__).resolve().parent / 'vbox-guestctl'


def _load_guestctl():
    loader = importlib.machinery.SourceFileLoader(
        'vbox_guestctl_under_test', str(GUESTCTL))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


GC = _load_guestctl()


def test_guestctl_text_scancodes():
    ## make+break per char; break = make|0x80. Uppercase + shifted symbols wrap in
    ## Shift make/break; unshifted symbols do not.
    assert GC.text_scancodes('a') == [0x1e, 0x9e]
    assert GC.text_scancodes('B') == [0x2a, 0x30, 0xb0, 0xaa]
    assert GC.text_scancodes(';') == [0x27, 0xa7]
    assert GC.text_scancodes('$') == [0x2a, 0x05, 0x85, 0xaa]
    assert GC.text_scancodes('>') == [0x2a, 0x34, 0xb4, 0xaa]
    assert GC.text_scancodes('') == []


def test_guestctl_text_scancodes_rejects_unmapped():
    ## a non-printable / non-US-keyboard char has no scancode.
    with pytest.raises(ValueError):
        GC.text_scancodes('\t')


def test_guestctl_parser_validates_operands():
    ## argparse gives clean usage/SystemExit, not a raw IndexError/ValueError, on
    ## missing or non-numeric operands.
    parser = GC._build_parser()
    ns = parser.parse_args(['v', 'click', '10', '20'])
    assert (ns.vm, ns.cmd, ns.x, ns.y, ns.button) == ('v', 'click', 10, 20, 1)
    with pytest.raises(SystemExit):
        parser.parse_args(['v'])
    with pytest.raises(SystemExit):
        parser.parse_args(['v', 'click', 'x', 'y'])


def test_guestctl_never_echoes_typed_text():
    ## CWE-532: the typed string may be a LUKS passphrase, so `type` must never
    ## print it back (recoverable from captured output).
    src = GUESTCTL.read_text(encoding='utf-8')
    assert 'type %r' not in src


def test_guestctl_parser_has_type_stdin():
    ## CWE-214: a secret is typed via stdin (type-stdin), never on argv.
    ns = GC._build_parser().parse_args(['v', 'type-stdin'])
    assert ns.cmd == 'type-stdin'


def test_guestctl_click_dwells_between_move_and_press():
    ## Regression: a ZERO-delay move->press->release loses the first click at
    ## 1920x1080 (motion/focus-enter not yet propagated when the button goes
    ## down), so the page never advances. A click MUST dwell after the move and
    ## hold before release. Canary: the old no-sleep sequence emits no sleep
    ## between move and press and fails the order assertion below.
    events: list[tuple] = []

    class FakeMouse:
        def putMouseEventAbsolute(self, x, y, dz, dw, buttons):
            events.append(('mouse', x, y, buttons))

    def fake_sleep(secs):
        assert secs > 0
        events.append(('sleep', secs))

    GC.perform_pointer(FakeMouse(), 10, 20, True, 1, sleep=fake_sleep)
    kinds = [event[0] for event in events]
    ## move(button 0) -> dwell -> press(button 1) -> hold -> release(button 0)
    assert kinds == ['mouse', 'sleep', 'mouse', 'sleep', 'mouse']
    assert events[0] == ('mouse', 10, 20, 0)   # move, no button held
    assert events[2] == ('mouse', 10, 20, 1)   # press, after the dwell
    assert events[4] == ('mouse', 10, 20, 0)   # release, after the hold


def test_guestctl_move_does_not_click_or_dwell():
    ## a bare move just positions the absolute pointer: one event, no button,
    ## no dwell (the dwell only matters when a press follows).
    events: list[tuple] = []

    class FakeMouse:
        def putMouseEventAbsolute(self, x, y, dz, dw, buttons):
            events.append((x, y, buttons))

    def fake_sleep(secs):
        events.append(('sleep', secs))

    GC.perform_pointer(FakeMouse(), 5, 6, False, 1, sleep=fake_sleep)
    assert events == [(5, 6, 0)]


def test_guestctl_env_float_falls_back_on_bad_value(monkeypatch):
    ## a malformed tuning knob must NOT crash the tool (res/shot never dwell);
    ## fall back to the safe default instead of a raw ValueError traceback.
    ## Canary: a reverted fallback raises here instead of returning the default.
    monkeypatch.setenv('VBOX_GUESTCTL_CLICK_SETTLE', 'notanumber')
    assert GC._env_float('VBOX_GUESTCTL_CLICK_SETTLE', 0.3) == 0.3
    monkeypatch.delenv('VBOX_GUESTCTL_CLICK_SETTLE', raising=False)
    assert GC._env_float('VBOX_GUESTCTL_CLICK_SETTLE', 0.3) == 0.3
    monkeypatch.setenv('VBOX_GUESTCTL_CLICK_SETTLE', '0.5')
    assert GC._env_float('VBOX_GUESTCTL_CLICK_SETTLE', 0.3) == 0.5


def test_poweroff_quietly_tolerates_missing_vboxmanage(monkeypatch):
    ## a missing VBoxManage raises FileNotFoundError in the finally; cleanup must
    ## swallow it, not crash over the real exit status.
    def boom(_argv):
        raise FileNotFoundError('VBoxManage')
    monkeypatch.setattr(M, '_run', boom)
    M._poweroff_quietly('kick')


ORCH = Path(__file__).resolve().parents[2] / 'bin' / 'dm-calamares-install'


def test_calamares_install_passphrase_not_on_argv():
    ## CWE-214: the LUKS passphrase is read from a file + piped to type-stdin, never
    ## passed on argv (readable in /proc/PID/cmdline).
    src = ORCH.read_text(encoding='utf-8')
    assert '--passphrase-file' in src
    assert 'type-stdin' in src
    assert 'type "${passphrase}"' not in src


def test_calamares_install_powers_off_only_started_vm():
    ## regression: the exit trap must power off only a VM THIS run started, and both
    ## runners guard poweroff behind the started flag.
    src = ORCH.read_text(encoding='utf-8')
    assert 'vm_started="true"' in src
    assert 'trap on_exit EXIT' in src


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


@pytest.mark.parametrize('firmware,expect_value', [
    ('bios', 'bios'),
    ('efi', 'efi'),
    ('efi-secureboot', 'efi'),
])
def test_modifyvm_firmware_mapping(firmware, expect_value):
    ## Harness firmware name -> VBoxManage --firmware value. A wrong map silently
    ## boots the wrong firmware. modifyvm has NO --secure-boot in VBox 7.x (that
    ## lives in the NVRAM store, build_secureboot_plan), so it must NEVER appear.
    argv = M.build_modifyvm_argv('kick', firmware=firmware)
    idx = argv.index('--firmware')
    assert argv[idx + 1] == expect_value
    assert '--secure-boot' not in argv


def test_secureboot_plan_is_nvram_enroll_then_enable():
    ## VBox 7.x SecureBoot = NVRAM var-store enrollment, in order: init store,
    ## enroll the platform key + MS signatures, THEN enable. A wrong order (enable
    ## before the db is enrolled) leaves an EFI VM that cannot boot a signed shim.
    plan = M.build_secureboot_plan('kick')
    tails = [argv[3:] for argv in plan]
    assert tails == [
        ['inituefivarstore'],
        ['enrollorclpk'],
        ['enrollmssignatures'],
        ['secureboot', '--enable'],
    ]
    assert all(argv[:3] == ['VBoxManage', 'modifynvram', 'kick'] for argv in plan)


def test_install_plan_enrolls_secureboot_only_for_efi_secureboot():
    with_sb = M.build_install_vm_plan('k', '/i.iso', '/d.vdi',
                                      firmware='efi-secureboot')
    without = M.build_install_vm_plan('k', '/i.iso', '/d.vdi', firmware='efi')
    flat_sb = [tok for argv in with_sb for tok in argv]
    flat_no = [tok for argv in without for tok in argv]
    assert 'secureboot' in flat_sb and 'inituefivarstore' in flat_sb
    assert 'secureboot' not in flat_no and 'modifynvram' not in flat_no
    ## Enrollment is spliced AFTER modifyvm (VM exists, firmware efi) and BEFORE
    ## the disk/ISO attach (boot).
    names = [argv[1] for argv in with_sb]
    assert names.index('modifynvram') > names.index('modifyvm')
    assert names.index('modifynvram') < names.index('storageattach')


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


def test_install_vm_plan_composes_efi_iso_and_empty_disk():
    plan = M.build_install_vm_plan(
        'inst', '/img/live.iso', '/vms/inst.vdi',
        firmware='efi-secureboot', memory=4096, disk_mb=25600)
    ## The plan is the exact create->modify->medium->controllers->attach order,
    ## each entry the SAME argv the individual builders emit (no drift).
    assert plan[0] == M.build_createvm_argv('inst', 'Debian_64')
    ## EFI firmware, NAT for the live/installer network. SecureBoot enrollment is
    ## its own NVRAM step-group (test_install_plan_enrolls_secureboot_*), never a
    ## modifyvm flag.
    modify = plan[1]
    assert '--firmware' in modify and 'efi' in modify
    assert '--secure-boot' not in modify
    assert modify[modify.index('--nic1') + 1] == 'nat'
    ## Headless GUI rendering: vmsvga + 128 MiB VRAM, else the LXQt desktop /
    ## Calamares never draw in the software framebuffer (blank wallpaper only).
    assert modify[modify.index('--graphicscontroller') + 1] == 'vmsvga'
    assert modify[modify.index('--vram') + 1] == '128'
    ## Absolute pointer for the host-side IMouse (vboxapi) coordinate-click drive:
    ## usbtablet + a USB controller, so putMouseEventAbsolute works pre-Guest-Additions.
    assert modify[modify.index('--mouse') + 1] == 'usbtablet'
    assert modify[modify.index('--usb-ohci') + 1] == 'on'
    ## Empty target disk sized as requested (after the SecureBoot enroll steps).
    medium = M.build_createmedium_argv('/vms/inst.vdi', 25600)
    assert medium in plan
    ## Target disk on SATA port 0; the ISO as a dvddrive on IDE.
    assert plan[-2] == M.build_storageattach_argv(
        'inst', 'SATA', 0, 0, 'hdd', '/vms/inst.vdi')
    assert plan[-1] == M.build_storageattach_argv(
        'inst', 'IDE', 0, 0, 'dvddrive', '/img/live.iso')


def test_install_vm_plan_threads_vboxmanage_override():
    plan = M.build_install_vm_plan(
        'inst', '/img/live.iso', '/vms/inst.vdi', vboxmanage='/opt/vbm')
    assert all(argv[0] == '/opt/vbm' for argv in plan)


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


## dm-smbios-reader-image-test's SETUP exit code -- a usage error must map here, never a
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


## --- AMD-V availability (pure decision; the deferred host action is not run) --

_CPUINFO_AMD = 'processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel\t\t: 1\n'
_CPUINFO_INTEL = 'processor\t: 0\nvendor_id\t: GenuineIntel\nmodel\t\t: 1\n'

## AMD host, KVM loaded but IDLE (kvm_amd refcount 0 -- no VM holding AMD-V).
_MODULES_KVM_IDLE = (
    'kvm_amd 176128 0 - Live 0x0000000000000000\n'
    'kvm 1146880 1 kvm_amd, Live 0x0000000000000000\n'
    'ccp 126976 1 kvm_amd, Live 0x0000000000000000\n')
## AMD host, a VM is RUNNING (kvm_amd refcount 3).
_MODULES_KVM_BUSY = (
    'kvm_amd 176128 3 - Live 0x0000000000000000\n'
    'kvm 1146880 1 kvm_amd, Live 0x0000000000000000\n')
## No KVM loaded at all.
_MODULES_NO_KVM = 'ext4 1048576 1 - Live 0x0000000000000000\n'


def test_cpu_is_amd():
    assert M.cpu_is_amd(_CPUINFO_AMD) is True
    assert M.cpu_is_amd(_CPUINFO_INTEL) is False
    assert M.cpu_is_amd('') is False


def test_parse_module_refcounts():
    refs = M.parse_module_refcounts(_MODULES_KVM_IDLE)
    assert refs['kvm_amd'] == 0
    assert refs['kvm'] == 1
    assert 'ccp' in refs


def test_kvm_vm_running_from_vendor_refcount():
    assert M.kvm_vm_running(M.parse_module_refcounts(_MODULES_KVM_IDLE)) is False
    assert M.kvm_vm_running(M.parse_module_refcounts(_MODULES_KVM_BUSY)) is True


def test_amd_v_plan_non_amd_is_noop():
    outcome, _msg = M.amd_v_plan(False, M.parse_module_refcounts(
        _MODULES_KVM_IDLE))
    assert outcome == M.AMD_V_NOOP


def test_amd_v_plan_no_kvm_is_noop():
    outcome, _msg = M.amd_v_plan(True, M.parse_module_refcounts(
        _MODULES_NO_KVM))
    assert outcome == M.AMD_V_NOOP


def test_amd_v_plan_idle_kvm_unloads():
    outcome, _msg = M.amd_v_plan(True, M.parse_module_refcounts(
        _MODULES_KVM_IDLE))
    assert outcome == M.AMD_V_UNLOAD


def test_amd_v_plan_running_vm_refuses():
    ## Safety-critical: a live VM must never have AMD-V yanked from under it.
    outcome, _msg = M.amd_v_plan(True, M.parse_module_refcounts(
        _MODULES_KVM_BUSY))
    assert outcome == M.AMD_V_REFUSE


def test_sudo_prefix_root_vs_unprivileged():
    assert M.sudo_prefix(0) == []
    assert M.sudo_prefix(1000) == ['sudo', '--non-interactive']


def test_build_modprobe_remove_argv_vendor_first():
    refs = M.parse_module_refcounts(_MODULES_KVM_IDLE)
    assert M.build_modprobe_remove_argv(refs, 0) == [
        'modprobe', '--remove', '--', 'kvm_amd', 'kvm']
    assert M.build_modprobe_remove_argv(refs, 1000) == [
        'sudo', '--non-interactive', 'modprobe', '--remove', '--',
        'kvm_amd', 'kvm']


def test_cli_parser_accepts_ensure_amd_v():
    ## Parse only -- do NOT dispatch: the real action touches host modules.
    args = M._build_parser().parse_args(['ensure-amd-v'])
    assert args.cmd == 'ensure-amd-v'


## --- serial backend (for dm-smbios-reader-image-test --backend vbox) -----------

_DMI_VENDOR_KEY = 'VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor'
_DMI_SERIAL_KEY = 'VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial'
_DMI_VENDOR_KEY_EFI = 'VBoxInternal/Devices/efi/0/Config/DmiSystemVendor'
_DMI_SERIAL_KEY_EFI = 'VBoxInternal/Devices/efi/0/Config/DmiSystemSerial'


def test_uart_server_argv():
    assert M.build_uart_server_argv('kick', '/run/x.sock') == [
        'VBoxManage', 'modifyvm', 'kick',
        '--uart1', '0x3f8', '4', '--uartmode1', 'server', '/run/x.sock']


def test_dmi_argv_vendor_qemu_and_serial_verbatim():
    serial = 'dm-cmdline=console=ttyS0,115200n8 loglevel=3'
    argvs = M.build_dmi_argv('kick', 'QEMU', serial)  # default firmware=bios
    assert argvs == [
        ['VBoxManage', 'setextradata', 'kick', _DMI_VENDOR_KEY, 'QEMU'],
        ['VBoxManage', 'setextradata', 'kick', _DMI_SERIAL_KEY, serial]]
    ## single commas preserved -- VBox DMI takes the value verbatim (no qemu doubling).
    assert ',,' not in argvs[1][-1]


def test_dmi_argv_firmware_selects_device():
    ## Regression (server integration): EFI/efi-secureboot DMI must go on the 'efi'
    ## device, NOT 'pcbios'. pcbios keys on an EFI VM force-instantiate pcbios, whose
    ## init fails querying BootDevice0 (VERR_CFGM_VALUE_NOT_FOUND) -> power-on dies
    ## before DMI reaches the guest. VERIFIED on VBox 7.2.
    bios = M.build_dmi_argv('kick', 'QEMU', 's', firmware='bios')
    assert bios[0][-2] == _DMI_VENDOR_KEY and bios[1][-2] == _DMI_SERIAL_KEY
    for fw in ('efi', 'efi-secureboot'):
        efi = M.build_dmi_argv('kick', 'QEMU', 's', firmware=fw)
        assert efi[0][-2] == _DMI_VENDOR_KEY_EFI and efi[1][-2] == _DMI_SERIAL_KEY_EFI


def test_storageattach_multiattach_appends_mtype():
    base = M.build_storageattach_argv('kick', 'SATA', 0, 0, 'hdd', '/d.vdi')
    assert '--mtype' not in base  # backward compatible: no mtype by default
    ma = M.build_storageattach_argv('kick', 'SATA', 0, 0, 'hdd', '/d.vdi',
                                    mtype='multiattach')
    assert ma[-2:] == ['--mtype', 'multiattach']


def test_serial_vm_plan_disk_is_multiattach_hdd_no_createmedium():
    plan = M.build_serial_vm_plan(
        'kick', disk='/d.vdi', firmware='efi', uart_socket='/s.sock',
        dmi_vendor='QEMU', dmi_serial='dm-cmdline=x')
    flat = [' '.join(a) for a in plan]
    assert flat[0] == 'VBoxManage createvm --name kick --ostype Debian_64 --register'
    assert 'VBoxManage modifyvm kick --memory 3072 --firmware efi' in flat
    ## firmware='efi' -> DMI on the efi device (not pcbios).
    assert ('VBoxManage setextradata kick %s QEMU' % _DMI_VENDOR_KEY_EFI) in flat
    assert any('--uart1 0x3f8 4 --uartmode1 server /s.sock' in f for f in flat)
    assert any('--type hdd --medium /d.vdi --mtype multiattach' in f for f in flat)
    ## a disk boots the EXISTING image -- never create an empty target medium.
    assert not any('createmedium' in f for f in flat)
    ## plain efi -> no SecureBoot enrollment.
    assert not any('modifynvram' in f for f in flat)


def test_serial_vm_plan_iso_is_dvddrive():
    plan = M.build_serial_vm_plan(
        'kick', iso='/live.iso', firmware='efi', uart_socket='/s.sock',
        dmi_vendor='QEMU', dmi_serial='dm-cmdline=x')
    flat = [' '.join(a) for a in plan]
    assert any('--type dvddrive --medium /live.iso' in f for f in flat)
    assert any('storagectl kick --name IDE --add ide' in f for f in flat)
    assert not any('multiattach' in f for f in flat)


def test_serial_vm_plan_secureboot_spliced_for_efi_secureboot():
    plan = M.build_serial_vm_plan(
        'kick', disk='/d.vdi', firmware='efi-secureboot', uart_socket='/s.sock',
        dmi_vendor='QEMU', dmi_serial='dm-cmdline=x')
    flat = [' '.join(a) for a in plan]
    for step in ('inituefivarstore', 'enrollorclpk', 'enrollmssignatures',
                 'secureboot --enable'):
        assert any(step in f for f in flat), step


def test_serial_vm_plan_requires_exactly_one_medium():
    with pytest.raises(ValueError):
        M.build_serial_vm_plan('kick', uart_socket='/s', dmi_vendor='QEMU',
                               dmi_serial='x')
    with pytest.raises(ValueError):
        M.build_serial_vm_plan('kick', iso='/i', disk='/d', uart_socket='/s',
                               dmi_vendor='QEMU', dmi_serial='x')


def test_cli_serial_up_emit_argv_vendor_qemu_and_media(tmp_path):
    proc = subprocess.run(
        [str(BACKEND), 'serial-up', '--emit-argv', '--vm', 'kick',
         '--disk', '/d.vdi', '--uart-socket', str(tmp_path / 's.sock'),
         '--smbios-serial', 'dm-cmdline=console=ttyS0,115200n8'],
        capture_output=True, text=True)
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    out = proc.stdout
    assert 'DmiSystemVendor QEMU' in out          # default vendor fires the reader
    assert '--uart1 0x3f8 4 --uartmode1 server' in out
    assert '--type hdd --medium /d.vdi --mtype multiattach' in out
    assert 'dm-cmdline=console=ttyS0,115200n8' in out  # single commas, verbatim


def test_cli_serial_up_requires_media_is_setup():
    proc = subprocess.run(
        [str(BACKEND), 'serial-up', '--vm', 'kick', '--uart-socket', '/s',
         '--smbios-serial', 'x'],
        capture_output=True, text=True)
    ## argparse mutually-exclusive-required group rejects (exit 2 == SETUP_RC).
    assert proc.returncode == SETUP_RC, (proc.returncode, proc.stderr)


def test_require_vboxmanage_absent_raises_setup(monkeypatch):
    monkeypatch.setattr(M, 'VBOXMANAGE', 'nonexistent-vboxmanage-xyz')
    with pytest.raises(M.SetupError):
        M.require_vboxmanage()


def test_serial_up_without_vboxmanage_returns_setup(monkeypatch):
    monkeypatch.setattr(M, 'VBOXMANAGE', 'nonexistent-vboxmanage-xyz')
    args = types.SimpleNamespace(
        vm='kick', iso=None, disk='/d.vdi', firmware='efi', memory=3072,
        uart_socket='/s.sock', smbios_serial='dm-cmdline=x', dmi_vendor='QEMU',
        emit_argv=False)
    assert M.run_serial_up(args) == SETUP_RC


def test_hwaccel_in_use_known_answers():
    assert M.hwaccel_in_use('HM: Using AMD-V\nHM: Enabled nested paging\n') is True
    assert M.hwaccel_in_use('00:00:01.1 HM: Using VT-x\n') is True
    assert M.hwaccel_in_use(
        'HM: HMR3Init: Falling back to NEM (Hyper-V active)\n') is False
    assert M.hwaccel_in_use('HM: ... raw-mode ...\n') is False
    assert M.hwaccel_in_use('') is False
    ## Regression (server integration): a REAL VBox 7.2 AMD-V boot log carries the
    ## benign "No raw-mode support in this build!" line AND "Using AMD-V". The old
    ## bare 'raw-mode' fallback marker substring-matched the benign line and refused
    ## a hardware-accelerated run (HwAccelError). Must be True.
    vbox72_amdv = (
        '00:00:00.018331 fHMForced=true - No raw-mode support in this build!\n'
        '00:00:00.029629 HM: HMR3Init: AMD-V w/ nested paging\n'
        '00:00:00.101863 HM: Using AMD-V implementation 2.0\n'
    )
    assert M.hwaccel_in_use(vbox72_amdv) is True
    ## Regression: a boot whose log merely MENTIONS "HMR3Init: AMD-V" while saying it
    ## is unavailable must be False (a bare 'hmr3init: amd-v' positive marker
    ## false-POSITIVEd these). No "using"/"enabled" verb -> no positive marker -> fail;
    ## software fallback is not modelled (it cannot occur -- such a VM never powers on).
    assert M.hwaccel_in_use(
        'HM: HMR3Init: AMD-V is not available, falling back to software virtualization\n') is False
    assert M.hwaccel_in_use(
        'HM: HMR3Init: AMD-V is not supported by the host CPU\n') is False


def test_assert_hwaccel_raises_setup_on_no_amdv(monkeypatch):
    monkeypatch.setattr(M, '_vm_log_text',
                        lambda vm, vboxmanage=M.VBOXMANAGE:
                        'HM: HMR3Init: Falling back to NEM\n')
    with pytest.raises(M.HwAccelError):
        M.assert_hwaccel('kick', timeout=0, interval=0)
    ## HwAccelError maps to SETUP (it is a SetupError), never FAIL.
    assert issubclass(M.HwAccelError, M.SetupError)


def test_assert_hwaccel_passes_on_amdv(monkeypatch):
    monkeypatch.setattr(M, '_vm_log_text',
                        lambda vm, vboxmanage=M.VBOXMANAGE: 'HM: Using AMD-V\n')
    M.assert_hwaccel('kick', timeout=0, interval=0)  # must not raise


def test_start_vm_amd_v_refusal_is_setup_not_fail(monkeypatch):
    ## AMD-V refused (KVM VM running) is SETUP, not a boot FAIL: start_vm must raise
    ## SetupError so the caller maps it to SETUP_RC (2), not FAIL_RC (5).
    monkeypatch.setattr(M, 'ensure_amd_v_available', lambda: M.SETUP_RC)
    with pytest.raises(M.SetupError):
        M.start_vm('kick')


def test_start_vm_powers_off_when_not_hardware_accelerated(monkeypatch):
    ## The hwaccel check runs AFTER power-on; a non-AMD-V boot must be powered back
    ## off (not left running) before start_vm raises HwAccelError.
    monkeypatch.setattr(M, 'ensure_amd_v_available', lambda: M.PASS_RC)
    monkeypatch.setattr(M, '_run', lambda argv: None)
    monkeypatch.setattr(M, '_vm_log_text',
                        lambda vm, vboxmanage=M.VBOXMANAGE:
                        'HM: HMR3Init: Falling back to NEM\n')
    offs = []
    monkeypatch.setattr(M, '_poweroff_quietly', lambda vm: offs.append(vm))
    with pytest.raises(M.HwAccelError):
        M.start_vm('kick')
    assert offs == ['kick']  # powered off before raising


def test_serial_up_tears_down_half_built_vm_on_build_failure(monkeypatch):
    ## A build step failing (e.g. RAW disk rejected for multiattach) must unregister
    ## the half-built VM, else the next serial-up fails at createvm (name in use).
    monkeypatch.setattr(M, 'require_vboxmanage', lambda: None)
    ran = []

    def fake_run(argv):
        ran.append(argv)
        if 'storageattach' in argv:
            raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(M, '_run', fake_run)
    monkeypatch.setattr(M, '_poweroff_quietly', lambda vm: None)
    args = types.SimpleNamespace(
        vm='kick', iso=None, disk='/d.raw', firmware='efi', memory=3072,
        uart_socket='/s.sock', smbios_serial='dm-cmdline=x', dmi_vendor='QEMU',
        emit_argv=False)
    assert M.run_serial_up(args) == M.SETUP_RC
    assert any('unregistervm' in a for a in ran), ran  # teardown unregistered it
