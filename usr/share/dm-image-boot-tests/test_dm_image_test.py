#!/usr/bin/python3 -u

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for dm-image-test that need no VM image.

dm-image-boot-tests proper needs a built image and qemu, so it cannot guard
the decode path that killed runs before this file existed: pexpect's default
strict UTF-8 decoding raised UnicodeDecodeError inside wait_for(), which
catches only TIMEOUT/EOF, so a boot run died with a traceback instead of one
of the documented FAIL/SETUP exit codes. read_nonblocking() cuts the serial
stream at a byte count, so a multi-byte character straddling the boundary is
routine rather than exotic.
"""

import importlib.util
import os
import re
import signal
import subprocess
import time
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parent / 'dm-image-test'
DMSERIAL = Path(__file__).resolve().parent / 'debug' / 'dmserial.py'

## dm-image-test's documented FAIL exit code (dm-image-test: FAIL = 5).
FAIL_RC = 5


def test_harness_present():
    assert HARNESS.is_file(), f"harness not found: {HARNESS}"


def test_spawn_asks_for_lenient_decoding():
    """The fix itself: the spawn call must not use pexpect's strict default."""
    source = HARNESS.read_text(encoding='utf-8')
    match = re.search(r'child = pexpect\.spawn\((.*?)\)\n', source, re.DOTALL)
    assert match, 'could not find the pexpect.spawn call in dm-image-test'
    call = match.group(1)
    assert 'encoding="utf-8"' in call, 'spawn should still decode to str'
    assert 'codec_errors="replace"' in call, (
        "spawn must pass codec_errors='replace'; pexpect defaults to strict, "
        'which raises UnicodeDecodeError on a split or invalid byte sequence'
    )


def test_lenient_decoding_survives_invalid_utf8():
    """Behavioural half: the same kwargs really do survive bad bytes."""
    pexpect = pytest.importorskip('pexpect')

    ## Octal escapes, not \x: /bin/sh is dash, whose printf implements the
    ## POSIX \ddd form but passes \xNN through literally -- which would emit
    ## only valid ASCII and let this test pass without ever exercising the
    ## decoder. 0377 is never valid UTF-8; 0303 alone is a truncated two-byte
    ## sequence, the exact shape a read-size cut produces.
    argv = ['/bin/sh', ['-c', r"printf 'start\377\303 end\n'"]]

    def read_all(child):
        chunks = []
        while True:
            try:
                chunks.append(child.read_nonblocking(size=4096, timeout=5))
            except pexpect.EOF:
                return ''.join(chunks)

    strict = pexpect.spawn(*argv, timeout=5, encoding='utf-8')
    with pytest.raises(UnicodeDecodeError):
        ## Guards the premise: without the fix this really does raise, so a
        ## future pexpect that decodes leniently by default cannot let the
        ## test pass vacuously.
        read_all(strict)
    strict.close(force=True)

    lenient = pexpect.spawn(
        *argv, timeout=5, encoding='utf-8', codec_errors='replace'
    )
    text = read_all(lenient)
    lenient.close(force=True)
    assert 'start' in text
    assert 'end' in text
    ## Escape, not the literal glyph: this tree is ASCII-only (R-001).
    assert '\ufffd' in text, 'invalid bytes should decode to the replacement char'


def test_dm_image_test_survives_split_multibyte(tmp_path):
    """End-to-end on the REAL harness: dm-image-test's own read loop must survive
    non-UTF-8 / split multibyte serial bytes and exit with a DOCUMENTED code, not
    a decode traceback.

    Where the two tests above check pexpect's kwargs (the source text, and the
    kwargs on a generic /bin/sh), this drives dm-image-test itself: a stub dm-qemu
    whose emitted 'serial' process prints a truncated two-byte sequence (0303) and
    an invalid byte (0377) then hangs, so the login prompt never appears. With the
    fix the run reads those bytes leniently and ends in FAIL on the deadline; drop
    codec_errors='replace' and read_nonblocking raises UnicodeDecodeError inside
    wait_for() (which catches only TIMEOUT/EOF), turning the run into a traceback."""
    pytest.importorskip('pexpect')
    if not HARNESS.is_file():
        pytest.skip('dm-image-test harness absent')

    ## Stub dm-qemu: ignores every argument and, on the --emit-argv call
    ## dm-image-test makes, prints (one token per line) the argv of a fake serial
    ## source. 0377 is never valid UTF-8; 0303 alone is a truncated two-byte
    ## sequence -- the exact shape a read-size boundary cut produces. dash printf
    ## implements the POSIX octal form, so these become real bytes on the pty.
    stub = tmp_path / 'dm-qemu'
    stub.write_text(
        "#!/bin/bash\n"
        + r'''printf '%s\n' '/bin/sh' '-c' "printf 'start\377\303 end\n'; sleep 30"'''
        + "\n"
    )
    stub.chmod(0o755)
    disk = tmp_path / 'dummy.qcow2'
    disk.write_bytes(b'')

    proc = subprocess.run(
        [str(HARNESS), '--disk', str(disk), '--dm-qemu', str(stub),
         '--timeout', '8'],
        capture_output=True, text=True, timeout=90, check=False,
    )
    tail = proc.stderr[-2000:]
    assert 'UnicodeDecodeError' not in proc.stderr, (
        'dm-image-test died decoding serial bytes (strict decode):\n' + tail)
    assert 'Traceback' not in proc.stderr, (
        'dm-image-test crashed instead of a documented exit:\n' + tail)
    assert proc.returncode == FAIL_RC, (
        'expected documented FAIL=%d (login prompt never appeared), got rc=%d\n'
        'stderr tail:\n%s' % (FAIL_RC, proc.returncode, tail))


def _load_dmserial():
    """Import debug/dmserial.py fresh, so it re-reads $DMSERIAL_WORK."""
    spec = importlib.util.spec_from_file_location('dmserial_under_test',
                                                  DMSERIAL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dmserial_boot_log_survives_the_parent_closing_its_handle(tmp_path,
                                                                 monkeypatch):
    """do_boot hands the boot log to Popen as the child's stdout and closes the
    PARENT's copy at once; the child keeps writing through its own descriptor.

    Guards the whole boot transcript: a restructuring that lets the log handle
    die with the parent (or closes it before Popen dups it) loses every line
    qemu emits after do_boot returns, and dmserial.py has no other capture.
    """
    work = tmp_path / 'work'
    ## A stub dm-qemu: dmserial only asks it to --emit-argv, then runs the
    ## printed argv itself. Sleep first, so EVERY byte of the log is written
    ## after do_boot has returned and the parent's handle is long closed.
    stub = tmp_path / 'dm-qemu-stub'
    stub.write_text(
        '#!/bin/sh\n'
        "printf '%s\\n' /bin/sh -c 'sleep 1; printf AFTER-RETURN'\n",
        encoding='ascii')
    stub.chmod(0o755)
    monkeypatch.setenv('DM_QEMU', str(stub))
    monkeypatch.setenv('DMSERIAL_WORK', str(work))

    dmserial = _load_dmserial()
    image = str(tmp_path / 'disk.qcow2')
    dmserial.do_boot(image, '')

    ## do_boot has returned: nothing in this process holds the log open.
    bootlog = work / 'boot.log'
    pid = int((work / 'dmserial.pid').read_text(encoding='ascii'))
    assert (work / 'image').read_text(encoding='ascii') == image
    try:
        deadline = time.monotonic() + 30
        text = ''
        while time.monotonic() < deadline:
            text = bootlog.read_text(encoding='ascii')
            if 'AFTER-RETURN' in text:
                break
            time.sleep(0.1)
        assert 'AFTER-RETURN' in text, (
            'the child wrote to a boot log the parent had already closed; '
            f'log holds {text!r}')
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            ## The stub child exits on its own; a missing pid here just means
            ## it beat the cleanup, which is not a test failure.
            pass
