#!/usr/bin/python3 -Bsu

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

import importlib.machinery
import importlib.util
import json
import os
import re
import signal
import socket
import subprocess
import threading
import time
import types
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parent / 'dm-image-test'
DMSERIAL = Path(__file__).resolve().parent / 'debug' / 'dmserial.py'

## dm-image-test's documented exit codes (PASS = 0, FAIL = 5, SETUP = 2). The
## contract is EXACTLY these three: an uncaught exception (exit 1) breaks it.
FAIL_RC = 5
SETUP_RC = 2


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
    assert spec is not None and spec.loader is not None
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


## --- Qmp reply-id correlation (dm-qemu-screendump-watch) --------------------
## A screendump whose recv times out leaves its reply pending; without id
## correlation the NEXT command reads that late reply and every subsequent
## command is off-by-one -> a silently WRONG boot verdict. The client now tags
## each command with a monotonic id and correlates the reply.

SCREENDUMP_WATCH = Path(__file__).resolve().parent / 'dm-qemu-screendump-watch'


def _load_qmp():
    ## The script has no .py extension, so an explicit SourceFileLoader is needed
    ## (spec_from_file_location cannot infer a loader and returns None).
    loader = importlib.machinery.SourceFileLoader(
        'screendump_watch_under_test', str(SCREENDUMP_WATCH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module.Qmp


class _MockQmpServer:
    ## Minimal AF_UNIX QMP server: greeting on connect, auto-answers
    ## qmp_capabilities, then defers to responder(cmd) -> list of reply dicts.
    def __init__(self, path, responder):
        self.responder = responder
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(str(path))
        self.srv.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.srv.accept()
        except OSError:
            return
        try:
            conn.sendall(b'{"QMP": {"version": {}}}\n')
            buf = b""
            while True:
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                line, buf = buf.split(b"\n", 1)
                cmd = json.loads(line.decode("utf-8"))
                if cmd.get("execute") == "qmp_capabilities":
                    replies = [{"return": {}, "id": cmd.get("id")}]
                else:
                    replies = self.responder(cmd)
                for reply in replies:
                    conn.sendall((json.dumps(reply) + "\n").encode("utf-8"))
        except (OSError, ValueError):
            pass
        finally:
            conn.close()

    def close(self):
        try:
            self.srv.close()
        except OSError:
            pass


def _qmp_client(tmp_path, responder):
    server = _MockQmpServer(tmp_path / "q.sock", responder)
    return _load_qmp()(str(tmp_path / "q.sock"), time.time() + 5), server


def test_qmp_correlates_reply_by_id(tmp_path):
    ## Each command's reply echoes its id; command() returns the matching reply.
    client, server = _qmp_client(
        tmp_path, lambda cmd: [{"return": {"seen": cmd["execute"]}, "id": cmd["id"]}])
    try:
        reply = client.command("screendump", {"filename": "x"})
        assert reply["return"] == {"seen": "screendump"}
    finally:
        client.close()
        server.close()


def test_qmp_drains_stale_reply_after_timeout(tmp_path):
    ## Model a desync: a prior command's LATE reply (an earlier id) precedes this
    ## command's reply on the wire. command() must DRAIN the stale one and return
    ## THIS command's reply, never misattribute the stale frame.
    def responder(cmd):
        cur = cmd["id"]
        return [{"return": {"stale": True}, "id": cur - 1},
                {"return": {"fresh": True}, "id": cur}]
    client, server = _qmp_client(tmp_path, responder)
    try:
        reply = client.command("screendump", {"filename": "x"})
        assert reply["return"] == {"fresh": True}, reply
    finally:
        client.close()
        server.close()


@pytest.mark.parametrize("bad", [{"return": {}, "id": 999}, {"return": {}}])
def test_qmp_rejects_mismatched_id(tmp_path, bad):
    ## A reply carrying an id we never sent (999) or none is an unrecoverable
    ## desync: fail LOUD, never silently accept it as this command's reply.
    client, server = _qmp_client(tmp_path, lambda cmd: [dict(bad)])
    try:
        with pytest.raises(ConnectionError):
            client.command("screendump", {"filename": "x"})
    finally:
        client.close()
        server.close()


## --- dm-qemu-screendump-watch --interval lower bound ------------------------

def test_interval_must_be_positive(tmp_path):
    ## --interval feeds time.sleep(); < 1 would ValueError-crash (exit 1) and break the
    ## 0/5/2 exit-code contract. The guard turns it into an argparse usage error (exit 2).
    proc = subprocess.run(
        [str(SCREENDUMP_WATCH), '--qmp', str(tmp_path / 'x.sock'),
         '--outdir', str(tmp_path), '--interval', '-1'],
        capture_output=True, text=True)
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    assert '--interval' in proc.stderr


def test_bad_outdir_maps_to_setup(tmp_path):
    ## --outdir under a regular FILE makes os.makedirs raise NotADirectoryError.
    ## That call was outside the try, so the OSError escaped as an uncaught exit 1;
    ## it must now map to SETUP(2). Requires ImageMagick (preflighted first): the
    ## 'cannot create --outdir' assertion fails loudly if it is absent, so the test
    ## can never pass for the wrong reason (an ImageMagick-missing early return 2).
    blocker = tmp_path / 'afile'
    blocker.write_text('x', encoding='ascii')
    bad_outdir = blocker / 'sub'  # parent is a file -> NotADirectoryError
    proc = subprocess.run(
        [str(SCREENDUMP_WATCH), '--qmp', str(tmp_path / 'x.sock'),
         '--outdir', str(bad_outdir)],
        capture_output=True, text=True)
    assert 'Traceback' not in proc.stderr, proc.stderr
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    assert 'cannot create --outdir' in proc.stderr, proc.stderr


## --- dm-image-test safe_rmtree_workdir (unvalidated-path teardown) ----------

def _load_dm_image_test():
    loader = importlib.machinery.SourceFileLoader(
        'dm_image_test_under_test', str(HARNESS))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_safe_rmtree_workdir(tmp_path, monkeypatch):
    ## qemu_workdir is parsed from dm-qemu stderr; the teardown must only rmtree a real,
    ## non-symlink dir strictly UNDER the temp root -- never a symlink, the temp root, or
    ## an out-of-tree path, so a bad marker cannot aim the recursive delete elsewhere.
    m = _load_dm_image_test()
    logs: list[str] = []
    log = logs.append
    # (a) a real dir strictly under the temp root -> removed
    monkeypatch.setattr(m.tempfile, 'gettempdir', lambda: str(tmp_path))
    wd = tmp_path / "qemu-workdir"
    (wd / "sub").mkdir(parents=True)
    (wd / "sub" / "f").write_text("x", encoding="utf-8")
    assert m.safe_rmtree_workdir(str(wd), log) is True
    assert not wd.exists()
    # (b) a path OUTSIDE the temp root -> refused, not removed
    fake_tmp = tmp_path / "tmproot"
    fake_tmp.mkdir()
    monkeypatch.setattr(m.tempfile, 'gettempdir', lambda: str(fake_tmp))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("x", encoding="utf-8")
    assert m.safe_rmtree_workdir(str(outside), log) is False
    assert outside.exists()
    # (c) the temp root itself -> refused
    assert m.safe_rmtree_workdir(str(fake_tmp), log) is False
    assert fake_tmp.exists()
    # (d) a symlink -> refused (even pointing inside the temp root)
    target = fake_tmp / "real"
    target.mkdir()
    link = fake_tmp / "link"
    link.symlink_to(target)
    assert m.safe_rmtree_workdir(str(link), log) is False
    assert link.exists() and target.exists()
    # (e) a non-existent path -> refused
    assert m.safe_rmtree_workdir(str(fake_tmp / "nope"), log) is False


## --- exit-code contract: setup errors must map to SETUP(2), never exit 1 ------
## Every uncaught-exception path out of main() breaks the 0/5/2 promise by
## surfacing as exit 1. These lock the environment/IO paths to SETUP(2).

def test_missing_qemu_binary_maps_to_setup(tmp_path):
    ## A stub dm-qemu emits an argv whose qemu binary (argv[0]) does not exist, so
    ## pexpect.spawn raises pexpect.ExceptionPexpect. That is a setup error -- the
    ## harness must exit SETUP(2), not let the exception escape as exit 1.
    pytest.importorskip('pexpect')
    stub = tmp_path / 'dm-qemu'
    stub.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' /nonexistent/qemu-system-x86_64 -m 512\n",
        encoding='ascii')
    stub.chmod(0o755)
    disk = tmp_path / 'dummy.qcow2'
    disk.write_bytes(b'')
    proc = subprocess.run(
        [str(HARNESS), '--disk', str(disk), '--dm-qemu', str(stub),
         '--timeout', '8'],
        capture_output=True, text=True, timeout=90, check=False)
    assert 'Traceback' not in proc.stderr, proc.stderr[-2000:]
    assert proc.returncode == SETUP_RC, (
        'a missing qemu binary must map to SETUP=%d, got rc=%d\n%s'
        % (SETUP_RC, proc.returncode, proc.stderr[-2000:]))
    assert 'cannot spawn qemu' in proc.stderr, proc.stderr[-2000:]


def test_nonexecutable_dm_qemu_maps_to_setup(tmp_path):
    ## --dm-qemu points at a file that exists but is not executable, so
    ## subprocess.run raises PermissionError (an OSError, NOT FileNotFoundError).
    ## That must map to SETUP(2), not escape as an uncaught exit 1.
    dmqemu = tmp_path / 'dm-qemu'
    dmqemu.write_text("#!/bin/sh\ntrue\n", encoding='ascii')
    dmqemu.chmod(0o644)  # readable but not +x
    disk = tmp_path / 'dummy.qcow2'
    disk.write_bytes(b'')
    proc = subprocess.run(
        [str(HARNESS), '--disk', str(disk), '--dm-qemu', str(dmqemu),
         '--timeout', '8'],
        capture_output=True, text=True, timeout=90, check=False)
    assert 'Traceback' not in proc.stderr, proc.stderr[-2000:]
    assert proc.returncode == SETUP_RC, (
        'a non-executable --dm-qemu must map to SETUP=%d, got rc=%d\n%s'
        % (SETUP_RC, proc.returncode, proc.stderr[-2000:]))
    assert 'cannot execute dm-qemu' in proc.stderr, proc.stderr[-2000:]


def test_emit_argv_preserves_empty_token(tmp_path):
    ## dm-qemu emits one argv token per line; an EMPTY token is legitimate (e.g. an
    ## empty '-append' value). The old parse filtered every empty line, shifting all
    ## later tokens. build_qemu_argv must keep interior empties and drop only the
    ## trailing terminator.
    m = _load_dm_image_test()
    stub = tmp_path / 'dm-qemu'
    stub.write_text(
        "#!/bin/sh\nprintf '%s\\n' qemu-system-x86_64 '' -m 512\n",
        encoding='ascii')
    stub.chmod(0o755)
    disk = tmp_path / 'dummy.qcow2'
    disk.write_bytes(b'')
    args = types.SimpleNamespace(
        dm_qemu=str(stub), disk=str(disk), iso=None, arch="", firmware="",
        serial_log="", session="user", smbios_append="", dm_qemu_args=[])
    argv, _workdir = m.build_qemu_argv(args)
    assert argv == ['qemu-system-x86_64', '', '-m', '512'], argv


class _FakeChild:
    ## Minimal pexpect.spawn stand-in for run_checks: answers each sendline() with
    ## the exact serial output the real root shell would produce, so run_checks'
    ## real read/sentinel loop drives to a verdict with no VM. read_nonblocking
    ## hands back the buffered reply, then raises pexpect.TIMEOUT (its idle poll).
    def __init__(self, pid, systemcheck_rc, diag_rc):
        self.pid = pid
        self.systemcheck_rc = systemcheck_rc
        self.diag_rc = diag_rc
        self.buf = ""

    def sendline(self, line):
        if "DM<>" in line and "printf" in line:
            m = re.search(r"DMRDY\d+", line)
            assert m is not None
            token = m.group(0)
            self.buf += "DM<>%s<>\n" % token
        elif "is-system-running" in line:
            m = re.search(r"DMBOOT\d+", line)
            assert m is not None
            token = m.group(0)
            self.buf += "%s\n" % token
        elif "DMRC" in line:
            m = re.search(r"DMRC\d+", line)
            assert m is not None
            sentinel = m.group(0)
            rc = self.diag_rc if "FAILED-UNITS-BEGIN" in line \
                else self.systemcheck_rc
            self.buf += "%s:%d:%s\n" % (sentinel, rc, sentinel)

    def read_nonblocking(self, size=1, timeout=None):
        import pexpect
        if self.buf:
            chunk, self.buf = self.buf[:size], self.buf[size:]
            return chunk
        time.sleep(0.02)
        raise pexpect.TIMEOUT("no data")


def test_diag_cmd_exempt_from_expect_rc():
    ## The default command list is [systemcheck, diag]; the diag always exits 0.
    ## With --expect-rc 1, systemcheck returning 1 is the PASS, and the diag's rc=0
    ## must NOT flip the verdict to FAIL. run_checks must return PASS.
    pytest.importorskip('pexpect')
    m = _load_dm_image_test()
    child = _FakeChild(os.getpid(), systemcheck_rc=1, diag_rc=0)
    args = types.SimpleNamespace(
        timeout=30, run=None, login_user="user", expect_rc=1, firmware="")
    logs: list[str] = []
    rc = m.run_checks(child, args, logs.append)
    assert rc == m.PASS, (rc, logs)
