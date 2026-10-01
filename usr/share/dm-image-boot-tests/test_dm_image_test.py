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
    def __init__(self, pid, systemcheck_rc, diag_rc, hardening_rc=0,
                 boot_match_rc=0, cli_login_rc=0):
        self.pid = pid
        self.systemcheck_rc = systemcheck_rc
        self.diag_rc = diag_rc
        self.hardening_rc = hardening_rc
        ## The firmware/role boot-match sentinels; 0 = a correctly-booted guest.
        self.boot_match_rc = boot_match_rc
        ## check 5 CLI-login ('id -un' identity assertion); 0 = login yields the user.
        self.cli_login_rc = cli_login_rc
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
            if "MISSING-HARDENING" in line:
                rc = self.hardening_rc
            elif ("WRONG-ROLE" in line or "WRONG-FIRMWARE" in line
                  or "WRONG-SECUREBOOT" in line):
                rc = self.boot_match_rc
            elif "id -un" in line:
                ## check 5 (CLI login): 'test "$(id -un)" = <user>'.
                rc = self.cli_login_rc
            elif "FAILED-UNITS-BEGIN" in line:
                rc = self.diag_rc
            else:
                rc = self.systemcheck_rc
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
        timeout=30, run=None, login_user="user", expect_rc=1, firmware="",
        iso=None, session="user")
    logs: list[str] = []
    rc = m.run_checks(child, args, logs.append)
    assert rc == m.PASS, (rc, logs)


## --- ISO kernel-hardening cmdline check ---------------------------------------
## build-steps.d/4310_convert-raw-to-iso scrapes the rootfs kernel hardening into
## the live boot append; dropping that scrape boots an unhardened live ISO. These
## lock the check that catches that regression on the ISO boot legs.

def test_hardening_cmdline_check_passes_when_all_tokens_present(tmp_path):
    m = _load_dm_image_test()
    cmdline = tmp_path / "cmdline"
    cmdline.write_text(
        "BOOT_IMAGE=/live/vmlinuz boot=live components splash "
        "slab_nomerge rd.shell=0 rd.emergency=halt mitigations=auto,nosmt\n",
        encoding="utf-8")
    cmd = m.hardening_cmdline_check(str(cmdline))
    rc = subprocess.call(["bash", "-c", cmd])
    assert rc == 0


@pytest.mark.parametrize("missing", ["slab_nomerge", "rd.shell=0", "rd.emergency=halt"])
def test_hardening_cmdline_check_fails_when_a_token_missing(tmp_path, missing):
    ## Canary: an unhardened live cmdline (any one hardening token dropped) must fail
    ## the check, so the 4310 scrape regression cannot pass the ISO legs green.
    m = _load_dm_image_test()
    kept = [token for token in m.ISO_HARDENING_TOKENS if token != missing]
    cmdline = tmp_path / "cmdline"
    cmdline.write_text("BOOT_IMAGE=/live/vmlinuz " + " ".join(kept) + "\n",
                       encoding="utf-8")
    cmd = m.hardening_cmdline_check(str(cmdline))
    rc = subprocess.call(["bash", "-c", cmd])
    assert rc != 0


def test_iso_leg_inserts_hardening_check_and_a_failure_fails_the_verdict():
    ## Wiring: on the ISO path (args.iso set) run_checks prepends the hardening
    ## check; when it fails (hardening_rc != expect_rc) the whole leg is FAIL even
    ## though systemcheck passed.
    pytest.importorskip('pexpect')
    m = _load_dm_image_test()
    base = dict(timeout=30, run=None, login_user="root", expect_rc=0, firmware="",
                session="user")
    ## Hardened ISO: hardening check passes, systemcheck passes -> PASS.
    child = _FakeChild(os.getpid(), systemcheck_rc=0, diag_rc=0, hardening_rc=0)
    ok = m.run_checks(child, types.SimpleNamespace(iso="x.iso", **base), (lambda _: None))
    assert ok == m.PASS
    ## Unhardened ISO: hardening check fails -> FAIL, regardless of systemcheck.
    child = _FakeChild(os.getpid(), systemcheck_rc=0, diag_rc=0, hardening_rc=1)
    logs: list[str] = []
    bad = m.run_checks(child, types.SimpleNamespace(iso="x.iso", **base), logs.append)
    assert bad == m.FAIL, logs


def test_disk_leg_does_not_insert_hardening_check():
    ## The disk legs inherit hardening from their installed grub; run_checks must not
    ## add the ISO-only cmdline assertion there (args.iso is None).
    pytest.importorskip('pexpect')
    m = _load_dm_image_test()
    ## hardening_rc=1 would fail the verdict IF the check were (wrongly) inserted.
    child = _FakeChild(os.getpid(), systemcheck_rc=0, diag_rc=0, hardening_rc=1)
    args = types.SimpleNamespace(
        timeout=30, run=None, login_user="root", expect_rc=0, firmware="", iso=None,
        session="user")
    rc = m.run_checks(child, args, (lambda _: None))
    assert rc == m.PASS


def _run_as_harness(sentinel_cmd):
    """Run a sentinel exactly as run_checks does -- in a SUBSHELL, with the
    exit-code printf appended -- and return the reported rc, or None if the printf
    never ran (the shell died: the exit-1-escapes-the-debug-shell regression)."""
    out = subprocess.run(
        ['bash', '-c',
         "( %s ); printf 'RCSENT:%%s:RCSENT\\n' \"$?\"" % sentinel_cmd],
        capture_output=True, text=True)
    m = re.search(r'RCSENT:(-?\d+):RCSENT', out.stdout)
    return int(m.group(1)) if m else None


def test_boot_role_sentinel_verifies_the_actual_session(tmp_path):
    """The sysmaint sentinel passes only when /proc/cmdline carries the injected
    boot-role=sysmaint WHOLE token; the user sentinel passes only when it does NOT.
    Runs the REAL generated command the way run_checks does (subshell + printf
    sentinel), so a returned rc also proves the shell survived the exit."""
    m = _load_dm_image_test()
    sm = tmp_path / 'cmdline_sysmaint'
    sm.write_text('BOOT_IMAGE=/vmlinuz ro boot-role=sysmaint '
                  'systemd.unit=sysmaint-boot.target quiet\n')
    usr = tmp_path / 'cmdline_user'
    usr.write_text('BOOT_IMAGE=/vmlinuz ro quiet splash boot-role=user\n')
    ## A longer token that merely STARTS with boot-role=sysmaint (grep -w would
    ## wrongly accept it; the anchored match must not).
    canary = tmp_path / 'cmdline_canary'
    canary.write_text('BOOT_IMAGE=/vmlinuz ro quiet boot-role=sysmaint-canary splash\n')

    def cmd(session, cmdline):
        return m.boot_role_sentinel(session).replace('/proc/cmdline', str(cmdline))

    assert _run_as_harness(cmd('sysmaint', sm)) == 0
    assert _run_as_harness(cmd('sysmaint', usr)) == 1
    assert _run_as_harness(cmd('user', usr)) == 0
    assert _run_as_harness(cmd('user', sm)) == 1
    ## Whole-token: boot-role=sysmaint-canary is NOT boot-role=sysmaint.
    assert _run_as_harness(cmd('user', canary)) == 0      # user leg not false-failed
    assert _run_as_harness(cmd('sysmaint', canary)) == 1  # canary != the real token


def test_firmware_bios_sentinel_survives_and_flags_efi(tmp_path):
    """The bios firmware sentinel passes with no EFI dir, fails (rc 1, shell alive)
    when one is present -- run via the harness wrapper so exit-1 must not kill the
    shell (rc None would be that regression)."""
    m = _load_dm_image_test()
    (bios_cmd,) = m.firmware_sentinels('bios')
    no_efi = bios_cmd.replace('/sys/firmware/efi', str(tmp_path / 'no_such'))
    assert _run_as_harness(no_efi) == 0
    efi_dir = tmp_path / 'efi'
    efi_dir.mkdir()
    has_efi = bios_cmd.replace('/sys/firmware/efi', str(efi_dir))
    assert _run_as_harness(has_efi) == 1


def test_firmware_sentinels_match_the_claimed_firmware():
    """Each firmware yields the right assertions: bios refuses EFI presence; efi
    and efi-secureboot require EFI and read the SecureBoot var, wanting 0 vs 1;
    an unknown/empty firmware yields nothing."""
    m = _load_dm_image_test()
    bios = m.firmware_sentinels('bios')
    assert len(bios) == 1
    assert '/sys/firmware/efi' in bios[0]
    assert 'WRONG-FIRMWARE' in bios[0]
    efi = m.firmware_sentinels('efi')
    efisb = m.firmware_sentinels('efi-secureboot')
    for cmds in (efi, efisb):
        assert any('WRONG-FIRMWARE:expected-efi-but-none' in c for c in cmds)
        assert any(m.SECUREBOOT_EFIVAR in c for c in cmds)
    assert any('"$sb" = "0"' in c for c in efi)
    assert any('"$sb" = "1"' in c for c in efisb)
    assert m.firmware_sentinels('') == []
    assert m.firmware_sentinels('arm64-efi') == []


def test_secureboot_value_read_parses_the_efivar(tmp_path):
    """The od|awk read the firmware sentinel uses extracts 1 for an enabled
    SecureBoot var, 0 for disabled, empty for an absent var (which the sentinel
    then defaults to 0)."""
    on = tmp_path / 'sb_on'
    on.write_bytes(b'\x06\x00\x00\x00\x01')
    off = tmp_path / 'sb_off'
    off.write_bytes(b'\x06\x00\x00\x00\x00')

    def read(path):
        out = subprocess.run(
            ['bash', '-c',
             "od -An -t u1 %s 2>/dev/null | awk 'END{print $NF}'" % path],
            capture_output=True, text=True)
        return out.stdout.strip()

    assert read(str(on)) == '1'
    assert read(str(off)) == '0'
    assert read(str(tmp_path / 'absent')) == ''


def test_run_checks_inserts_boot_match_sentinels_and_a_mismatch_fails():
    """run_checks prepends the boot-match sentinels regardless of --expect-rc, and
    a mismatch (boot_match_rc != 0) fails the leg even when systemcheck passes --
    while a healthy boot_match_rc=0 passes. This is what stops a leg from going
    green on the wrong firmware/session."""
    pytest.importorskip('pexpect')
    m = _load_dm_image_test()
    base = dict(timeout=30, run=None, login_user="root", expect_rc=0,
                firmware="efi-secureboot", iso=None, session="sysmaint")
    ## Correct boot: every sentinel returns 0 -> PASS.
    child = _FakeChild(os.getpid(), systemcheck_rc=0, diag_rc=0, boot_match_rc=0)
    ok = m.run_checks(child, types.SimpleNamespace(**base), (lambda _: None))
    assert ok == m.PASS
    ## Wrong firmware/session: a boot-match sentinel fails even though systemcheck
    ## passed -> FAIL.
    child = _FakeChild(os.getpid(), systemcheck_rc=0, diag_rc=0, boot_match_rc=1)
    logs: list[str] = []
    bad = m.run_checks(child, types.SimpleNamespace(**base), logs.append)
    assert bad == m.FAIL, logs


def test_boot_match_sentinels_require_zero_regardless_of_expect_rc():
    """A --expect-rc 1 run (systemcheck expected to 'fail') must STILL require the
    boot matched: a healthy boot_match_rc=0 passes despite expect_rc=1, and a
    mismatch fails. Guards the want_rc split from the global --expect-rc."""
    pytest.importorskip('pexpect')
    m = _load_dm_image_test()
    base = dict(timeout=30, run=None, login_user="root", expect_rc=1,
                firmware="bios", iso=None, session="sysmaint")
    ## systemcheck returns 1 (== expect_rc -> its own pass); boot-match returns 0.
    child = _FakeChild(os.getpid(), systemcheck_rc=1, diag_rc=0, boot_match_rc=0)
    ok = m.run_checks(child, types.SimpleNamespace(**base), (lambda _: None))
    assert ok == m.PASS
    ## boot-match mismatch (returns 1) must FAIL even though 1 == expect_rc: the
    ## sentinel's want_rc is 0, not expect_rc.
    child = _FakeChild(os.getpid(), systemcheck_rc=1, diag_rc=0, boot_match_rc=1)
    logs: list[str] = []
    bad = m.run_checks(child, types.SimpleNamespace(**base), logs.append)
    assert bad == m.FAIL, logs


## --- numbered release-critical checks (1/2/5/8) --------------------------------
## The serial leg formalizes the checks it CAN assert (headless, no network) as
## numbered release-critical PASS/FAIL, matching dm-calamares-install's vocabulary.
## These lock the numbering, the per-leg selection, the verdict wiring, and the
## honest "what this leg does NOT cover" summary.

def _plan_args(**kw):
    base = dict(disk='/x.qcow2', iso=None, arch='', firmware='bios', session='user',
                login_user='user', login_pass='', run=None, expect_rc=0,
                timeout=1800, smbios_append='', serial_log='', dm_qemu='dm-qemu',
                dm_qemu_args=[])
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_release_checks_catalog_numbers():
    ## The single source of truth lists exactly the checks a serial leg can assert.
    m = _load_dm_image_test()
    assert set(m.RELEASE_CHECKS) == {1, 2, 5, 8}, m.RELEASE_CHECKS
    ## The delegated set must not overlap -- a number is either asserted here or
    ## delegated, never both (else a reader can't tell who owns it).
    delegated = {num for num, _ in m.DELEGATED_CHECKS}
    assert delegated.isdisjoint(m.RELEASE_CHECKS), (delegated, set(m.RELEASE_CHECKS))
    assert delegated == {0, 3, 4, 6, 7}, delegated


def test_build_check_plan_user_leg_numbers_check_1_not_2():
    m = _load_dm_image_test()
    plan = m.build_check_plan(_plan_args(session='user'))
    nums = [num for *_rest, num in plan if num is not None]
    assert nums == [1, 5, 8], nums  ## order: session-boot, CLI login, systemcheck


def test_build_check_plan_sysmaint_leg_numbers_check_2_not_1():
    m = _load_dm_image_test()
    plan = m.build_check_plan(_plan_args(session='sysmaint'))
    nums = [num for *_rest, num in plan if num is not None]
    assert nums == [2, 5, 8], nums


def test_build_check_plan_integrity_and_diag_are_unnumbered():
    ## firmware sentinels, the ISO hardening guard and the diagnostic are NOT
    ## release-critical checks -- they must carry num None so they never appear as a
    ## numbered check in the summary.
    m = _load_dm_image_test()
    plan = m.build_check_plan(_plan_args(iso='/x.iso', disk=None,
                                         firmware='efi-secureboot', session='user'))
    ## The diagnostic is the only want_rc=None (exempt) entry, and it is unnumbered.
    diag = [e for e in plan if e[2] is None]
    assert len(diag) == 1 and diag[0][3] is None, plan
    ## Every firmware/hardening guard (force_root True, want_rc 0) that is not the
    ## role check is unnumbered.
    role_cmd = m.boot_role_sentinel('user')
    guards = [e for e in plan if e[1] and e[2] == 0 and e[0] != role_cmd]
    assert guards, plan
    assert all(e[3] is None for e in guards), guards


def test_build_check_plan_run_override_keeps_role_check_only():
    ## --run replaces the functional checks but the session-boot check (1/2) still
    ## guards the leg; no check 5/8 are injected into a custom run.
    m = _load_dm_image_test()
    plan = m.build_check_plan(_plan_args(run=['echo hi'], session='sysmaint'))
    nums = [num for *_rest, num in plan if num is not None]
    assert nums == [2], nums


def test_check_5_cli_login_failure_fails_the_verdict():
    ## Canary: a login that yields the WRONG identity (check 5 rc != 0) FAILS the
    ## leg, and the failure is reported as numbered 'check 5'. The all-pass inverse
    ## (cli_login_rc=0) must stay PASS, proving the assertion is not inert.
    pytest.importorskip('pexpect')
    m = _load_dm_image_test()
    args = _plan_args(timeout=30, session='user', login_user='user')
    ok_logs: list[str] = []
    ok = m.run_checks(_FakeChild(os.getpid(), systemcheck_rc=0, diag_rc=0,
                                 cli_login_rc=0), args, ok_logs.append)
    assert ok == m.PASS, ok_logs
    bad_logs: list[str] = []
    bad = m.run_checks(_FakeChild(os.getpid(), systemcheck_rc=0, diag_rc=0,
                                  cli_login_rc=1), args, bad_logs.append)
    assert bad == m.FAIL, bad_logs
    assert any('check 5' in line and 'FAIL' in line for line in bad_logs), bad_logs


def test_check_8_systemcheck_failure_reported_by_number():
    ## A systemcheck failure must surface as numbered 'check 8', not a bare command.
    pytest.importorskip('pexpect')
    m = _load_dm_image_test()
    args = _plan_args(timeout=30, session='user', login_user='user')
    logs: list[str] = []
    bad = m.run_checks(_FakeChild(os.getpid(), systemcheck_rc=1, diag_rc=0),
                       args, logs.append)
    assert bad == m.FAIL, logs
    assert any('check 8' in line and 'FAIL' in line for line in logs), logs


def test_summary_reports_verdicts_and_delegated_checks():
    ## The leg must log each numbered verdict AND an honest line naming the checks it
    ## does NOT run, so a green serial leg is never read as "all release checks pass".
    pytest.importorskip('pexpect')
    m = _load_dm_image_test()
    args = _plan_args(timeout=30, session='user', login_user='user')
    logs: list[str] = []
    rc = m.run_checks(_FakeChild(os.getpid(), systemcheck_rc=0, diag_rc=0),
                      args, logs.append)
    assert rc == m.PASS, logs
    blob = "\n".join(logs)
    assert 'release-critical check summary' in blob, logs
    assert 'check 1 (user session boots): PASS' in blob, logs
    assert 'check 5 (CLI login works): PASS' in blob, logs
    assert 'check 8 (systemcheck --leak-tests passes): PASS' in blob, logs
    ## the delegation line names every check this serial leg does not cover.
    for token in ('0 (install)', '3 (upgrade-nonroot)', '4 (networking)',
                  '6 (GUI login)', '7 (LUKS)'):
        assert token in blob, (token, logs)
    assert 'dm-calamares-install' in blob, logs


## --- cross-file numbering contract --------------------------------------------
## The serial RELEASE_CHECKS numbers MUST mean the same thing as dm-calamares-install's
## numbered run_check battery; a drift (someone renumbering one side) would make the
## two halves of the gate disagree on what "check N" asserts. This locks them together.

DM_CALAMARES = Path(__file__).resolve().parents[2] / 'bin' / 'dm-calamares-install'


def _calamares_run_checks():
    ## Map check number -> the command string of its run_check in dm-calamares-install.
    text = DM_CALAMARES.read_text(encoding='utf-8')
    return {int(num): cmd
            for num, cmd in re.findall(r"run_check\s+(\d+)\s+'([^']*)'", text)}


def test_cross_file_numbering_contract():
    assert DM_CALAMARES.is_file(), f"VBox-path battery not found: {DM_CALAMARES}"
    m = _load_dm_image_test()
    cal = _calamares_run_checks()
    ## Every serial release-check number must exist in the VBox battery with the same
    ## meaning (so the number is not reused for a different guarantee across files).
    for num in m.RELEASE_CHECKS:
        assert num in cal, (
            f"RELEASE_CHECKS[{num}] has no run_check {num} in dm-calamares-install; "
            "the two halves disagree on check numbering")
    ## Polarity + intent of the shared numbers:
    assert 'boot-role=sysmaint' in cal[1] and cal[1].lstrip().startswith('!'), cal[1]
    assert 'boot-role=sysmaint' in cal[2] and not cal[2].lstrip().startswith('!'), cal[2]
    assert 'whoami' in cal[5] or 'id -un' in cal[5], cal[5]  ## both assert CLI identity
    assert 'systemcheck' in cal[8], cal[8]
