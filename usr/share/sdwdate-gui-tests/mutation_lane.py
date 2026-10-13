#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
TARGETED mutation-testing lane for sdwdate-gui's security-critical code: the
sdwdate_gui_shared wire parser (length framing, printable-ASCII and octal-escape
boundaries, the unsigned length decode, the qrexec NUL scan / field split), the
sdwdate_gui_config_read argument check, the server's name-length and
argument-count validation, enum-value ordering and RPC send framing, and the
client's reconnect-backoff reset, Tor-status de-duplication and inotify watch
mask.

A full cosmic-ray pass over the package was used ONCE to discover the true
survivor set; this permanent lane ships NO engine dependency. It applies a
HAND-PICKED set of high-value mutants -- the gap-revealers and the boundaries a
reviewer most wants proven dead -- to a COPY of the real package, runs the REAL
test suite that should catch each, and asserts the mutant is KILLED. Nothing is
written back to the source tree.

A mutant is KILLED when its designated real killer suite, which PASSES on the
clean package, FAILS on the mutated package. A SURVIVOR (the killer still passes)
is a test gap, reported with a triage note -- never silently.

This lane is TRUSTED TOOLING (it reports whether a mutant died); it must get an
ai-review pass before any CI gate relies on its verdict.

Env: SDWDATE_GUI_REPO (source checkout); helper-scripts on the inherited
PYTHONPATH; QT_QPA_PLATFORM=offscreen. The tests dir is this file's dir. Exit 0
iff every mutant in the scoped set is killed; 1 on any survivor / error; 77 if the
package or a killer suite cannot be located.
"""

import os
import sys
import shutil
import tempfile
import subprocess


def _repo():
    repo = os.environ.get("SDWDATE_GUI_REPO", "")
    if not repo:
        default = os.path.expanduser(
            "~/derivative-maker/packages/kicksecure/sdwdate-gui"
        )
        if os.path.isdir(
            os.path.join(
                default, "usr", "lib", "python3", "dist-packages", "sdwdate_gui"
            )
        ):
            repo = default
    pkg = (
        os.path.join(
            repo, "usr", "lib", "python3", "dist-packages", "sdwdate_gui"
        )
        if repo
        else ""
    )
    if not repo or not os.path.isdir(pkg):
        sys.stderr.write(
            "mutation_lane: SKIP (sdwdate_gui not found; set SDWDATE_GUI_REPO)\n"
        )
        sys.exit(77)
    return repo, pkg


REPO, PKG = _repo()
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

## sdwdate-gui's suites run headless on the Qt offscreen platform (no X/Wayland).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


# Each mutant: a UNIQUE source substring in one package module, its mutation, and
# the REAL suite(s) that must catch it. `old` must occur EXACTLY once in the file
# (asserted -- a silent no-op mutation would falsely read as an un-killable mutant).
MUTANTS = [
    dict(id="shared check_bytes_printable upper bound 0x7E -> 0x7F (admit DEL)",
         module="sdwdate_gui_shared.py",
         old="if byte < 0x20 or byte > 0x7E:",
         new="if byte < 0x20 or byte > 0x7F:",
         killers=["test_mutation_shared.py"],
         note="DEL (0x7F) would pass as printable into a status/name field."),
    dict(id="shared parse_ipc_command frame cap > -> >= (reject exactly MAX)",
         module="sdwdate_gui_shared.py",
         old="if msg_len > MAX_MSG_SIZE:",
         new="if msg_len >= MAX_MSG_SIZE:",
         killers=["test_mutation_shared.py"],
         note="a legitimate MAX_MSG_SIZE-byte message would be wrongly rejected."),
    dict(id="shared length decode signed=False -> True (sign confusion)",
         module="sdwdate_gui_shared.py",
         old='msg_len: int = int.from_bytes(sock_buf[:2], byteorder="big", signed=False)',
         new='msg_len: int = int.from_bytes(sock_buf[:2], byteorder="big", signed=True)',
         killers=["test_mutation_shared.py"],
         note="a 0x8000-0xFFFF prefix would decode negative and bypass the cap."),
    dict(id="shared frame completeness (msg_len + 2) -> (msg_len + 1)",
         module="sdwdate_gui_shared.py",
         old="if len(sock_buf) < (msg_len + 2):",
         new="if len(sock_buf) < (msg_len + 1):",
         killers=["test_mutation_shared.py"],
         note="a one-byte-short frame would be parsed as if complete."),
    dict(id="shared qrexec NUL advance [idx + 1 :] -> [idx + 2 :]",
         module="sdwdate_gui_shared.py",
         old="sock_buf = sock_buf[idx + 1 :]",
         new="sock_buf = sock_buf[idx + 2 :]",
         killers=["test_mutation_shared.py"],
         note="the byte after the qrexec NUL terminator would be dropped."),
    dict(id="shared octal-escape upper bound > 0x7E -> >= 0x7E",
         module="sdwdate_gui_shared.py",
         old="if (octal_int < 0x20 or octal_int > 0x7E) and octal_int != 0x0A:",
         new="if (octal_int < 0x20 or octal_int >= 0x7E) and octal_int != 0x0A:",
         killers=["test_mutation_shared.py"],
         note="the printable tilde (\\176) would be wrongly rejected as unsafe."),
    dict(id="shared qrexec field count < 2 -> != 2",
         module="sdwdate_gui_shared.py",
         old="if len(qrexec_header_parts) < 2:",
         new="if len(qrexec_header_parts) != 2:",
         killers=["test_mutation_shared.py"],
         note="a 3-field qrexec header would lose its authenticated source VM."),
    dict(id="config_read argument count != 2 -> < 2",
         module="sdwdate_gui_config_read.py",
         old="if len(sys.argv) != 2:",
         new="if len(sys.argv) < 2:",
         killers=["test_mutation_shared.py"],
         note="surplus CLI arguments would be silently accepted instead of exit 2."),
    dict(id="server SdwdateStatus.SUCCESS value 0 -> 1 (status ordering)",
         module="sdwdate_gui_server.py",
         old="SUCCESS = 0",
         new="SUCCESS = 1",
         killers=["test_mutation_server.py"],
         note="the success/busy status ordering (worst-status icon) would break."),
    dict(id="server non-Qubes name length > 255 -> >= 255",
         module="sdwdate_gui_server.py",
         old="if len(client_name) > 255:",
         new="if len(client_name) >= 255:",
         killers=["test_mutation_server.py"],
         note="a legitimate 255-char client name would be wrongly kicked."),
    dict(id="server set_sdwdate_status arg count != 2 -> < 2",
         module="sdwdate_gui_server.py",
         old="if len(msg_parts) != 2:",
         new="if len(msg_parts) < 2:",
         killers=["test_mutation_server.py"],
         note="a surplus-argument status command would not be kicked."),
    dict(id="server RPC frame length accounting += 2 -> += 1",
         module="sdwdate_gui_server.py",
         old="msg_len += 2",
         new="msg_len += 1",
         killers=["test_mutation_server.py"],
         note="the length prefix byte would be dropped from the sent frame."),
    dict(id="server worst-status index init -1 -> 1",
         module="sdwdate_gui_server.py",
         old="sdwdate_status_index: int = -1",
         new="sdwdate_status_index: int = 1",
         killers=["test_mutation_server.py"],
         note="a SUCCESS client would show the wrong (busy) aggregate tray icon."),
    dict(id="server menu placeholder clients_shown == 0 -> != 0",
         module="sdwdate_gui_server.py",
         old="if clients_shown == 0:",
         new="if clients_shown != 0:",
         killers=["test_mutation_server.py"],
         note="the empty menu would omit the 'waiting for client' placeholder."),
    dict(id="client inotify watch mask | IN_MOVE_SELF -> & IN_MOVE_SELF",
         module="sdwdate_gui_client.py",
         old="| pyinotify.IN_MOVE_SELF",
         new="& pyinotify.IN_MOVE_SELF",
         killers=["test_mutation_client.py"],
         note="the composed inotify event mask would be corrupted."),
    dict(id="client backoff reset _now() - start -> _now() + start",
         module="sdwdate_gui_client.py",
         old="if _now() - session_start >= MIN_ESTABLISHED_SESSION_SECS:",
         new="if _now() + session_start >= MIN_ESTABLISHED_SESSION_SECS:",
         killers=["test_mutation_client.py"],
         note="a sub-threshold session would wrongly reset the backoff, "
              "re-enabling the dom0 qrexec-policy flood."),
    dict(id="client Tor-status de-dup != last -> > last",
         module="sdwdate_gui_client.py",
         old="if status != GlobalData.last_tor_status:",
         new="if status > GlobalData.last_tor_status:",
         killers=["test_mutation_client.py"],
         note="a lexicographically-lower Tor status change would be dropped."),
    dict(id="client send frame cap > -> >= (reject exactly MAX)",
         module="sdwdate_gui_client.py",
         old="if msg_len > MAX_MSG_SIZE:",
         new="if msg_len >= MAX_MSG_SIZE:",
         killers=["test_mutation_client.py"],
         note="a legitimate MAX_MSG_SIZE-byte client send would exit instead."),
]


_PKG_REL = os.path.join("usr", "lib", "python3", "dist-packages")


def _run_suite(repo_copy, suite):
    """Run a real test suite against the staged repo copy: its package dir first on
    PYTHONPATH (helper-scripts stays on the inherited PYTHONPATH the runner set up)
    and SDWDATE_GUI_REPO pointed at the copy root. QT_QPA_PLATFORM=offscreen is
    inherited. A killer PASSES (0) on the clean copy and must FAIL (non-zero, not
    77) mutated. Returns (exit code, combined output)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        os.path.join(repo_copy, _PKG_REL)
        + os.pathsep
        + env.get("PYTHONPATH", "")
    )
    env["SDWDATE_GUI_REPO"] = repo_copy
    try:
        proc = subprocess.run(
            [sys.executable, "-Bsu", os.path.join(TESTS_DIR, suite)],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # A mutant that hangs the suite (e.g. an unbounded send loop) is a KILL, not
        # a lane crash: report a non-zero, non-77 code so the caller counts it caught.
        raw_stdout = exc.stdout or ""
        raw_stderr = exc.stderr or ""
        if isinstance(raw_stdout, bytes):
            raw_stdout = raw_stdout.decode("utf-8", "replace")
        if isinstance(raw_stderr, bytes):
            raw_stderr = raw_stderr.decode("utf-8", "replace")
        return 124, raw_stdout + raw_stderr + "\n[mutation_lane: suite timed out]\n"
    return proc.returncode, (proc.stdout + proc.stderr)


def _staged_pkg(mutate=None):
    """Copy the WHOLE repo (minus .git) into a temp dir -- so the package keeps its
    real layout -- and (optionally) apply `mutate` = (module, old, new) to the copied
    module. Returns (repo_copy, cleanup). Asserts the mutation is a real edit (anchor
    occurs exactly once), so a silent no-op never reads as un-killable."""
    root = tempfile.mkdtemp(prefix="sdwgui-mut-")
    dst = os.path.join(root, "sdwdate-gui")
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns(".git"))
    if mutate is not None:
        module, old, new = mutate
        if new == old:
            shutil.rmtree(root, ignore_errors=True)
            raise AssertionError("mutation is a no-op (new == old) for %s" % module)
        path = os.path.join(dst, _PKG_REL, "sdwdate_gui", module)
        with open(path, encoding="utf-8") as handle:
            src = handle.read()
        count = src.count(old)
        if count != 1:
            shutil.rmtree(root, ignore_errors=True)
            raise AssertionError(
                "mutation anchor %r occurs %d times in %s (want 1)"
                % (old, count, module)
            )
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(src.replace(old, new))
    return dst, (lambda: shutil.rmtree(root, ignore_errors=True))


def main():
    # Baseline: every killer suite must PASS on the CLEAN (copied) package, else a
    # "mutant killed" verdict would be meaningless.
    killers = sorted({s for m in MUTANTS for s in m["killers"]})
    for suite in killers:
        if not os.path.isfile(os.path.join(TESTS_DIR, suite)):
            sys.stderr.write(
                "mutation_lane: SKIP (killer suite %s not found)\n" % suite
            )
            sys.exit(77)
    print("== baseline: killer suites on the clean package ==")
    clean_root, clean_cleanup = _staged_pkg()
    baseline_ok = True
    try:
        for suite in killers:
            rc, _out = _run_suite(clean_root, suite)
            print(
                "  %-28s %s (exit %d)"
                % (suite, "PASS" if rc == 0 else "FAIL", rc)
            )
            if rc != 0:
                baseline_ok = False
    finally:
        clean_cleanup()
    if not baseline_ok:
        sys.stderr.write(
            "mutation_lane: a killer suite fails on CLEAN code -- fix that "
            "first; a mutation verdict would be meaningless.\n"
        )
        return 1

    print("\n== mutants ==")
    killed = 0
    survivors = []
    for mut in MUTANTS:
        root, cleanup = _staged_pkg((mut["module"], mut["old"], mut["new"]))
        try:
            caught_by = None
            for suite in mut["killers"]:
                rc, _out = _run_suite(root, suite)
                if rc not in (0, 77):
                    caught_by = suite
                    break
            if caught_by:
                killed += 1
                print("  KILLED   %-54s by %s" % (mut["id"], caught_by))
            else:
                survivors.append(mut)
                print("  SURVIVED %-54s -- TRIAGE: %s" % (mut["id"], mut["note"]))
        finally:
            cleanup()

    total = len(MUTANTS)
    score = 100.0 * killed / total if total else 100.0
    print("\n== mutation score (scoped set) ==")
    print("  %d/%d mutants killed (%.1f%%)" % (killed, total, score))
    if survivors:
        print("  SURVIVORS (a test gap -- add a killer):")
        for mut in survivors:
            print("    - %s :: %s" % (mut["id"], mut["note"]))
    sys.stdout.write(
        "sdwdate-gui-tests(mutation): %d/%d killed, %d survivor(s)\n"
        % (killed, total, len(survivors))
    )
    return 0 if not survivors else 1


if __name__ == "__main__":
    sys.exit(main())
