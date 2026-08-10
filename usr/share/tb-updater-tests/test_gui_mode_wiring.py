#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Behavioral guard for tb-updater's GUI mode -- the "Tor Browser Downloader
desktop shortcut does nothing" territory.

The desktop shortcut runs the wrapper, which runs `update-torbrowser --input
gui`; update-torbrowser then asks for confirmation through the msgcollector
PyQt5 dialogs (tb_updater_gui for the download confirmation, generic_gui_message
for the install confirmation) and routes their documented return codes. If any
link in that chain is dropped -- the wrapper stops passing `--input gui`, the
confirmation path stops invoking the dialogs, moves a dialog into the stdin arm,
or mishandles the yes/no return code -- the GUI shortcut silently breaks.

These tests RUN the real shipped code rather than grepping its source: the
wrapper is executed with a stub update-torbrowser on PATH, and the two
confirmation functions are sourced from the real update-torbrowser and driven
with a stub dialog, so the actual TB_INPUT routing and return-code handling are
exercised. The dialogs' own Wayland/xcb robustness is guarded separately by the
msgcollector suite (the dialog code lives in msgcollector); this asserts
tb-updater actually drives those exact dialogs, so the two-package contract is
covered end to end.
"""

import os
import shlex
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tb_updater_testlib as T  # noqa: E402

try:
    WRAPPER = T.desktop_starter_wrapper()
    UPDATER = T.update_torbrowser_script()
except SystemExit:
    pytest.skip("tb-updater not available", allow_module_level=True)

## The two msgcollector dialogs update-torbrowser drives for GUI confirmation.
## These exact paths are what the msgcollector suite's test_gui_platform guards
## for the Wayland no-window fix; here they are rewritten to a stub so the
## routing around them can be exercised without a display.
DOWNLOAD_DIALOG = "/usr/libexec/msgcollector/tb_updater_gui.py"
INSTALL_DIALOG = "/usr/libexec/msgcollector/generic_gui_message.py"

## Rewrite both dialog invocations to a single stub that announces it ran (on
## stderr) and returns the answer chosen per case (on stdout).
DIALOG_REPLACE = {
    DOWNLOAD_DIALOG: "__tb_dialog",
    INSTALL_DIALOG: "__tb_dialog",
}

## Stub collaborators so the confirmation functions reach their TB_INPUT
## dispatch without a display, cache, or real exit. tb_exit_function announces
## the code it was asked to exit with (the abort path); __tb_dialog announces it
## ran and yields DIALOG_ANSWER.
STUBS = r"""
log() { :; }
output_cli() { :; }
output_gui() { :; }
error() { printf 'ERROR:%s\n' "$*" >&2; }
tb_read_cached_unixtime() { printf ''; }
tb_exit_function() { printf 'EXIT:%s\n' "${1:-}"; exit 200; }
__tb_dialog() { printf 'DIALOG\n' >&2; printf '%s' "${DIALOG_ANSWER:-}"; }
"""

## Fixture variables so each function reaches its dispatch on the simplest
## branch (not installed -> no dpkg version compare; no freshness cache).
BASE_ENV = {
    "TITLE": "Tor Browser Downloader",
    "tb_title": "Tor Browser",
    "tbb_locally_installed_version_stripped": "1.0",
    "tbb_version_stripped": "2.0",
    "tb_documentation_base_url_clearnet": "https://www.example.com",
    "tb_wiki": "TorBrowser",
    "installed_or_not_result": "false",
    "tb_postinst": "true",
    "tb_confirm_installation_skip": "false",
    "who_ami": "user",
}


def _drive(func, tb_input, answer=None, stdin=None):
    env = dict(BASE_ENV)
    env["TB_INPUT"] = tb_input
    if answer is not None:
        env["DIALOG_ANSWER"] = answer
    return T.drive_bash_function(
        UPDATER, func, preamble=STUBS, replace=DIALOG_REPLACE,
        env=env, stdin=stdin)


def test_desktop_wrapper_launches_gui_mode(tmp_path):
    ## The desktop shortcut's Exec= points at the wrapper; run it with a stub
    ## update-torbrowser on PATH and assert it is actually invoked with
    ## '--input gui'. Without this the shortcut does nothing useful.
    marker = tmp_path / "argv"
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    stub = stub_bin / "update-torbrowser"
    stub.write_text(
        "#!/bin/bash\nprintf '%s\\n' \"$*\" > " + shlex.quote(str(marker))
        + "\n")
    stub.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = str(stub_bin) + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(
        ["bash", WRAPPER], capture_output=True, text=True, env=env, check=False)
    assert proc.returncode == 0, proc.stderr
    assert marker.exists(), "wrapper never invoked update-torbrowser"
    assert marker.read_text().strip() == "--input gui", (
        os.path.basename(WRAPPER)
        + " must run 'update-torbrowser --input gui', got: "
        + marker.read_text().strip())


def test_download_confirmation_gui_dispatches_dialog_and_honours_no():
    ## GUI input must drive the download dialog and treat 65536 as 'No' (abort
    ## with tb_exit_function 10).
    proc = _drive("tb_confirm_update", "gui", answer="65536")
    assert "DIALOG" in proc.stderr, (
        "GUI download confirmation did not invoke tb_updater_gui.py")
    assert "EXIT:10" in proc.stdout, (
        "download confirmation did not abort on the dialog's 65536 ('No') "
        "return code; stdout=" + repr(proc.stdout))


def test_download_confirmation_gui_proceeds_on_yes():
    ## A non-65536 answer must NOT abort: the function returns and the download
    ## proceeds.
    proc = _drive("tb_confirm_update", "gui", answer="16384")
    assert "DIALOG" in proc.stderr
    assert "EXIT:" not in proc.stdout, (
        "download confirmation aborted despite a 'Yes' answer; stdout="
        + repr(proc.stdout))


def test_install_confirmation_gui_dispatches_dialog_and_honours_yes():
    ## GUI input must drive the install dialog; only 16384 ('Yes') proceeds, any
    ## other answer aborts with tb_exit_function 14.
    yes = _drive("tb_confirm_install", "gui", answer="16384")
    assert "DIALOG" in yes.stderr, (
        "GUI install confirmation did not invoke generic_gui_message.py")
    assert "EXIT:" not in yes.stdout, (
        "install confirmation aborted despite a 'Yes' answer; stdout="
        + repr(yes.stdout))
    no = _drive("tb_confirm_install", "gui", answer="65536")
    assert "DIALOG" in no.stderr
    assert "EXIT:14" in no.stdout, (
        "install confirmation did not abort on a non-16384 answer; stdout="
        + repr(no.stdout))


def test_stdin_input_uses_read_not_the_gui_dialog():
    ## The stdin path must read from stdin, never the GUI dialog. This is the
    ## exact regression guarded: a dialog call that drifted into the stdin arm
    ## (or a stdin arm that reached for the dialog) would make the GUI dialog run
    ## here -- so require it does NOT.
    proc = _drive("tb_confirm_update", "stdin", answer="16384", stdin="n\n")
    assert "DIALOG" not in proc.stderr, (
        "stdin input path invoked the GUI dialog")
    assert "EXIT:10" in proc.stdout, (
        "stdin 'n' answer did not abort the download; stdout="
        + repr(proc.stdout))
