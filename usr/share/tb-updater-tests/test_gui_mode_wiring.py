#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Structural guard for tb-updater's GUI mode -- the "Tor Browser Downloader
desktop shortcut does nothing" territory.

The desktop shortcut runs the wrapper, which runs `update-torbrowser --input
gui`; update-torbrowser then asks for confirmation through the msgcollector
PyQt5 dialogs (tb_updater_gui for the download confirmation, generic_gui_message
for the install confirmation). If any link in that chain is dropped -- the
wrapper stops passing `--input gui`, the option parser loses `--input`, or the
confirmation path stops invoking the dialogs -- the GUI shortcut silently
breaks.

These are pure-source structural checks (no install, no display). The dialogs'
own Wayland/xcb platform robustness is guarded separately by the msgcollector
suite's test_gui_platform (the dialog code lives in msgcollector); this test
asserts tb-updater actually drives those exact dialogs, so the contract between
the two packages is covered end to end.
"""

import os
import re
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

WRAPPER_SRC = T.read(WRAPPER)
UPDATER_SRC = T.read(UPDATER)

## The two msgcollector dialogs update-torbrowser drives for GUI confirmation.
## These exact paths are what the msgcollector suite's test_gui_platform guards
## for the Wayland no-window fix.
DOWNLOAD_DIALOG = "/usr/libexec/msgcollector/tb_updater_gui.py"
INSTALL_DIALOG = "/usr/libexec/msgcollector/generic_gui_message.py"


def test_desktop_wrapper_launches_gui_mode():
    ## The desktop shortcut's Exec= points at the wrapper; the wrapper must
    ## start update-torbrowser in GUI input mode. Without this the shortcut
    ## either does nothing useful or falls back to a terminal it has none of.
    assert re.search(r"update-torbrowser\s+--input\s+gui", WRAPPER_SRC), (
        f"{os.path.basename(WRAPPER)} must run 'update-torbrowser --input gui'")


def test_updater_parses_input_option():
    ## '--input gui' must be an accepted option that sets TB_INPUT; otherwise
    ## the wrapper's invocation dies as 'Unknown option'.
    assert "--input)" in UPDATER_SRC, (
        "update-torbrowser option parser lost the '--input' case")
    assert re.search(r'TB_INPUT="\$2"', UPDATER_SRC), (
        "'--input' must assign its argument to TB_INPUT")


def test_updater_drives_download_confirmation_dialog():
    ## The download confirmation on the GUI path runs tb_updater_gui and
    ## treats 65536 as the 'No' answer (the dialog's documented return code).
    assert DOWNLOAD_DIALOG in UPDATER_SRC, (
        f"update-torbrowser must invoke {DOWNLOAD_DIALOG} for GUI download "
        "confirmation")
    assert '"65536"' in UPDATER_SRC, (
        "update-torbrowser must honour tb_updater_gui's 65536 ('No') return "
        "code")


def test_updater_drives_install_confirmation_dialog():
    ## The install confirmation on the GUI path runs generic_gui_message and
    ## treats 16384 as the 'Yes' answer (the dialog's documented return code).
    assert INSTALL_DIALOG in UPDATER_SRC, (
        f"update-torbrowser must invoke {INSTALL_DIALOG} for GUI install "
        "confirmation")
    assert '"16384"' in UPDATER_SRC, (
        "update-torbrowser must honour generic_gui_message's 16384 ('Yes') "
        "return code")


def test_gui_dialogs_live_in_the_else_arm_of_the_stdin_check():
    ## Each dialog call must sit in the 'else' (gui) arm of the
    ## TB_INPUT="stdin" conditional, not the stdin arm. Find the nearest
    ## preceding stdin comparison and assert an 'else' appears between it and
    ## the dialog call -- so moving the dialog into the stdin arm (the exact
    ## GUI regression this guards) fails, rather than passing just because the
    ## strings exist somewhere earlier in the file.
    for dialog in (DOWNLOAD_DIALOG, INSTALL_DIALOG):
        call_index = UPDATER_SRC.find(dialog)
        assert call_index != -1
        stdin_index = UPDATER_SRC.rfind('= "stdin"', 0, call_index)
        assert stdin_index != -1, (
            f"{dialog}: no TB_INPUT=stdin check precedes the invocation")
        between = UPDATER_SRC[stdin_index:call_index]
        assert re.search(r"^\s*else\b", between, re.MULTILINE), (
            f"{dialog} is not in the else (gui) arm of the TB_INPUT=stdin "
            "check")
