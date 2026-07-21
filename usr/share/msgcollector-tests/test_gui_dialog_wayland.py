#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Real-dialog GUI test: launch each msgcollector PyQt5 confirmation dialog under
the real Qt 'wayland' platform plugin, connected to a real headless Wayland
compositor, and drive its 'Yes' button with a real key event -- no stubbing,
no offscreen QPA, no monkeypatching.

This is the end-to-end counterpart to test_gui_platform.py (which only checks
select_qt_platform statically) and test_safe_textbrowser.py (which runs Qt
offscreen and never opens a window). Here a real window is mapped on a real
compositor and really confirmed, exercising the exact path that regressed when
the dialogs defaulted to xcb under a Wayland session and aborted before any
window.

Mechanics live in the shared wl-headless-run helper: it starts a private
headless wlroots compositor (labwc), exports WAYLAND_DISPLAY +
QT_QPA_PLATFORM=wayland, and runs a background clicker that sends Alt+Y (the
'&Yes' mnemonic of a QDialogButtonBox Yes button) via wtype. wlroots, not
weston, because only it implements the virtual-keyboard protocol wtype needs to
reach a separate-process client.

'no skips in CI': when the Wayland tooling or PyQt5 is missing the test SKIPs on
a developer box but FAILS under CI (CI=true / GITHUB_ACTIONS), so a
mis-provisioned CI can never silently skip real GUI coverage.
"""

import importlib.util
import os
import subprocess

import pytest

import msgcollector_testlib as T

_HERE = os.path.dirname(os.path.abspath(__file__))


def _in_ci() -> bool:
    return os.environ.get("CI") == "true" or bool(os.environ.get("GITHUB_ACTIONS"))


def _require(present: bool, reason: str) -> None:
    """Skip locally, fail in CI: a required-but-absent prerequisite must never
    silently skip real GUI coverage in CI."""
    if present:
        return
    if _in_ci():
        pytest.fail(f"required in CI but missing: {reason}")
    pytest.skip(reason, allow_module_level=True)


def _wl_headless_run() -> str | None:
    ## Installed alongside this suite, or in the checkout's shared dir.
    for candidate in (
        os.path.join(_HERE, "wl-headless-run"),
        os.path.join(_HERE, "..", "dist-ai-tests-common", "wl-headless-run"),
    ):
        candidate = os.path.normpath(candidate)
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def _have(binary: str) -> bool:
    return any(
        os.access(os.path.join(d, binary), os.X_OK)
        for d in os.environ.get("PATH", "").split(os.pathsep)
        if d
    )


WL_RUN = _wl_headless_run()
_require(WL_RUN is not None, "wl-headless-run helper not found")
_require(importlib.util.find_spec("PyQt5") is not None, "PyQt5 not installed")
_require(_have("labwc"), "labwc (headless Wayland compositor) not installed")
_require(_have("wtype"), "wtype (Wayland key injector) not installed")


def _run_dialog(dialog: str, argv: list[str]) -> str:
    """Run <dialog> <argv...> under wl-headless-run; return its stdout, stripped.
    The background Alt+Y clicker confirms the yes/no dialog. A hang (clicker
    failed to reach the window) is turned into a clear failure by the timeout."""
    try:
        completed = subprocess.run(
            [WL_RUN, "--", dialog, *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"{os.path.basename(dialog)} was not confirmed within 60s "
            f"(the Alt+Y clicker never reached the window)"
        ) from exc
    return completed.stdout.strip()


def test_generic_gui_message_yesno_confirmed_on_wayland() -> None:
    """generic_gui_message.py <type> <title> <message> <question> yesno prints
    16384 on 'Yes'."""
    dialog = T.gui_dialog_script("generic_gui_message.py")
    out = _run_dialog(
        dialog,
        ["warning", "Wayland Real-Dialog Test",
         "This is a real dialog on a real compositor.",
         "Proceed?", "yesno"],
    )
    assert out == "16384", f"expected '16384' (Yes), got {out!r}"


def test_tb_updater_gui_yesno_confirmed_on_wayland() -> None:
    """tb_updater_gui.py's download-confirmation dialog prints the chosen online
    version on 'Yes'."""
    dialog = T.gui_dialog_script("tb_updater_gui.py")
    out = _run_dialog(
        dialog,
        ["info", "Download confirmation", "12.0", "13.0",
         "A new version is available.", "Download now?", "yesno"],
    )
    assert out == "13.0", f"expected the chosen version '13.0' (Yes), got {out!r}"
