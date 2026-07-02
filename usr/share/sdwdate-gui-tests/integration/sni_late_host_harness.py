#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
StatusNotifier (SNI) late-host integration harness for sdwdate-gui.

Reproduces the startup race that hides the tray icon: a QSystemTrayIcon
binds to its backend (legacy XEmbed vs. the StatusNotifier D-Bus protocol)
when it is CONSTRUCTED. If the applet is constructed before the panel's
StatusNotifierWatcher is on the session bus, Qt binds XEmbed and never
re-registers via SNI even after isSystemTrayAvailable() flips to True, so an
SNI-only panel (lxqt-panel, waybar) never shows the icon.

The harness starts with NO watcher, then brings one up ~1s later -- the
order seen in the user-sysmaint-split sysmaint session, where the tray host
and sdwdate-gui are launched together. Two arms (argv[2]):

  blind     A plain QSystemTrayIcon().show() at t=0, i.e. the pre-fix
            'SdwdateTrayIcon(); show()'. This is the NEGATIVE CONTROL: it
            must NOT register via SNI (the bug). Pure Qt, no sdwdate_gui
            import, so it isolates the Qt backend-binding behaviour that
            the fix works around. If it ever DOES register, the control is
            broken (Qt changed, or the premise is wrong) and the arm fails
            loudly.

  deferred  The real sdwdate_gui_server.install_tray_when_available(), which
            defers construction until the watcher exists. It MUST register
            via SNI (the fix). This arm needs the fixed sdwdate_gui on
            PYTHONPATH.

Run under a private session bus (dbus-run-session) on a headless X display.
Prints 'RESULT <json>' then 'PASS' or 'FAIL: <reason>'. Exit 0 on pass.
Driven by the sdwdate-gui-tests-integration orchestrator, which runs both
arms.
"""

# pylint: disable=wrong-import-position,no-name-in-module,invalid-name

import json
import os
import subprocess
import sys

from PyQt5.QtCore import QObject, QTimer, pyqtSignal
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon

HERE = os.path.dirname(os.path.realpath(__file__))
WATCHER_SCRIPT = os.path.join(HERE, "sni_watcher.py")
WATCHER_LOG = sys.argv[1]
ARM = sys.argv[2] if len(sys.argv) > 2 else "deferred"

if ARM not in ("blind", "deferred"):
    print(f"FAIL: unknown arm {ARM!r} (expected 'blind' or 'deferred')")
    sys.exit(2)

app = QApplication(["sni-late-host-harness"])
if app.platformName() != "xcb":
    print(f"FAIL: expected xcb platform, got {app.platformName()!r}")
    sys.exit(1)

result: dict = {"arm": ARM, "platform": app.platformName()}
state: dict = {"watcher_pid": None, "tray": None}


def watcher_registered_item() -> bool:
    """True once the watcher has logged a RegisterStatusNotifierItem call."""
    try:
        with open(WATCHER_LOG, "r", encoding="utf-8") as log_file:
            return any(
                line.startswith("REGISTER_ITEM")
                for line in log_file.read().splitlines()
            )
    except FileNotFoundError:
        return False


def start_watcher() -> None:
    """Bring the StatusNotifierWatcher up late, after the applet started."""
    ## A long-lived background process killed in check(); 'with' would tear
    ## it down immediately, so the pylint suggestion does not apply.
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        ["python3", WATCHER_SCRIPT, WATCHER_LOG],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    state["watcher_pid"] = proc.pid


def install_blind_tray() -> None:
    """The pre-fix behaviour: construct + show() with no watcher present."""
    pixmap = QPixmap(22, 22)
    pixmap.fill()
    tray = QSystemTrayIcon()
    tray.setIcon(QIcon(pixmap))
    tray.show()
    ## Keep a reference so Qt does not garbage-collect the icon.
    state["tray"] = tray


def check() -> None:
    """Evaluate the outcome and exit with pass/fail."""
    result["tray_available"] = QSystemTrayIcon.isSystemTrayAvailable()
    result["registered_via_sni"] = watcher_registered_item()
    print("RESULT " + json.dumps(result))

    if state["watcher_pid"]:
        try:
            os.kill(state["watcher_pid"], 15)
        except OSError:
            pass

    failures = []
    if not result["tray_available"]:
        failures.append("watcher never became visible to Qt")

    if ARM == "deferred":
        ## The fix must register the icon via StatusNotifier.
        if not result["registered_via_sni"]:
            failures.append(
                "tray icon did not register via StatusNotifier "
                "(fell back to XEmbed -- the startup-race bug)"
            )
    else:
        ## Negative control: the blind path must NOT register via SNI.
        if result["registered_via_sni"]:
            failures.append(
                "blind path unexpectedly registered via StatusNotifier "
                "(negative control broken: Qt now recovers late, or the "
                "premise is wrong -- re-check whether the fix is needed)"
            )

    if failures:
        print("FAIL: " + "; ".join(failures))
        app.exit(1)
    else:
        print("PASS")
        app.exit(0)


## No watcher yet at construction time: exercise the race.
assert (
    not QSystemTrayIcon.isSystemTrayAvailable()
), "a system tray host is already present; cannot exercise the race"

if ARM == "blind":
    install_blind_tray()
else:
    from sdwdate_gui import sdwdate_gui_server as server

    class FakeListener(QObject):  # pylint: disable=too-few-public-methods
        """Stub listener: keeps the test off the real IPC socket / PID file."""

        newClient = pyqtSignal(object)

    server.SdwdateGuiListener = FakeListener
    server.install_tray_when_available(app)

## Bring the watcher up after the applet has already started.
QTimer.singleShot(1000, start_watcher)
## Allow time for the watcher to own the bus name and for any deferred
## construction + SNI registration round-trip to complete.
QTimer.singleShot(5000, check)
## Safety net.
QTimer.singleShot(12000, lambda: (print("FAIL: timed out"), app.exit(1)))

sys.exit(app.exec_())
