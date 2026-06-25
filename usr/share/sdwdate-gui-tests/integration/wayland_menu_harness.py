#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Wayland integration harness for the sdwdate-gui tray menu opt-out.

Runs the real SdwdateTrayIcon under the real Qt 'wayland' platform plugin,
connected to a real Wayland compositor (expected: a headless weston set up
by the orchestrator). Asserts that:

  * the platform really is Wayland (not a monkeypatched string), and
  * show_menu() does NOT self-popup the menu on Trigger or Context -- the
    handler returns early and leaves the menu to the compositor, avoiding a
    popup at the bogus QCursor.pos() that Wayland reports to clients.

It also bypasses the gate once and calls popup(QCursor.pos()) directly --
the exact call the gate suppresses -- as evidence that the menu CAN show
(so the two 'not visible' results are due to the gate, not an inability to
show menus at all). That observation is reported but not asserted, to stay
robust on minimal headless compositors.

Prints 'RESULT <json>' then 'PASS' or 'FAIL: <reason>'.
Exit code 0 on pass, 1 on fail.
"""

# pylint: disable=wrong-import-position,no-name-in-module,duplicate-code

import json
import sys

from PyQt5.QtCore import QObject, QTimer, pyqtSignal
from PyQt5.QtGui import QCursor
from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon

app = QApplication(["wayland-menu-harness"])

result: dict = {"platform": app.platformName()}

from sdwdate_gui import sdwdate_gui_server as server

Reason = QSystemTrayIcon.ActivationReason


class FakeListener(QObject):  # pylint: disable=too-few-public-methods
    """Stub listener, avoids PID-file / socket side effects."""

    newClient = pyqtSignal(object)


server.SdwdateGuiListener = FakeListener

tray = server.SdwdateTrayIcon()

client = server.SdwdateGuiClient(QLocalSocket())
tray.accept_client(client)
client.sdwdate_status = server.SdwdateStatus.SUCCESS
client.sdwdate_msg = "ok"
client.tor_status = server.TorStatus.ABSENT
client.client_name = "disp5711"
client.client_name_set = True
client.clientNameChanged.emit()
app.processEvents()


def run() -> None:
    """Exercise the gate under real Wayland and evaluate."""
    tray.show_menu(Reason.Trigger)
    app.processEvents()
    result["after_trigger_menu_visible"] = tray.menu.isVisible()

    tray.show_menu(Reason.Context)
    app.processEvents()
    result["after_context_menu_visible"] = tray.menu.isVisible()

    ## Contrast: bypass the gate and do exactly what it suppresses.
    pos = QCursor.pos()
    result["qcursor_pos"] = [pos.x(), pos.y()]
    tray.menu.popup(pos)
    app.processEvents()
    result["after_forced_popup_menu_visible"] = tray.menu.isVisible()
    tray.menu.hide()

    print("RESULT " + json.dumps(result))

    failures = []
    if result["platform"] != "wayland":
        failures.append(f"expected wayland platform, got {result['platform']!r}")
    if result["after_trigger_menu_visible"]:
        failures.append("menu self-popped on Trigger under Wayland")
    if result["after_context_menu_visible"]:
        failures.append("menu self-popped on Context under Wayland")

    if failures:
        print("FAIL: " + "; ".join(failures))
        app.exit(1)
    else:
        print("PASS")
        app.exit(0)


QTimer.singleShot(800, run)
QTimer.singleShot(6000, lambda: app.exit(1))  # safety net
sys.exit(app.exec_())
