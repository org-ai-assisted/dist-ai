#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
X11 click integration harness for the sdwdate-gui tray menu.

Runs the real SdwdateTrayIcon on the current X11 DISPLAY (expected to be a
freshly started headless Xvfb with a real XEmbed systray host), injects a
ready client, then delivers a single genuine mouse click on the embedded
tray icon via xdotool and asserts the menu opened with exactly one visible
menu (no double menu).

One click per process against a fresh systray: re-using a systray host
across clicks races on icon embedding and on the popup's pointer grab, so
the orchestrator starts a clean Xvfb + host for each button.

Usage: x11_click_harness.py <button>     # button: 1 (left) or 3 (right)

Prints 'RESULT <json>' then 'PASS' or 'FAIL: <reason>'.
Exit code 0 on pass, 1 on fail. Driven by the
sdwdate-gui-tests-integration orchestrator.
"""

# pylint: disable=wrong-import-position,no-name-in-module,duplicate-code

import json
import subprocess
import sys

from PyQt5.QtCore import QObject, QTimer, pyqtSignal
from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication, QMenu, QSystemTrayIcon

BUTTON = sys.argv[1] if len(sys.argv) > 1 else "1"

app = QApplication(["x11-click-harness"])
if app.platformName() != "xcb":
    print(f"FAIL: expected xcb platform, got {app.platformName()!r}")
    sys.exit(1)

from sdwdate_gui import sdwdate_gui_server as server


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

activations: list[int] = []
tray.activated.connect(lambda reason: activations.append(int(reason)))
tray.show()

result: dict = {"platform": app.platformName(), "button": BUTTON}


def sh(*args: str) -> str:
    """Run a command and return its stripped stdout."""
    return subprocess.check_output(list(args), text=True).strip()


def visible_menu_count() -> int:
    """Number of QMenu widgets currently visible in the process."""
    return sum(
        1
        for widget in app.allWidgets()
        if isinstance(widget, QMenu) and widget.isVisible()
    )


def do_click() -> None:
    """Locate the systray host window and click its centre."""
    result["tray_available"] = QSystemTrayIcon.isSystemTrayAvailable()
    try:
        wid = sh("xdotool", "search", "--class", "stalonetray").split()[0]
        geo: dict = {}
        for line in sh("xwininfo", "-id", wid).splitlines():
            line = line.strip()
            if line.startswith("Absolute upper-left X:"):
                geo["x"] = int(line.split(":")[1])
            elif line.startswith("Absolute upper-left Y:"):
                geo["y"] = int(line.split(":")[1])
            elif line.startswith("Width:"):
                geo["w"] = int(line.split(":")[1])
            elif line.startswith("Height:"):
                geo["h"] = int(line.split(":")[1])
        cx = geo["x"] + geo["w"] // 2
        cy = geo["y"] + geo["h"] // 2
        result["click_xy"] = [cx, cy]
        subprocess.run(["xdotool", "mousemove", "--sync", str(cx), str(cy)], check=True)
        subprocess.run(["xdotool", "click", BUTTON], check=True)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(f"FAIL: could not click systray icon: {exc}")
        app.exit(1)
        return
    QTimer.singleShot(900, check)


def check() -> None:
    """Evaluate the outcome and exit with pass/fail."""
    result["activations"] = activations
    result["menu_visible"] = tray.menu.isVisible()
    result["visible_menu_count"] = visible_menu_count()
    print("RESULT " + json.dumps(result))

    failures = []
    if not result.get("tray_available"):
        failures.append("tray icon did not embed in the systray host")
    if not activations:
        failures.append("click produced no activation signal")
    if not result["menu_visible"]:
        failures.append("menu did not open on click")
    if result["visible_menu_count"] != 1:
        count = result["visible_menu_count"]
        failures.append(f"expected exactly 1 visible menu, got {count}")

    if failures:
        print("FAIL: " + "; ".join(failures))
        app.exit(1)
    else:
        print("PASS")
        app.exit(0)


QTimer.singleShot(2500, do_click)
QTimer.singleShot(9000, lambda: app.exit(1))  # safety net
sys.exit(app.exec_())
