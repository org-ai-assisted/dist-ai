#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Minimal self-contained reproducer for the sdwdate-gui tray-icon startup race.

Pure Qt -- does NOT import sdwdate_gui -- so it isolates the one disputed
claim: when a QSystemTrayIcon is constructed + show()n BEFORE the panel's
org.kde.StatusNotifierWatcher exists, does Qt recover and register via
StatusNotifier (SNI) once the watcher appears late?

Two arms differing only in ORDER prove it is construction-ordering, not an
environment artifact:

  late    construct + show(), THEN bring the watcher up 1s later
          -> icon never registers via SNI (stuck on legacy XEmbed; invisible
             on an SNI-only panel such as waybar / lxqt-panel)
  early   bring the watcher up first, THEN construct + show()
          -> icon registers via SNI

Same code path in both arms; only the watcher timing changes. On a cold
sysmaint boot nothing owns the watcher until the tray host launches, so a
sdwdate-gui-server that wins that race hits the 'late' case and its icon
never appears.

Deps: python3-pyqt5 python3-dbus python3-gi dbus + an X server.
Run:  xvfb-run -a python3 tray_startup_race_reproducer.py
      (each arm is run under its own dbus-run-session automatically)
Exit 0 iff late=NOT-registered and early=registered (race confirmed).
"""

# pylint: disable=invalid-name,no-name-in-module,wrong-import-position

import json
import os
import subprocess
import sys
import tempfile
import time

WATCHER_IFACE = "org.kde.StatusNotifierWatcher"
PROPS_IFACE = "org.freedesktop.DBus.Properties"


def run_watcher(log_path: str) -> None:
    """A just-enough StatusNotifierWatcher; logs each item registration.

    This is the session-bus object a real panel provides. Qt registers its
    StatusNotifierItem here, so the log tells us whether the icon went out
    over SNI rather than silently falling back to XEmbed.
    """
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    def log(message: str) -> None:
        with open(log_path, "a", encoding="utf-8") as log_file:
            log_file.write(message + "\n")

    class Watcher(dbus.service.Object):
        def __init__(self, bus: "dbus.Bus") -> None:
            super().__init__(bus, "/StatusNotifierWatcher")
            self.items: list = []

        @dbus.service.method(WATCHER_IFACE, in_signature="s")
        def RegisterStatusNotifierItem(self, service: str) -> None:
            log("REGISTER_ITEM " + str(service))
            self.items.append(str(service))
            self.StatusNotifierItemRegistered(str(service))

        @dbus.service.method(WATCHER_IFACE, in_signature="s")
        def RegisterStatusNotifierHost(self, service: str) -> None:
            log("REGISTER_HOST " + str(service))

        @dbus.service.signal(WATCHER_IFACE, signature="s")
        def StatusNotifierItemRegistered(self, service: str) -> None:
            pass

        @dbus.service.method(PROPS_IFACE, in_signature="ss", out_signature="v")
        def Get(self, _iface: str, prop: str) -> object:
            if prop == "IsStatusNotifierHostRegistered":
                return dbus.Boolean(True)
            if prop == "RegisteredStatusNotifierItems":
                return dbus.Array(self.items, signature="s")
            if prop == "ProtocolVersion":
                return dbus.Int32(0)
            return dbus.Boolean(False)

        @dbus.service.method(PROPS_IFACE, in_signature="s", out_signature="a{sv}")
        def GetAll(self, _iface: str) -> dict:
            return {
                "IsStatusNotifierHostRegistered": dbus.Boolean(True),
                "RegisteredStatusNotifierItems": dbus.Array(
                    self.items, signature="s"
                ),
                "ProtocolVersion": dbus.Int32(0),
            }

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    _name = dbus.service.BusName(WATCHER_IFACE, bus)
    _watcher = Watcher(bus)
    log("WATCHER_UP")
    GLib.MainLoop().run()


def spawn_watcher(log_path: str) -> "subprocess.Popen":
    ## Long-lived child, terminated by the arm; 'with' would kill it at once.
    return subprocess.Popen(  # pylint: disable=consider-using-with
        [sys.executable, os.path.realpath(__file__), "--watcher", log_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def registered_via_sni(log_path: str) -> bool:
    try:
        with open(log_path, "r", encoding="utf-8") as log_file:
            return any(
                line.startswith("REGISTER_ITEM") for line in log_file
            )
    except FileNotFoundError:
        return False


def watcher_up(log_path: str, timeout: float = 5.0) -> None:
    """Block until the spawned watcher has logged WATCHER_UP."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(log_path, "r", encoding="utf-8") as log_file:
                if any(l.startswith("WATCHER_UP") for l in log_file):
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.05)


def run_arm(arm: str) -> None:
    """One arm in its own process (a QApplication is one-shot per process)."""
    from PyQt5.QtCore import QTimer
    from PyQt5.QtGui import QIcon, QPixmap
    from PyQt5.QtWidgets import QApplication, QSystemTrayIcon

    log_path = tempfile.mktemp(prefix=f"sni-{arm}-")
    app = QApplication(["repro-" + arm])
    if app.platformName() != "xcb":
        print(f"SKIP {arm}: need the xcb platform, got {app.platformName()!r}")
        sys.exit(2)

    state = {"proc": None, "tray": None}

    def build_and_show() -> None:
        ## The backend (XEmbed vs. SNI) is chosen HERE, at CONSTRUCTION -- Qt
        ## queries for the watcher when the QSystemTrayIcon is created, not at
        ## show(). Whatever it picks is permanent for this icon.
        pixmap = QPixmap(22, 22)
        pixmap.fill()
        tray = QSystemTrayIcon()
        tray.setIcon(QIcon(pixmap))
        tray.show()
        state["tray"] = tray

    if arm == "early":
        ## Watcher exists BEFORE construction -> Qt binds the SNI backend.
        state["proc"] = spawn_watcher(log_path)
        watcher_up(log_path)
        build_and_show()
    else:
        ## Construct with NO watcher -> Qt binds XEmbed; the watcher arriving
        ## 1s later never flips this icon to SNI.
        build_and_show()
        QTimer.singleShot(
            1000, lambda: state.__setitem__("proc", spawn_watcher(log_path))
        )

    def finish() -> None:
        registered = registered_via_sni(log_path)
        print("RESULT " + json.dumps(
            {"arm": arm, "registered_via_sni": registered}))
        if state["proc"] is not None:
            state["proc"].terminate()
        app.exit(0 if registered else 1)

    QTimer.singleShot(4000, finish)
    sys.exit(app.exec_())


def main() -> None:
    expected = {"late": False, "early": True}
    got = {}
    for arm in ("late", "early"):
        ## Each arm gets its own private session bus so the watcher and Qt
        ## share one bus and successive arms do not fight over the
        ## well-known StatusNotifierWatcher name.
        out = subprocess.run(
            ["dbus-run-session", "--",
             sys.executable, os.path.realpath(__file__), "--arm", arm],
            capture_output=True, text=True, check=False,
        )
        sys.stdout.write(out.stdout)
        line = [l for l in out.stdout.splitlines() if l.startswith("RESULT ")]
        got[arm] = json.loads(line[0][len("RESULT "):])["registered_via_sni"] \
            if line else None

    print("VERDICT " + json.dumps({"expected": expected, "got": got}))
    if got == expected:
        print(
            "PASS: race confirmed -- same construct+show(), the icon registers "
            "via SNI only when the watcher exists BEFORE construction."
        )
        sys.exit(0)
    print("MISMATCH: got != expected (see above).")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--watcher":
        run_watcher(sys.argv[2])
    elif len(sys.argv) >= 3 and sys.argv[1] == "--arm":
        run_arm(sys.argv[2])
    else:
        main()
