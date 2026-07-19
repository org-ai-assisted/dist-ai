#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Minimal org.kde.StatusNotifierWatcher for the sdwdate-gui SNI integration
test. This is the session-bus object a real panel (lxqt-panel, waybar)
provides; Qt's QSystemTrayIcon registers its StatusNotifierItem with it.

It records every RegisterStatusNotifierItem call to the log file given as
argv[1], so the harness can assert whether the tray icon registered via the
StatusNotifier (SNI) protocol rather than silently falling back to XEmbed.

Run on a private session bus (dbus-run-session). Started late by the
harness to reproduce the panel-comes-up-after-the-applet startup race.
"""

# pylint: disable=invalid-name,missing-function-docstring

import sys

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

WATCHER_IFACE = "org.kde.StatusNotifierWatcher"
PROPS_IFACE = "org.freedesktop.DBus.Properties"
log_path = sys.argv[1]


def log(message: str) -> None:
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")


class StatusNotifierWatcher(dbus.service.Object):
    """A just-enough watcher: tracks items and reports a host as present."""

    def __init__(self, bus: dbus.Bus) -> None:
        super().__init__(bus, "/StatusNotifierWatcher")
        self.items: list[str] = []

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
            "RegisteredStatusNotifierItems": dbus.Array(self.items, signature="s"),
            "ProtocolVersion": dbus.Int32(0),
        }


def main() -> None:
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    ## Hold the well-known name for the lifetime of the process.
    _name = dbus.service.BusName(WATCHER_IFACE, bus)
    _watcher = StatusNotifierWatcher(bus)
    assert _name is not None and _watcher is not None  # hold the D-Bus name + service alive
    log("WATCHER_UP")
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
