#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Guards for the plain-Debian / non-Whonix design (adrelanos/ArrayBolt3, forum
posts #105/#110/#123/#154). These encode invariants that FUTURE changes must
not break:

  * every privileged action is dispatched through the `privilege` runner
    (leaprun on Whonix/Kicksecure, pkexec on plain Debian) -- no module may
    hard-code 'leaprun' again, or the tool silently breaks on plain Debian;
  * tor_status and torrc_gen agree on the drop-in path, and that path lives in
    a torrc.d directory whose %include the tool can vouch for.
"""

import os
import re
import subprocess
import sys
import unittest

import tcp_testlib

tcp_testlib.require_app()  # side-effect harness: sys.path + offscreen QApplication
from tor_control_panel import privilege, tor_status, torrc_gen

PKG_DIR = os.path.dirname(privilege.__file__)
DIST_PACKAGES = os.path.dirname(PKG_DIR)


class PyQtBoundaryTest(unittest.TestCase):
    """The config-logic layer must be usable by a CLI with no GUI: importing it
    must not pull in PyQt (adrelanos #48/#53/#106 -- share the config code
    without the GUI dependency). The PyQt help dialogs live in info_gui.py."""

    CONFIG_MODULES = [
        "info", "torrc_gen", "tor_status", "validators", "privilege",
        "edit_etc_resolv_conf", "repair_torrc",
    ]

    def test_config_logic_imports_without_pyqt(self):
        ## Run in a fresh interpreter with PyQt5 blocked, so a real GUI-less
        ## environment is simulated (not one where PyQt is merely already
        ## loaded). Inject the import paths via sys.path in the child code (not
        ## PYTHONPATH, which the runner's environment does not reliably pass on).
        path_setup = "import sys\n" + "".join(
            "sys.path.insert(0, %r)\n" % p for p in sys.path if p)
        block = ("for _m in ('PyQt5', 'PyQt5.QtCore', 'PyQt5.QtGui',"
                 " 'PyQt5.QtWidgets'):\n    sys.modules[_m] = None\n")
        imports = "import " + ", ".join(
            "tor_control_panel." + m for m in self.CONFIG_MODULES) + "\n"
        code = path_setup + block + imports + "print('ok')\n"
        result = subprocess.run([sys.executable, "-c", code],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                encoding="utf-8")
        self.assertEqual(
            result.returncode, 0,
            "config-logic layer imports PyQt (breaks CLI use):\n"
            + result.stderr)

    def test_info_gui_is_the_only_gui_helper_module(self):
        ## info_gui.py is where the PyQt dialogs were moved; it SHOULD need PyQt.
        self.assertTrue(
            os.path.exists(os.path.join(PKG_DIR, "info_gui.py")),
            "info_gui.py (the GUI help dialogs) is missing")

## A 'leaprun' string literal (single or double quoted).
_LEAPRUN_LITERAL = re.compile(r"""['"]leaprun['"]""")


class LeaprunInvariantTest(unittest.TestCase):
    """No privileged call may hard-code leaprun outside privilege.py."""

    def test_no_hardcoded_leaprun_outside_privilege(self):
        offenders = []
        for filename in sorted(os.listdir(PKG_DIR)):
            if not filename.endswith(".py") or filename == "privilege.py":
                continue
            path = os.path.join(PKG_DIR, filename)
            with open(path, encoding="utf-8") as handle:
                for lineno, line in enumerate(handle, 1):
                    ## Skip comment lines; leaprun is fine to mention in prose.
                    if line.lstrip().startswith("#"):
                        continue
                    if _LEAPRUN_LITERAL.search(line):
                        offenders.append(
                            "{0}:{1}: {2}".format(filename, lineno, line.strip()))
        self.assertEqual(
            offenders, [],
            "privileged calls must go through privilege.command/run, but a "
            "hard-coded 'leaprun' remains:\n" + "\n".join(offenders))


class DistroPathConsistencyTest(unittest.TestCase):
    def test_tor_status_and_torrc_gen_agree_on_dropin(self):
        ## Both modules compute the drop-in path from the same whonix check;
        ## if they ever diverge, enable/disable would edit a different file
        ## than the one gen_torrc writes.
        self.assertEqual(tor_status.torrc_file_path, torrc_gen.torrc_file_path)

    def test_dropin_lives_in_a_torrc_d_directory(self):
        self.assertTrue(
            torrc_gen.torrc_file_path.endswith(
                "/torrc.d/40_tor_control_panel.conf"),
            torrc_gen.torrc_file_path)

    def test_include_directive_would_pull_in_our_dropin(self):
        ## The %include we advertise must be one main_torrc_includes_dropin()
        ## accepts -- otherwise we'd tell users to add a line that does not
        ## actually make Tor read our drop-in.
        self.assertTrue(torrc_gen.main_torrc_includes_dropin(
            torrc_gen.torrc_include_directive()))


if __name__ == "__main__":
    unittest.main()
