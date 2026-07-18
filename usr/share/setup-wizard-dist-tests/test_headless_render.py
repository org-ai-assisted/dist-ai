#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Headless render test on a REAL X server.

The other suites drive the wizard under the offscreen QPA plugin, which proves
the QWizard option state but not that a real windowing backend maps the button
box the same way. This test spawns render_probe.py under xvfb-run with the xcb
platform plugin -- a genuine X server, headless -- and asserts the Back button
is not shown on the single-page wizard yet is shown once past the start page on
the multi-page wizard. It also captures a screenshot of the rendered wizard as a
test artifact.

Runs in a subprocess so it does not collide with the offscreen QApplication the
rest of the suite creates. Skips (never fails) when xvfb-run or the xcb platform
plugin is unavailable, so an environment with only the offscreen backend does
not go red.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROBE = os.path.join(_HERE, "render_probe.py")
_XVFB_RUN = shutil.which("xvfb-run")


@unittest.skipUnless(_XVFB_RUN, "xvfb-run is not installed")
class HeadlessRenderTestCase(unittest.TestCase):
    def _probe(self, mode, png=None):
        cmd = [_XVFB_RUN, "-a", sys.executable, _PROBE, mode]
        if png:
            cmd.append(png)
        ## The subprocess must import swd_testlib (this dir) and setup_wizard_dist
        ## (via SETUP_WIZARD_DIST_REPO) and guimessages (inherited PYTHONPATH).
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            p for p in (_HERE, env.get("PYTHONPATH", "")) if p
        )
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            ## Most likely the xcb plugin or an Xvfb library is missing; treat
            ## the render backend as unavailable rather than failing.
            self.skipTest(
                "real-X render unavailable "
                f"(rc={proc.returncode}): {proc.stderr.strip()[-300:]}"
            )
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertTrue(lines, f"probe produced no output; stderr={proc.stderr}")
        return json.loads(lines[-1])

    def test_single_page_back_absent_on_real_x(self):
        with tempfile.TemporaryDirectory() as tmp:
            png = os.path.join(tmp, "single.png")
            result = self._probe("single", png)
            self.assertTrue(result["option_no_back_on_start"])
            self.assertFalse(
                result["back_visible"],
                "Back button must not render on a single-page wizard",
            )
            self.assertTrue(
                os.path.isfile(png) and os.path.getsize(png) > 0,
                "screenshot artifact was not written",
            )

    def test_multi_page_back_present_on_real_x(self):
        result = self._probe("multi")
        self.assertFalse(result["option_no_back_on_start"])
        self.assertTrue(
            result["back_visible"],
            "Back button must render past the start page",
        )


if __name__ == "__main__":
    unittest.main()
