#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Headless render tests on REAL windowing backends: X11 and Wayland.

The rest of the suite drives the wizard under the offscreen QPA plugin, which
proves the QWizard option state but not that a real windowing backend maps the
button box the same way. These tests spawn render_probe.py against a genuine,
headless display server -- X11 via xvfb-run + the xcb plugin, and Wayland via a
headless weston + the wayland plugin -- and assert the Back button is not mapped
on the single-page wizard yet is mapped once past the start page on the
multi-page wizard, on BOTH backends. A screenshot of each rendered wizard is
saved as an artifact.

The probe runs in a subprocess so it does not collide with the offscreen
QApplication the rest of the suite creates. These tests do NOT skip: a missing
or broken backend is a real failure, so the render path is always exercised.
The required tools (xvfb + xcb libs, weston + qtwayland5) are declared in the
consumer's dm-consumer.yml.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROBE = os.path.join(_HERE, "render_probe.py")
_WAYLAND_RUN = os.path.join(_HERE, "wayland-run.sh")
_TIMEOUT = 180


def _env_for(platform):
    """Subprocess environment: the probe's import path plus the real backend."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (_HERE, env.get("PYTHONPATH", "")) if p
    )
    ## Override the entrypoint's QT_QPA_PLATFORM=offscreen for the real render.
    env["QT_QPA_PLATFORM"] = platform
    return env


def _parse(proc):
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert lines, (
        f"probe produced no output; rc={proc.returncode} "
        f"stderr={proc.stderr[-500:]}"
    )
    return json.loads(lines[-1])


class _RenderContract:
    """Shared assertions; subclasses provide the backend launcher."""

    backend = None
    platform = None

    def _command(self, mode, png):
        raise NotImplementedError

    def _run(self, mode, png=None):
        proc = subprocess.run(
            self._command(mode, png),
            capture_output=True,
            text=True,
            env=_env_for(self.platform),
            timeout=_TIMEOUT,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"[{self.backend}] render failed (rc={proc.returncode}): "
            f"{proc.stderr[-500:]}",
        )
        return _parse(proc)

    def test_single_page_back_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            png = os.path.join(tmp, f"{self.backend}_single.png")
            result = self._run("single", png)
            self.assertTrue(result["option_no_back_on_start"])
            self.assertFalse(
                result["back_visible"],
                f"[{self.backend}] Back button must not render on a "
                "single-page wizard",
            )
            self.assertTrue(
                os.path.isfile(png) and os.path.getsize(png) > 0,
                f"[{self.backend}] screenshot artifact was not written",
            )

    def test_multi_page_back_present(self):
        result = self._run("multi")
        self.assertFalse(result["option_no_back_on_start"])
        self.assertTrue(
            result["back_visible"],
            f"[{self.backend}] Back button must render past the start page",
        )


class X11RenderTestCase(_RenderContract, unittest.TestCase):
    backend = "x11"
    platform = "xcb"

    def _command(self, mode, png):
        cmd = ["xvfb-run", "-a", sys.executable, _PROBE, mode]
        if png:
            cmd.append(png)
        return cmd


class WaylandRenderTestCase(_RenderContract, unittest.TestCase):
    backend = "wayland"
    platform = "wayland"

    def _command(self, mode, png):
        cmd = ["bash", _WAYLAND_RUN, sys.executable, _PROBE, mode]
        if png:
            cmd.append(png)
        return cmd


if __name__ == "__main__":
    unittest.main()
