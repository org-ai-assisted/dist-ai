#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Real-X render probe for the headless render test.

Run under a real windowing backend (xcb on an Xvfb display), NOT the offscreen
QPA plugin, so it exercises the actual window mapping and button-layout the user
sees. Constructs the setup_wizard_dist wizard, shows it, and reports the Back
button visibility as one JSON line on stdout; optionally saves a screenshot of
the rendered wizard (grab of the real widget tree) to a PNG.

    python3 render_probe.py {single|multi} [screenshot.png]

Meant to be spawned as a subprocess by test_headless_render.py under xvfb-run;
it deliberately forces QT_QPA_PLATFORM=xcb before importing the shared harness
(which otherwise defaults to offscreen).
"""

import json
import os
import sys

## Force the real X backend before swd_testlib's offscreen setdefault runs.
os.environ["QT_QPA_PLATFORM"] = "xcb"

import swd_testlib as T  # noqa: E402


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "single"
    png = sys.argv[2] if len(sys.argv) > 2 else ""

    if mode == "single":
        T.swd.Common.show_disclaimer = False
        T.swd.Common.wizard_steps = list(T.FINISH_ONLY_STEPS)
    else:
        T.swd.Common.show_disclaimer = True
        T.swd.Common.wizard_steps = list(T.DISCLAIMER_STEPS)

    wizard = T.swd.setup_wizard_dist()
    wizard.show()
    T.APP.processEvents()

    if mode != "single":
        ## Advance off the start page so the Back button is reachable.
        wizard.disclaimer_1.yes_button.setChecked(True)
        wizard.next()
        T.APP.processEvents()

    back = wizard.button(T.QWizard.BackButton)
    result = {
        "mode": mode,
        "back_visible": bool(back.isVisible()),
        "option_no_back_on_start": bool(
            wizard.testOption(T.QWizard.NoBackButtonOnStartPage)
        ),
    }

    if png:
        wizard.grab().save(png)
        result["screenshot"] = png

    sys.stdout.write(json.dumps(result) + "\n")


if __name__ == "__main__":
    main()
