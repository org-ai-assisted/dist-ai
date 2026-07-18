#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for setup-wizard-dist.

Focus: the Back button must be hidden when the wizard has a single page (the
finish page, the default once the disclaimer is disabled) because there is
nowhere to go back to, and it must remain available on a multi-page (disclaimer
enabled) wizard. A plain QWidget.hide() on the Back button does NOT survive
QWizard rebuilding its button layout on show(); the wizard must set the
NoBackButtonOnStartPage option instead. This suite drives the real
setup_wizard_dist.setup_wizard_dist wizard under the Qt offscreen platform
plugin -- no X server, no root, no network.

Also checked: DisclaimerPage1.nextId() routing (accept -> disclaimer 2, reject
-> finish page) and that the shipped module is pure ASCII.

The wizard under test resolves from SETUP_WIZARD_DIST_REPO (a checkout root),
else from the installed package on the default sys.path. guimessages (from
helper-scripts) must be importable; when it or PyQt5 is missing the suite skips
rather than fails.
"""

# pylint: disable=wrong-import-position,no-name-in-module,protected-access

import os
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

## Put the setup-wizard-dist checkout's dist-packages ahead of the installed
## copy so a --component-root run tests the CHECKOUT, not a stale install.
_REPO = os.environ.get("SETUP_WIZARD_DIST_REPO", "").strip()
if _REPO:
    _CANDIDATE = os.path.join(_REPO, "usr", "lib", "python3", "dist-packages")
    if not os.path.isdir(os.path.join(_CANDIDATE, "setup_wizard_dist")):
        raise SystemExit(
            f"SETUP_WIZARD_DIST_REPO={_REPO} does not contain "
            "usr/lib/python3/dist-packages/setup_wizard_dist"
        )
    sys.path.insert(0, _CANDIDATE)

try:
    from PyQt5.QtWidgets import QApplication, QWizard
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "PyQt5 is not importable; install python3-pyqt5"
    ) from exc

try:
    ## Importing the module runs Common's body, which reads distro markers and
    ## (as root) creates /var/cache/setup-dist/status-files. A non-root run
    ## where that directory does not already exist raises PermissionError; skip
    ## rather than fail, matching the suite's no-root contract.
    from setup_wizard_dist import setup_wizard_dist as swd
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "setup_wizard_dist / guimessages is not importable; install the "
        "'setup-wizard-dist' package or set SETUP_WIZARD_DIST_REPO plus a "
        "helper-scripts PYTHONPATH"
    ) from exc
except PermissionError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "setup_wizard_dist import needs to create /var/cache/setup-dist "
        "(run as root or pre-create the directory)"
    ) from exc

## The wizard reads translations from an absolute install path; point it at the
## checkout's copy so setupUi() works from a --component-root run.
if _REPO:
    _YAML = os.path.join(
        _REPO, "usr", "share", "translations", "setup-wizard-dist.yaml"
    )
    if os.path.isfile(_YAML):
        swd.Common.translations_path = _YAML

## The wizard's __init__ shells out to /usr/bin/package-installed-check, which
## is absent in a bare test environment. Stub it out (return non-zero == "not
## installed") so construction does not depend on it.
swd.call = lambda *args, **kwargs: 1  # noqa: E731

_APP = QApplication.instance() or QApplication(["setup-wizard-dist-tests"])


class BackButtonTestCase(unittest.TestCase):
    """The Back button visibility contract, single vs multi page."""

    def _make_wizard(self, show_disclaimer, steps):
        swd.Common.show_disclaimer = show_disclaimer
        swd.Common.wizard_steps = list(steps)
        wizard = swd.setup_wizard_dist()
        self.addCleanup(wizard.deleteLater)
        return wizard

    def test_single_page_hides_back(self):
        wizard = self._make_wizard(False, ["finish_page"])
        self.assertEqual(len(wizard.pageIds()), 1)
        self.assertTrue(
            wizard.testOption(QWizard.NoBackButtonOnStartPage),
            "single-page wizard must set NoBackButtonOnStartPage",
        )
        wizard.show()
        _APP.processEvents()
        self.assertFalse(
            wizard.button(QWizard.BackButton).isVisible(),
            "Back button must not be visible on a single-page wizard",
        )

    def test_multi_page_keeps_back(self):
        wizard = self._make_wizard(
            True, ["disclaimer_1", "disclaimer_2", "finish_page"]
        )
        self.assertEqual(len(wizard.pageIds()), 3)
        self.assertFalse(
            wizard.testOption(QWizard.NoBackButtonOnStartPage),
            "multi-page wizard must not suppress the Back button",
        )
        wizard.show()
        _APP.processEvents()
        ## Accept page 1 so nextId() routes to disclaimer 2 (a non-start page).
        wizard.disclaimer_1.yes_button.setChecked(True)
        wizard.next()
        _APP.processEvents()
        self.assertTrue(
            wizard.button(QWizard.BackButton).isVisible(),
            "Back button must be available past the start page",
        )


class NextIdRoutingTestCase(unittest.TestCase):
    """DisclaimerPage1.nextId() branch routing."""

    def setUp(self):
        swd.Common.wizard_steps = [
            "disclaimer_1",
            "disclaimer_2",
            "finish_page",
        ]

    def test_accept_routes_to_disclaimer_2(self):
        page = swd.DisclaimerPage1()
        self.addCleanup(page.deleteLater)
        page.yes_button.setChecked(True)
        self.assertEqual(
            page.nextId(), swd.Common.wizard_steps.index("disclaimer_2")
        )

    def test_reject_routes_to_finish_page(self):
        page = swd.DisclaimerPage1()
        self.addCleanup(page.deleteLater)
        page.no_button.setChecked(True)
        self.assertEqual(
            page.nextId(), swd.Common.wizard_steps.index("finish_page")
        )


class SourceHygieneTestCase(unittest.TestCase):
    """The shipped module must stay pure ASCII (R-001)."""

    def test_module_is_ascii(self):
        source_path = swd.__file__
        with open(source_path, "rb") as handle:
            data = handle.read()
        try:
            data.decode("ascii")
        except UnicodeDecodeError as exc:  # pragma: no cover
            self.fail(f"{source_path} contains non-ASCII bytes: {exc}")


if __name__ == "__main__":
    unittest.main()
