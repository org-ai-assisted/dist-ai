#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared setup for the setup-wizard-dist suite.

Puts the wizard under test on sys.path (from SETUP_WIZARD_DIST_REPO, else the
installed package), forces the Qt offscreen platform plugin, points the wizard
at the checkout's translations, and stubs the /usr/bin/package-installed-check
call so wizard construction has no external dependency. Importing this module
raises unittest.SkipTest when PyQt5 or guimessages is unavailable, or when a
non-root run cannot create /var/cache/setup-dist; unittest reports the importing
test module as skipped rather than failed.

Test modules do `import swd_testlib as T` and use T.swd, T.APP, and
T.make_wizard(...).
"""

# pylint: disable=wrong-import-position,no-name-in-module

import os
import re
import sys
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

## Prefer the checkout under SETUP_WIZARD_DIST_REPO so a --component-root run
## tests the checkout, not a stale installed copy.
REPO = os.environ.get("SETUP_WIZARD_DIST_REPO", "").strip()
if REPO:
    _CANDIDATE = os.path.join(REPO, "usr", "lib", "python3", "dist-packages")
    if not os.path.isdir(os.path.join(_CANDIDATE, "setup_wizard_dist")):
        raise SystemExit(
            f"SETUP_WIZARD_DIST_REPO={REPO} does not contain "
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

## Point translations at the checkout copy so setupUi() resolves keys from a
## --component-root run.
TRANSLATIONS_YAML = ""
if REPO:
    _YAML = os.path.join(
        REPO, "usr", "share", "translations", "setup-wizard-dist.yaml"
    )
    if os.path.isfile(_YAML):
        swd.Common.translations_path = _YAML
        TRANSLATIONS_YAML = _YAML
else:
    TRANSLATIONS_YAML = swd.Common.translations_path

## Construction shells out to /usr/bin/package-installed-check; stub it to a
## deterministic "not installed" so tests do not depend on the host.
swd.call = lambda *args, **kwargs: 1  # noqa: E731

## The original import-time environment, restored by make_wizard's cleanup.
ORIG_ENVIRONMENT = swd.Common.environment

## One QApplication for the whole process.
APP = QApplication.instance() or QApplication(["setup-wizard-dist-tests"])

DISCLAIMER_STEPS = ["disclaimer_1", "disclaimer_2", "finish_page"]
FINISH_ONLY_STEPS = ["finish_page"]

## Every translation key the wizard resolves via self._('...').
with open(swd.__file__) as _swd_src:
    SOURCE_KEYS = frozenset(
        re.findall(r"self\._\('([^']+)'\)", _swd_src.read())
    )


def make_wizard(testcase, show_disclaimer, steps, environment=None):
    """Build a wizard with the given page configuration.

    Mutates the module-level Common state the wizard reads at construction and
    registers cleanups to restore it and dispose the widget.
    """
    swd.Common.show_disclaimer = show_disclaimer
    swd.Common.wizard_steps = list(steps)
    if environment is not None:
        swd.Common.environment = environment
        testcase.addCleanup(setattr, swd.Common, "environment", ORIG_ENVIRONMENT)
    wizard = swd.setup_wizard_dist()
    testcase.addCleanup(wizard.deleteLater)
    return wizard


__all__ = [
    "APP",
    "DISCLAIMER_STEPS",
    "FINISH_ONLY_STEPS",
    "ORIG_ENVIRONMENT",
    "QWizard",
    "REPO",
    "SOURCE_KEYS",
    "TRANSLATIONS_YAML",
    "make_wizard",
    "swd",
]
