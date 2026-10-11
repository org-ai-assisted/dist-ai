#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Shared import guard for the sdwdate-gui test subject.

The suites import the subject at module load and skip when it is absent. The
trap: catching ModuleNotFoundError and skipping unconditionally also skips when
sdwdate_gui IS installed but a DEPENDENCY (pyinotify, PyQt5, schema, ...) or a
SUBMODULE is missing -- a broken install then reads GREEN. Only a genuinely
absent sdwdate_gui PACKAGE is a legitimate skip; anything else is a broken
install and must fail loud (dist-ai: a required dependency's absence is FATAL,
never a silent skip).
"""

import unittest
from typing import NoReturn


def skip_if_subject_absent(exc: ModuleNotFoundError) -> NoReturn:
    """
    Raise SkipTest when the sdwdate_gui PACKAGE itself is absent; otherwise
    re-raise `exc`. `exc.name` is exactly 'sdwdate_gui' only when the top-level
    package cannot be found; a missing dependency or submodule carries that
    module's name instead and so fails loud.
    """

    if exc.name == "sdwdate_gui":
        raise unittest.SkipTest(
            "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
            "or set PYTHONPATH to its dist-packages directory"
        ) from exc
    raise exc
