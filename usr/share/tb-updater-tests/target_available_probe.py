#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pre-flight for tb-updater-tests: resolve the tb-updater target. When the
## checkout/install cannot be found, the test modules skip at import with a
## module-level pytest.skip -- for which pytest exits 0, not 5 -- so the suite
## would report PASS though nothing ran. A non-zero exit here lets the runner
## report SKIP (77) instead.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import tb_updater_testlib as T

T.update_torbrowser_script()
T.desktop_starter_wrapper()
