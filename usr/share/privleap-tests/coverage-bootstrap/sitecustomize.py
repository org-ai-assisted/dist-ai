#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Starts coverage measurement in a freshly executed Python process.

privleapd, and the shim it runs actions through, are separate processes. A
coverage run that only measures the harness therefore reports the daemon's own
code as untested, which is the opposite of the truth. Python imports
sitecustomize automatically at interpreter start, so putting this directory on
PYTHONPATH is what lets those child processes join the measurement.

Inert unless COVERAGE_PROCESS_START is set, so it costs nothing when a suite
is run normally.
"""

import os

if os.environ.get('COVERAGE_PROCESS_START'):
    try:
        # pylint: disable=import-outside-toplevel,import-error
        # Rationale:
        #   import-outside-toplevel: importing coverage unconditionally would
        #     make every measured process pay for it.
        #   import-error: python3-coverage is only needed when measuring.
        import coverage

        coverage.process_startup()
    except Exception:  # nosec B110 # pylint: disable=broad-exception-caught
        ## Measurement is never worth breaking the process being measured.
        pass
