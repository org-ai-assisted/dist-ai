#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted


def pytest_configure(config):
    ## Register the 'userns' marker so the hardened container lane (which runs the
    ## suite without a -m filter) emits no unknown-marker warning, and the
    ## bare-runner lane can select these tests with 'pytest -m userns'.
    config.addinivalue_line(
        "markers",
        "userns: requires unprivileged user namespaces; runs only in the "
        "bare-runner userns CI lane (the hardened container cannot provide them)")
