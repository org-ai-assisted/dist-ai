#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Anti-silent-green canary for the CrossHair lane.

A DELIBERATELY FALSE contract over the real check_bytes_printable. The lane
runs `crosshair check` on it and REQUIRES a counterexample (crosshair exit 1):
if this ever comes back clean, CrossHair is not actually exercising the subject
(a broken import, a stubbed function, an engine regression) and every clean
result on the real contracts would be a vacuous false pass. So the canary turns
a vacuous run into a loud lane FAILURE.

The claim below -- that check_bytes_printable is ALWAYS True -- is false for any
non-printable byte (e.g. 0x00), so a working CrossHair refutes it fast. It is
based on the same bounded byte loop as the real contracts (no unsupported
stdlib call), so a refutation here proves the engine really ran the subject.
"""

# pylint: disable=invalid-name

from sdwdate_gui.sdwdate_gui_shared import check_bytes_printable


def prop_canary_printable_always_true(buf: bytes) -> bool:
    """
    FALSE ON PURPOSE. Claims check_bytes_printable returns True for every input.
    CrossHair MUST refute this (any byte outside 0x20..0x7E, e.g. 0x00).
    post: __return__
    """
    return check_bytes_printable(buf) is True
