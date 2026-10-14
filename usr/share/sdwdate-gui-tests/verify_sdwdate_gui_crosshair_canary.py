#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Anti-silent-green canary for the CrossHair lane.

A DELIBERATELY FALSE contract over the real parse_ipc_command. The lane runs
`crosshair check` on it and REQUIRES a counterexample (crosshair exit 1): if
this ever comes back clean, CrossHair is not actually exercising the subject
(a broken import, a stubbed function, an engine regression) and every clean
result on the real contracts would be a vacuous false pass. So the canary turns
a vacuous run into a loud lane FAILURE.

The claim below -- that the returned buffer is ALWAYS strictly shorter than the
input -- is false for a partial frame (buffer unchanged) and for a short buffer
(empty / under two bytes), so a working CrossHair finds a counterexample fast.
"""

# pylint: disable=invalid-name

from sdwdate_gui.sdwdate_gui_shared import parse_ipc_command


def prop_canary_buffer_always_strictly_shrinks(sock_buf: bytes) -> bool:
    """
    FALSE ON PURPOSE. Claims parse_ipc_command's returned buffer is always
    strictly shorter than the input. CrossHair MUST refute this.
    post: __return__
    """
    try:
        new_buf, _name, _parts = parse_ipc_command(sock_buf)
    except ValueError:
        return True
    return len(new_buf) < len(sock_buf)
