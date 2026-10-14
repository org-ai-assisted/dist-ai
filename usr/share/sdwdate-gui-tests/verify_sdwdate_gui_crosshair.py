#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Bounded symbolic counterexample search (CrossHair) over sdwdate-gui's PyQt-free
wire-frame parsers.

NOT formal verification and NOT a proof. CrossHair symbolically executes the
REAL functions with an SMT backend and searches for an input that breaks a
contract, but the search is BOUNDED by a time / iteration budget and the input
domain here is unbounded (arbitrary-length bytes). A clean run therefore means
ONLY "no counterexample was found within the budget", never "holds for all
inputs". For an exhaustive, sound guarantee over a finite domain, see the
Z3 + full-enumeration `*-tests-verify` suites (e.g. stdisplay / unicode-show);
this lane is the complementary bounded search for the unbounded-input parsers
those techniques cannot enumerate.

Subject (imported, never copied -- a copy would drift from the shipped code):
  sdwdate_gui.sdwdate_gui_shared.parse_ipc_command
  sdwdate_gui.sdwdate_gui_shared.check_bytes_printable

Scope is deliberately limited to these two: they are pure and PyQt-free, and
live in CrossHair's well-supported core (ints, bytes, slicing, int.from_bytes,
a bounded byte loop, ascii decode, str.split). The octal-escape decoder is
out of scope on purpose -- it is PyQt-dependent and leans on re.sub + a
re.Match callback + int(str, 8), where CrossHair's stdlib models are imperfect,
so a clean result there would be weak and misleading.

Contracts are PEP 316 docstring post-conditions on thin wrapper functions that
CALL the real subject. The "raises only ValueError" property is expressed by
catching ValueError (the one permitted type) and letting any other exception
escape the wrapper, which CrossHair reports as a counterexample.
"""

# pylint: disable=invalid-name

from sdwdate_gui.sdwdate_gui_shared import (
    parse_ipc_command,
    check_bytes_printable,
    MAX_MSG_SIZE,
)


def prop_parse_raises_only_valueerror_and_is_suffix(sock_buf: bytes) -> bool:
    """
    On ANY bytes input, parse_ipc_command either raises ValueError or returns a
    new buffer that is a SUFFIX of the input and no longer than it (never
    grows). Any exception type other than ValueError escapes this wrapper and is
    reported as a counterexample.
    post: __return__
    """
    try:
        new_buf, _name, _parts = parse_ipc_command(sock_buf)
    except ValueError:
        return True
    return len(new_buf) <= len(sock_buf) and sock_buf.endswith(new_buf)


def prop_parse_progress_or_unchanged(sock_buf: bytes) -> bool:
    """
    Buffer-protocol progress: when a full frame is present (declared length
    within the cap and enough bytes buffered) the buffer STRICTLY shrinks;
    otherwise it is returned UNCHANGED. ValueError (a kick) is acceptable.
    post: __return__
    """
    try:
        new_buf, _name, _parts = parse_ipc_command(sock_buf)
    except ValueError:
        return True
    if len(sock_buf) >= 2:
        msg_len = int.from_bytes(sock_buf[:2], byteorder="big", signed=False)
        if msg_len <= MAX_MSG_SIZE and len(sock_buf) >= msg_len + 2:
            return len(new_buf) < len(sock_buf)
    return len(new_buf) == len(sock_buf)


def prop_check_printable_is_total_bool(buf: bytes) -> bool:
    """
    check_bytes_printable is total: on ANY bytes it never raises and returns a
    bool. (A non-bool return or any raised exception is a counterexample.)
    post: __return__
    """
    result = check_bytes_printable(buf)
    return result is True or result is False
