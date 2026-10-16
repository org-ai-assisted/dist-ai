#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Bounded symbolic counterexample search (CrossHair) over sdwdate-gui's wire
code: the printable-ASCII byte check and parse_ipc_buf's non-success paths.

NOT formal verification and NOT a proof. CrossHair symbolically executes the
REAL functions with an SMT backend and searches for an input that breaks a
contract, but the search is BOUNDED by a time / iteration budget over an
unbounded byte domain. A clean run means ONLY "no counterexample within the
budget", never "holds for all inputs".

Subjects (imported, never copied -- a copy would drift from the shipped code):
  sdwdate_gui.sdwdate_gui_shared.check_bytes_printable
  sdwdate_gui.sdwdate_gui_shared.parse_ipc_buf

check_bytes_printable is a pure, PyQt-free bounded byte loop in CrossHair's
well-supported core (bytes iteration, int comparison).

parse_ipc_buf's SUCCESS path calls `str(msg_buf, encoding="ascii")`, a 2-arg
str() form CrossHair's stdlib model does not implement (it raises a TypeError
INSIDE the engine, not a real counterexample), so the success path cannot be
symbolically executed here -- the property / mutation / conformance lanes and
the exhaustive-enumeration lanes cover it. But every NON-success path
(short buffer, bad declared length, incomplete body, non-printable body)
RETURNS or RAISES before that line, so a precondition that confines the search
to those paths IS checkable. The contracts below carry exactly those
preconditions; a precondition-free parse_ipc_buf contract would re-hit the
engine TypeError and must not be added back.

Contracts are PEP 316 docstring pre/post-conditions on thin wrappers that CALL
the real subjects.
"""

# pylint: disable=invalid-name

from sdwdate_gui.sdwdate_gui_shared import check_bytes_printable, parse_ipc_buf


def prop_check_printable_is_total_bool(buf: bytes) -> bool:
    """
    check_bytes_printable is total: on ANY bytes it never raises and returns a
    bool. (A non-bool return or any raised exception is a counterexample.)
    post: __return__
    """
    result = check_bytes_printable(buf)
    return result is True or result is False


def prop_check_printable_matches_range(buf: bytes) -> bool:
    """
    Correctness: check_bytes_printable(buf) is True exactly when every byte is
    printable ASCII (0x20..0x7E inclusive), and False otherwise. A buffer the
    function classifies differently from this byte-range predicate is a
    counterexample.
    post: __return__
    """
    all_printable = all(0x20 <= byte <= 0x7E for byte in buf)
    return check_bytes_printable(buf) is all_printable


def prop_parse_short_buffer_unchanged(buf: bytes) -> bool:
    """
    A buffer with fewer than 2 bytes has no complete length prefix, so
    parse_ipc_buf returns it verbatim with no messages. (Pre keeps the search
    off the str() success path.)
    pre: len(buf) < 2
    post: __return__
    """
    remainder, msg_list = parse_ipc_buf(buf)
    return remainder == buf and msg_list == []


def prop_parse_rejects_bad_length(buf: bytes) -> bool:
    """
    A declared message length of 0 (empty) or above MAX_MSG_SIZE (4096) is
    rejected with ValueError, before any body is read or decoded.
    pre: len(buf) >= 2
    pre: int.from_bytes(buf[:2], "big") == 0 or int.from_bytes(buf[:2], "big") > 4096
    post: __return__
    """
    try:
        parse_ipc_buf(buf)
    except ValueError:
        return True
    return False


def prop_parse_incomplete_body_waits(buf: bytes) -> bool:
    """
    A valid declared length whose body has not fully arrived yet makes
    parse_ipc_buf return the buffer verbatim (wait for more), no messages.
    pre: len(buf) >= 2
    pre: 0 < int.from_bytes(buf[:2], "big") <= 4096
    pre: len(buf) - 2 < int.from_bytes(buf[:2], "big")
    post: __return__
    """
    remainder, msg_list = parse_ipc_buf(buf)
    return remainder == buf and msg_list == []


def prop_parse_rejects_nonprintable_body(buf: bytes) -> bool:
    """
    A complete frame whose body contains a non-printable byte is rejected with
    ValueError, before the str() decode (which is the only unsupported call).
    pre: len(buf) >= 2
    pre: 0 < int.from_bytes(buf[:2], "big") <= 4096
    pre: len(buf) - 2 >= int.from_bytes(buf[:2], "big")
    pre: not all(0x20 <= b <= 0x7E for b in buf[2 : 2 + int.from_bytes(buf[:2], "big")])
    post: __return__
    """
    try:
        parse_ipc_buf(buf)
    except ValueError:
        return True
    return False
