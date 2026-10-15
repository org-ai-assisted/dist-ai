#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Bounded symbolic counterexample search (CrossHair) over sdwdate-gui's
printable-ASCII byte check.

NOT formal verification and NOT a proof. CrossHair symbolically executes the
REAL function with an SMT backend and searches for an input that breaks a
contract, but the search is BOUNDED by a time / iteration budget over an
unbounded byte domain. A clean run means ONLY "no counterexample within the
budget", never "holds for all inputs".

Subject (imported, never copied -- a copy would drift from the shipped code):
  sdwdate_gui.sdwdate_gui_shared.check_bytes_printable

Scope is JUST this function: it is a pure, PyQt-free bounded byte loop that
lives in CrossHair's well-supported core (bytes iteration, int comparison).
The wire-frame parser parse_ipc_buf is OUT of scope: it calls
`str(msg_buf, encoding="ascii")`, a 2-argument str() form CrossHair's stdlib
model does not support (it raises inside the engine, not a real finding), so it
cannot be symbolically executed here. The property fuzz / mutation / conformance
lanes cover parse_ipc_buf instead.

Contracts are PEP 316 docstring post-conditions on thin wrappers that CALL the
real subject.
"""

# pylint: disable=invalid-name

from sdwdate_gui.sdwdate_gui_shared import check_bytes_printable


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
