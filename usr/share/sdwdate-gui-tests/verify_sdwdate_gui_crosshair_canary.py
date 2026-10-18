#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Anti-silent-green + reachability canaries for the CrossHair lane.

Each function below is a DELIBERATELY FALSE contract. The lane runs
`crosshair check` on EACH one INDIVIDUALLY and REQUIRES a counterexample
(crosshair exit 1) for every one. A canary that comes back clean (exit 0) is a
VACUOUS pass -- the engine is not exercising that subject/branch at all (a broken
import, a stubbed function, an engine regression, or an UNSATISFIABLE precondition
in the real contract that shares this branch) -- so the lane turns it into a loud
FAILURE instead of trusting the real-contract result.

Two distinct failure modes are covered, which a single module-level canary cannot
separate (crosshair exits 1 if ANY contract in a module is refuted, so one live
canary would mask a dead sibling):

  1. SUBJECT-DRIVEN: the engine really runs check_bytes_printable / parse_ipc_buf
     (not a stub or a failed import).
  2. BRANCH-REACHABLE: each parse_ipc_buf non-success branch the real contracts
     rely on (short buffer, zero length, oversized length, incomplete body,
     nonprintable body) is actually REACHED -- its precondition is satisfiable.
     If a future off-by-one made a real contract's preconditions contradict,
     CrossHair would report "no counterexample" VACUOUSLY and the real lane would
     pass green while proving nothing; the matching canary here, carrying the SAME
     precondition over an inverted claim, stays UN-refuted and fails the lane.

Every canary is built on the SAME code path as the real contract it guards (no
unsupported 2-arg str() -- all stay on parse_ipc_buf's pre-decode branches), so a
refutation proves the engine really drove the subject on that branch.
"""

# pylint: disable=invalid-name

from sdwdate_gui.sdwdate_gui_shared import check_bytes_printable, parse_ipc_buf


def prop_canary_printable_always_true(buf: bytes) -> bool:
    """
    FALSE ON PURPOSE. Claims check_bytes_printable returns True for every input.
    CrossHair MUST refute this (any byte outside 0x20..0x7E, e.g. 0x00).
    post: __return__
    """
    return check_bytes_printable(buf) is True


def prop_canary_parse_short_reachable(buf: bytes) -> bool:
    """
    FALSE ON PURPOSE over the short-buffer branch. The real behavior is
    (remainder == buf, msg_list == []); this claims the opposite, so a working
    engine reaching the < 2 branch MUST refute it.
    pre: len(buf) < 2
    post: __return__
    """
    remainder, msg_list = parse_ipc_buf(buf)
    return not (remainder == buf and msg_list == [])


def prop_canary_parse_zero_length_reachable(buf: bytes) -> bool:
    """
    FALSE ON PURPOSE over the zero-length-frame branch. The real behavior RAISES
    ValueError; this returns True only when NO ValueError is raised, so a working
    engine reaching the msg_len == 0 guard MUST refute it.
    pre: len(buf) >= 2
    pre: int.from_bytes(buf[:2], "big") == 0
    post: __return__
    """
    try:
        parse_ipc_buf(buf)
    except ValueError:
        return False
    return True


def prop_canary_parse_oversized_length_reachable(buf: bytes) -> bool:
    """
    FALSE ON PURPOSE over the oversized-length branch (msg_len > MAX_MSG_SIZE).
    The real behavior RAISES ValueError; returns True only when none is raised,
    so a working engine reaching the cap guard MUST refute it.
    pre: len(buf) >= 2
    pre: int.from_bytes(buf[:2], "big") > 4096
    post: __return__
    """
    try:
        parse_ipc_buf(buf)
    except ValueError:
        return False
    return True


def prop_canary_parse_incomplete_body_reachable(buf: bytes) -> bool:
    """
    FALSE ON PURPOSE over the incomplete-body branch. The real behavior is
    (remainder == buf, msg_list == []); this claims the opposite, so a working
    engine reaching the wait-for-more branch MUST refute it.
    pre: len(buf) >= 2
    pre: 0 < int.from_bytes(buf[:2], "big") <= 4096
    pre: len(buf) - 2 < int.from_bytes(buf[:2], "big")
    post: __return__
    """
    remainder, msg_list = parse_ipc_buf(buf)
    return not (remainder == buf and msg_list == [])


def prop_canary_parse_nonprintable_body_reachable(buf: bytes) -> bool:
    """
    FALSE ON PURPOSE over the nonprintable-body branch. The real behavior RAISES
    ValueError; returns True only when none is raised, so a working engine
    reaching the printable check MUST refute it.
    pre: len(buf) >= 2
    pre: 0 < int.from_bytes(buf[:2], "big") <= 4096
    pre: len(buf) - 2 >= int.from_bytes(buf[:2], "big")
    pre: not all(0x20 <= b <= 0x7E for b in buf[2 : 2 + int.from_bytes(buf[:2], "big")])
    post: __return__
    """
    try:
        parse_ipc_buf(buf)
    except ValueError:
        return False
    return True


def prop_canary_parse_max_boundary_reachable(buf: bytes) -> bool:
    """
    FALSE ON PURPOSE over the msg_len == MAX_MSG_SIZE (4096) accept-boundary,
    checked on an incomplete body (stays off the str() success path). The real
    behavior is (remainder == buf, msg_list == []); this claims the opposite, so
    a working engine reaching the exact-4096 boundary MUST refute it. Guards
    prop_parse_accepts_max_boundary specifically: the general incomplete-body
    canary is satisfiable at any 0 < msg_len <= 4096, so it would stay refuted
    (lane green) even if the == 4096 precondition went unsatisfiable and the
    boundary contract passed VACUOUSLY.
    pre: len(buf) >= 2
    pre: int.from_bytes(buf[:2], "big") == 4096
    pre: len(buf) - 2 < 4096
    post: __return__
    """
    remainder, msg_list = parse_ipc_buf(buf)
    return not (remainder == buf and msg_list == [])
