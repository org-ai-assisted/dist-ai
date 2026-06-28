#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Hypothesis property-based tests for privleap's pure parser helpers.

Layer 1 of the fuzzing convention (see README): complements the in-process
parser fuzzer and the Atheris harness by generating arbitrary inputs and
asserting invariants that must hold for ALL inputs to the small,
security-relevant pure functions in privleap.privleap:

  - the argument-count codec is a faithful round-trip over its whole domain
    (0..63) and rejects everything outside it, never with a surprise exception;
  - validate_id never raises and is a pure predicate; and a string it accepts
    as a SIGNAL_NAME / USER_GROUP_NAME really is within the documented charset
    and length bound (so a name that passes validation cannot smuggle a space
    or a control byte into the protocol).

Run via pytest (the privleap-tests launcher does this automatically):
    PRIVLEAP_REPO=<checkout> python3 -m pytest --import-mode=importlib \\
        usr/share/privleap-tests/test_property.py
Needs python3-hypothesis (Debian apt); skipped cleanly if it is absent.
"""

import os
import sys

import pytest

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

pytest.importorskip("hypothesis")
# pylint: disable=wrong-import-position
from hypothesis import given, settings, strategies as st  # noqa: E402

from pl_testlib import import_privleap  # noqa: E402

try:
    pl = import_privleap()
except SystemExit:
    pytest.skip("privleap library not found", allow_module_level=True)

PrivleapCommon = pl.PrivleapCommon
PrivleapValidateType = pl.PrivleapValidateType


@given(st.integers(min_value=0, max_value=63))
def test_arg_count_roundtrip(n: int) -> None:
    """Every count in range encodes to a single char and decodes back."""
    chr_val = PrivleapCommon.int_to_msg_arg_count(n)
    assert len(chr_val) == 1
    assert PrivleapCommon.msg_arg_count_to_int(chr_val) == n


@given(st.integers())
def test_arg_count_encode_range(n: int) -> None:
    """Encoding accepts exactly 0..63 and raises ValueError otherwise."""
    if 0 <= n <= 63:
        PrivleapCommon.int_to_msg_arg_count(n)
    else:
        with pytest.raises(ValueError):
            PrivleapCommon.int_to_msg_arg_count(n)


@given(st.text())
def test_arg_count_decode_never_surprises(s: str) -> None:
    """Decoding any string raises only ValueError, never another type, and any
    success is in 0..63."""
    try:
        value = PrivleapCommon.msg_arg_count_to_int(s)
    except ValueError:
        return
    assert 0 <= value <= 63


@given(st.text(), st.sampled_from(list(PrivleapValidateType)))
@settings(max_examples=400)
def test_validate_id_never_raises(s: str, vtype: object) -> None:
    """validate_id is a total predicate: a bool for any input, never raises."""
    assert isinstance(PrivleapCommon.validate_id(s, vtype), bool)


@given(st.text())
@settings(max_examples=400)
def test_accepted_signal_name_is_safe(s: str) -> None:
    """A string accepted as a SIGNAL_NAME is within the documented charset and
    length bound -- it cannot carry a space, control byte, or non-ASCII."""
    if PrivleapCommon.validate_id(s, PrivleapValidateType.SIGNAL_NAME):
        assert 1 <= len(s) <= 100
        import re  # pylint: disable=import-outside-toplevel

        assert re.fullmatch(r"[-A-Za-z0-9_.]+", s) is not None


@given(st.text())
@settings(max_examples=400)
def test_accepted_user_name_is_safe(s: str) -> None:
    """A string accepted as a USER_GROUP_NAME matches the POSIX-ish user name
    charset and length bound."""
    if PrivleapCommon.validate_id(s, PrivleapValidateType.USER_GROUP_NAME):
        assert 1 <= len(s) <= 100
        import re  # pylint: disable=import-outside-toplevel

        assert re.fullmatch(r"[a-z_][-a-z0-9_]*\$?", s) is not None
