#!/usr/bin/python3 -Bsu

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
Needs python3-hypothesis (Debian apt). Its absence is a FAILURE, not a skip:
it is a declared dependency, and skipping reported the whole privleap suite
as PASS with none of these properties having run.
"""

import os
import sys

import pytest

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

## Imported, NOT importorskip'd. python3-hypothesis is a declared dependency
## of this suite (it is in the CI apt list), so its absence is a broken
## environment, not a reason to pass. Skipping here reported the whole
## privleap suite as PASS while the property layer ran nothing at all.
# pylint: disable=wrong-import-position
from hypothesis import example, given, settings, strategies as st  # noqa: E402

from pl_testlib import import_privleap  # noqa: E402

try:
    pl = import_privleap()
except SystemExit as exc:
    ## Mirror pl_testlib's split: 77 means nothing was asked for and privleap
    ## is genuinely absent, so skip. Anything else means a target WAS named
    ## and is broken -- that must surface as a failure, not a skip.
    if exc.code == 77:
        pytest.skip('privleap library not found', allow_module_level=True)
    raise

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

        assert re.fullmatch(r'[-A-Za-z0-9_.]+', s) is not None


@given(st.text())
@settings(max_examples=400)
def test_accepted_user_name_is_safe(s: str) -> None:
    """A string accepted as a USER_GROUP_NAME matches the POSIX-ish user name
    charset and length bound."""
    if PrivleapCommon.validate_id(s, PrivleapValidateType.USER_GROUP_NAME):
        assert 1 <= len(s) <= 100
        import re  # pylint: disable=import-outside-toplevel

        assert re.fullmatch(r'[a-z_][-a-z0-9_]*\$?', s) is not None


@given(st.text(), st.sampled_from(list(PrivleapValidateType)))
@settings(max_examples=600)
def test_no_accepted_id_can_smuggle_protocol_bytes(
    s: str, vtype: object
) -> None:
    """
    NOTHING validate_id accepts, for ANY type, may carry whitespace, a control
    byte or a non-ASCII character.

    The per-type properties above pin two of the four types individually; this
    one is total over the enum, so a validate type added later is covered the
    moment it exists rather than whenever someone remembers to write its
    property. These are the bytes that would let a name split a protocol field
    or a config line.
    """

    if not PrivleapCommon.validate_id(s, vtype):
        return
    assert s.isascii()
    assert not any(ch.isspace() for ch in s)
    assert all(ch.isprintable() for ch in s)
    assert '\0' not in s


@given(st.text(min_size=101), st.sampled_from(list(PrivleapValidateType)))
@settings(max_examples=200)
def test_length_bound_is_total(s: str, vtype: object) -> None:
    """The 100-character bound applies to every type, not just the ones whose
    regex happens to be anchored."""

    assert PrivleapCommon.validate_id(s, vtype) is False


@given(st.text())
@settings(max_examples=400)
def test_accepted_config_file_is_a_bare_filename(s: str) -> None:
    """
    A string accepted as a CONFIG_FILE is joined onto the config directory, so
    it must be a bare filename: anything that could traverse out of that
    directory, or name a different one, must be rejected.
    """

    if not PrivleapCommon.validate_id(s, PrivleapValidateType.CONFIG_FILE):
        return
    assert s.endswith('.conf')
    assert '/' not in s
    assert os.sep not in s
    assert os.path.basename(s) == s
    assert s not in ('.', '..')
    assert not s.startswith('.')


@given(st.text())
@settings(max_examples=400)
def test_accepted_uid_converts_to_a_non_negative_int(s: str) -> None:
    """A string accepted as a USER_GROUP_UID reaches int(); it must survive
    that without raising and without being negative."""

    if not PrivleapCommon.validate_id(s, PrivleapValidateType.USER_GROUP_UID):
        return
    assert int(s) >= 0


@given(st.text())
@settings(max_examples=200)
def test_normalize_user_id_is_total_and_returns_a_valid_name(s: str) -> None:
    """
    normalize_user_id takes an untrusted name-or-UID off the wire and its
    result is used downstream as an identity. So for ANY input it must return
    either None or something that is itself a valid user name -- never raise,
    and never hand back the raw UID digits it was given.
    """

    result = PrivleapCommon.normalize_user_id(s)
    if result is None:
        return
    assert PrivleapCommon.validate_id(
        result, PrivleapValidateType.USER_GROUP_NAME
    )
    ## Idempotent: normalizing an already-normalized name is a no-op, so a
    ## caller cannot get a different identity by normalizing twice.
    assert PrivleapCommon.normalize_user_id(result) == result


@given(st.text())
@settings(max_examples=200)
def test_normalize_group_id_is_total_and_returns_a_valid_name(s: str) -> None:
    """Same contract as normalize_user_id, for groups."""

    result = PrivleapCommon.normalize_group_id(s)
    if result is None:
        return
    assert PrivleapCommon.validate_id(
        result, PrivleapValidateType.USER_GROUP_NAME
    )
    assert PrivleapCommon.normalize_group_id(result) == result


@given(st.text())
@settings(max_examples=200)
def test_check_secure_file_permissions_is_total(s: str) -> None:
    """
    check_secure_file_permissions promises False rather than an exception for
    a file it cannot examine. A path is not always examinable: an embedded NUL
    makes os.stat raise ValueError, not OSError, which escaped a catch of
    OSError alone.
    """

    assert isinstance(PrivleapCommon.check_secure_file_permissions(s), bool)


@given(st.integers())
@example(-1)        ## OSError boundary (negative fd)
@example(2**63)     ## OverflowError boundary (os.stat out-of-range fd)
@settings(max_examples=200)
def test_check_secure_file_permissions_is_total_over_int_fds(fd: int) -> None:
    """
    check_secure_file_permissions also accepts an integer file descriptor and
    must stay total there too. A negative fd raises OSError, but an out-of-range
    fd (e.g. >= 2**63) makes os.stat raise OverflowError, not OSError -- which
    escaped a catch of (OSError, ValueError) alone.
    """

    assert isinstance(PrivleapCommon.check_secure_file_permissions(fd), bool)
