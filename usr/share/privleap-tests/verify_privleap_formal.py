#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Formal verification of privleap's argument-count codec -- the pure framing
primitive on the untrusted wire path. Every privleap message carries its
argument count as one Base64-like character (int_to_msg_arg_count /
msg_arg_count_to_int in privleap.py), which an unprivileged client controls, so
a decode that returned an out-of-range or wrong count would mis-frame the
message the server then parses.

Two complementary methods per theorem, mirroring the stdisplay / secure-terminal
verify_*_formal.py suites:
  - Z3 (SMT): prove the property over a SYMBOLIC model of the codec's arithmetic,
    so it holds for the whole domain, not sampled points.
  - ENUMERATION against the REAL functions: run the ACTUAL codec from the
    checkout over its ENTIRE input domain (all 64 counts; every Unicode code
    point as a decode input) and confirm it matches the model point-for-point.
    This anchors the symbolic model to the real code, so the proof is about
    privleap's codec, not a detached copy.
  - CANARIES: every method is also run against a deliberately BROKEN model that
    it MUST catch, so a green run has teeth.

The codec alphabet is standard Base64 order: 0-9, A-Z, a-z, '+', '/', mapping
counts 0..63 to one character and back.

Theorems:
  T1  Bijection -- decode(encode(n)) == n for every count 0..63, so a client
      cannot make the server read a count other than the one it framed.
  T2  Decode soundness -- a character decodes iff it is in the alphabet, and any
      accepted character maps to a count in 0..63; every other character (all
      1.1M code points outside the alphabet) is REJECTED, never silently
      mapped to a value.
  T3  Encode range -- every count 0..63 encodes to exactly one alphabet
      character, and a count outside 0..63 is rejected rather than encoded.

SCOPE -- honest. This verifies the pure integer/character codec. The id
validator (regex over whole strings) and the authorization decision (which
resolves uids/gids via the system password database) are not pure integer
functions and are covered by the Hypothesis property tests and the
authorization reference-model equivalence check in authorizer_test.py.
"""

import sys

sys.dont_write_bytecode = True

try:
    import z3
except (ImportError, OSError) as exc:  # any z3 load failure must FAIL clean
    sys.stderr.write(
        "privleap-tests(verify_privleap_formal): FAIL missing dependency "
        "(z3 / python3-z3): %s\n" % exc
    )
    sys.exit(1)

## Import privleap the way the rest of the suite does: honour PRIVLEAP_REPO,
## exit 77 only when privleap is genuinely absent, exit 1 on a broken target.
from pl_testlib import import_privleap  # noqa: E402

pl = import_privleap()
PrivleapCommon = pl.PrivleapCommon


## --- alphabet code points, as literals (ASCII-only source) ---
DIGIT_0 = 0x30  # '0'
DIGIT_9 = 0x39  # '9'
UPPER_A = 0x41  # 'A'
UPPER_Z = 0x5A  # 'Z'
LOWER_A = 0x61  # 'a'
LOWER_Z = 0x7A  # 'z'
PLUS = 0x2B  # '+'
SLASH = 0x2F  # '/'
MAX_COUNT = 63
MAX_CP = 0x10FFFF
INVALID = -1  # model sentinel for "the real decoder raises ValueError"


FAIL = 0
CANARIES_VERIFIED = [0]


def fail(msg):
    global FAIL
    FAIL += 1
    sys.stderr.write("FAIL: " + msg + "\n")


def _expect_caught(label, caught):
    if caught:
        CANARIES_VERIFIED[0] += 1
    else:
        fail("canary %s: a broken model was NOT caught" % label)


def z3_prove(name, claim, assumptions=(), report=True):
    solver = z3.Solver()
    for assumption in assumptions:
        solver.add(assumption)
    solver.add(z3.Not(claim))
    result = solver.check()
    if result == z3.unsat:
        return True
    if not report:
        return False
    if result == z3.sat:
        fail("Z3 %s: COUNTEREXAMPLE %s" % (name, solver.model()))
    else:
        fail("Z3 %s: proof INCOMPLETE (solver returned %s)" % (name, result))
    return False


## --- Z3 model of the codec, mirroring privleap.py ---


def _encode_z3(n, broken_off_by_one=False):
    """Symbolic count -> character code."""
    bias = 1 if broken_off_by_one else 0  # BUG: shifts the digit block by one
    return z3.If(
        n <= 9,
        DIGIT_0 + n + bias,
        z3.If(
            n <= 35,
            UPPER_A + (n - 10),
            z3.If(
                n <= 61,
                LOWER_A + (n - 36),
                z3.If(n == 62, z3.IntVal(PLUS), z3.IntVal(SLASH)),
            ),
        ),
    )


def _decode_z3(c, broken_widen=False):
    """Symbolic character code -> count, or INVALID for a non-alphabet code."""
    upper_hi = UPPER_Z + 1 if broken_widen else UPPER_Z  # BUG: accepts '['
    return z3.If(
        z3.And(c >= DIGIT_0, c <= DIGIT_9),
        c - DIGIT_0,
        z3.If(
            z3.And(c >= UPPER_A, c <= upper_hi),
            (c - UPPER_A) + 10,
            z3.If(
                z3.And(c >= LOWER_A, c <= LOWER_Z),
                (c - LOWER_A) + 36,
                z3.If(
                    c == PLUS,
                    z3.IntVal(62),
                    z3.If(c == SLASH, z3.IntVal(63), z3.IntVal(INVALID)),
                ),
            ),
        ),
    )


def _alphabet_z3(c):
    """The character code c is in the codec alphabet."""
    return z3.Or(
        z3.And(c >= DIGIT_0, c <= DIGIT_9),
        z3.And(c >= UPPER_A, c <= UPPER_Z),
        z3.And(c >= LOWER_A, c <= LOWER_Z),
        c == PLUS,
        c == SLASH,
    )


## --- pure-Python mirror of the Z3 model, for fast full-domain enumeration
## (invoking Z3 per code point would be far too slow). The enumeration confirms
## the REAL codec matches this mirror point-for-point, and the Z3 theorems above
## prove the mirror's logic, so the two together anchor the proof to real code.


def _encode_model_py(n):
    if 0 <= n <= 9:
        return DIGIT_0 + n
    if 10 <= n <= 35:
        return UPPER_A + (n - 10)
    if 36 <= n <= 61:
        return LOWER_A + (n - 36)
    if n == 62:
        return PLUS
    if n == 63:
        return SLASH
    return INVALID


def _decode_model_py(cp):
    if DIGIT_0 <= cp <= DIGIT_9:
        return cp - DIGIT_0
    if UPPER_A <= cp <= UPPER_Z:
        return (cp - UPPER_A) + 10
    if LOWER_A <= cp <= LOWER_Z:
        return (cp - LOWER_A) + 36
    if cp == PLUS:
        return 62
    if cp == SLASH:
        return 63
    return INVALID


## --- real-codec adapters (raising -> INVALID sentinel) ---


def _real_decode(cp):
    try:
        return PrivleapCommon.msg_arg_count_to_int(chr(cp))
    except ValueError:
        return INVALID


def _real_encode_code(n):
    try:
        return ord(PrivleapCommon.int_to_msg_arg_count(n))
    except ValueError:
        return INVALID


## --- T1: bijection ---


def t1_z3():
    n = z3.Int("n")
    dom = [n >= 0, n <= MAX_COUNT]
    z3_prove("T1-roundtrip", _decode_z3(_encode_z3(n)) == n, dom)


def t1_enumerate():
    for n in range(MAX_COUNT + 1):
        ch = PrivleapCommon.int_to_msg_arg_count(n)
        if PrivleapCommon.msg_arg_count_to_int(ch) != n:
            fail("T1-enum: real roundtrip broke at n=%d" % n)
            return
        ## Anchor the model's encode to the real one at this point.
        if _encode_model_py(n) != ord(ch):
            fail("T1-enum: model encode != real encode at n=%d" % n)
            return


def t1_canaries():
    n = z3.Int("n")
    dom = [n >= 0, n <= MAX_COUNT]
    _expect_caught(
        "T1-offbyone",
        not z3_prove(
            "T1-canary",
            _decode_z3(_encode_z3(n, broken_off_by_one=True)) == n,
            dom,
            report=False,
        ),
    )


## --- T2: decode soundness ---


def t2_z3():
    c = z3.Int("c")
    ## An accepted character (not INVALID) always yields a count in 0..63.
    z3_prove(
        "T2-decode-in-range",
        z3.Implies(
            _decode_z3(c) != INVALID,
            z3.And(_decode_z3(c) >= 0, _decode_z3(c) <= MAX_COUNT),
        ),
    )
    ## The accepted set is EXACTLY the alphabet.
    z3_prove(
        "T2-accepts-alphabet-only",
        (_decode_z3(c) != INVALID) == _alphabet_z3(c),
    )


def t2_enumerate():
    ## The whole Unicode code-point space, against the real decoder: every code
    ## point in the alphabet decodes to the model's value, every other code
    ## point is rejected.
    for cp in range(MAX_CP + 1):
        real = _real_decode(cp)
        if real != _decode_model_py(cp):
            fail(
                "T2-enum: real decode(%d)=%d but model=%d"
                % (cp, real, _decode_model_py(cp))
            )
            return
        if real != INVALID and not (0 <= real <= MAX_COUNT):
            fail("T2-enum: real decode(%d)=%d out of range" % (cp, real))
            return


def t2_canaries():
    c = z3.Int("c")
    ## A decoder that also accepted '[' (0x5B) would break "accepts alphabet
    ## only"; the widened model must be refuted.
    _expect_caught(
        "T2-widened",
        not z3_prove(
            "T2-canary",
            (_decode_z3(c, broken_widen=True) != INVALID) == _alphabet_z3(c),
            report=False,
        ),
    )
    ## And the real decoder must reject that same out-of-alphabet character.
    _expect_caught("T2-real-rejects-bracket", _real_decode(0x5B) == INVALID)


## --- T3: encode range ---


def t3_z3():
    n = z3.Int("n")
    ## Every count in range encodes to an alphabet character.
    z3_prove(
        "T3-encode-in-alphabet",
        _alphabet_z3(_encode_z3(n)),
        [n >= 0, n <= MAX_COUNT],
    )


def t3_enumerate():
    ## In range: exactly one alphabet character. Out of range: rejected.
    for n in range(MAX_COUNT + 1):
        ch = PrivleapCommon.int_to_msg_arg_count(n)
        if len(ch) != 1 or not _in_alphabet(ord(ch)):
            fail("T3-enum: encode(%d)=%r not a single alphabet char" % (n, ch))
            return
    for n in (-1, -1000, MAX_COUNT + 1, 1000):
        if _real_encode_code(n) != INVALID:
            fail("T3-enum: encode(%d) was accepted; should reject" % n)
            return


def t3_canaries():
    ## A model that claimed an out-of-range count still lands in the alphabet
    ## must be refuted (the unconstrained-domain proof is sat).
    n = z3.Int("n")
    _expect_caught(
        "T3-unbounded",
        not z3_prove(
            "T3-canary", _alphabet_z3(_encode_z3(n)), report=False
        ),
    )


def _in_alphabet(cp):
    return (
        DIGIT_0 <= cp <= DIGIT_9
        or UPPER_A <= cp <= UPPER_Z
        or LOWER_A <= cp <= LOWER_Z
        or cp == PLUS
        or cp == SLASH
    )


def main():
    sys.stdout.write(
        "verify_privleap_formal: Z3 + full-domain enumeration of the "
        "argument-count codec\n"
    )
    sys.stdout.write("  T1  bijection -- Z3 roundtrip + real 0..63 enumeration\n")
    t1_z3()
    t1_enumerate()
    t1_canaries()

    sys.stdout.write(
        "  T2  decode soundness -- Z3 range/alphabet + real full-Unicode sweep\n"
    )
    t2_z3()
    t2_enumerate()
    t2_canaries()

    sys.stdout.write(
        "  T3  encode range -- Z3 alphabet image + real in/out-of-range enum\n"
    )
    t3_z3()
    t3_enumerate()
    t3_canaries()

    sys.stdout.write(
        "verify_privleap_formal: %d canaries verified, %d obligations failed\n"
        % (CANARIES_VERIFIED[0], FAIL)
    )
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
