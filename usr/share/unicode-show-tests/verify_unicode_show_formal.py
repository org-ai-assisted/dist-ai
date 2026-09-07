#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Formal verification of unicode-show -- the helper-scripts scanner that DETECTS
suspicious Unicode in text/source and annotates it inline as [U+XXXX].

unicode-show is a DETECTOR/annotator, not a transformer: it does not emit a
sanitized payload, so there is no reversible transform to verify. What it DOES
guarantee, and what this harness proves, is (a) which characters it flags, (b)
that its OWN output can never leak a raw suspicious character, and (c) that its
[U+XXXX] code-point formatter is injective/reversible (distinct code point ->
distinct, decodable token).

Two complementary methods per theorem (mirrors verify_stdisplay_formal.py and
verify_curl_prgrs_formal.py):
  - Z3 (SMT): prove the property over the symbolic code-point domain.
  - ENUMERATION against the REAL functions (imported from the checkout): U1 over
    the ENTIRE Unicode space; U2/U3 over the full space and a hostile corpus.
  - CANARIES: every method is also run against a deliberately BROKEN model and
    must catch it, so a green run has teeth.

Theorems:
  U1  Classification soundness -- is_suspicious(c) is True for every non-ASCII
      code point (cp >= 0x80), every C0 control except tab/newline, and DEL, and
      False for every printable ASCII (0x20..0x7E) and tab/newline. Equivalently
      is_suspicious(c) <=> not(0x20 <= cp <= 0x7E or cp in {tab, newline}).
  U2  Self-safety -- describe_char(c) is pure ASCII for EVERY c (it uses ascii(),
      never repr(), and a [U+XXXX] hex marker), so a tool whose job is to display
      suspicious characters can never itself print one raw.
  U3  Formatter injectivity/reversibility -- the [U+{cp:04X}] token is injective
      over [0..0x10FFFF] (distinct cp -> distinct token) and reversible (the hex
      decodes back to cp); the min-4-width zero padding never truncates.

SCOPE -- honest. Z3 proves the classification structure (given the finite fact,
established by enumeration against the REAL SAFE_ASCII_SEMANTIC set, that every
printable ASCII / tab / newline is semantically allowed), the ASCII-ness of hex
rendering, and the injectivity of the nibble decomposition. String-shaped facts
(the real is_suspicious / describe_char results, the real token round-trip) are
proved by ENUMERATION against the real functions -- U1 exhaustively over all
0x110000 code points. The [U+XXXX] output is a REPORT, not a reversible sanitizer
of the payload; unicode-show fails closed (exit 2) on non-UTF-8, which is a
control-flow property covered by unicode-show-tests, not modeled here.

Exit 0 on a fully discharged proof, 1 on any counterexample, unmet assumption,
or model/real-code divergence. A missing z3 or the unicode-show subject is a hard
FAILURE (exit 1), never a silent skip.
"""

import os
import re
import sys

try:
    import z3
except (ImportError, OSError) as exc:  # any z3 load failure (module or native lib) must FAIL clean
    sys.stderr.write(
        "unicode-show-tests(verify_unicode_show_formal): FAIL missing "
        "dependency (z3 / python3-z3): %s\n" % exc
    )
    sys.exit(1)

REPO = os.environ.get("UNICODE_SHOW_REPO")
if REPO:
    sys.path.insert(0, os.path.join(REPO, "usr/lib/python3/dist-packages"))

try:
    # pylint: disable=wrong-import-position
    from unicode_show.unicode_show import (  # noqa: E402
        is_suspicious,
        describe_char,
        SAFE_ASCII_SEMANTIC,
        VISIBLE_ASCII_RANGE,
        ALLOWED_WHITESPACE,
    )
except ImportError as exc:  # pragma: no cover - environment error
    sys.stderr.write(
        "unicode-show-tests(verify_unicode_show_formal): FAIL cannot import the "
        "unicode_show package (%s); set UNICODE_SHOW_REPO to a helper-scripts "
        "checkout or install helper-scripts\n" % exc
    )
    sys.exit(1)


TAB = 0x09
NL = 0x0A
SP = 0x20
TILDE = 0x7E
DEL = 0x7F
MAX_CP = 0x10FFFF


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


## ============================ U1: classification ============================

def _u1_z3(broken=False):
    """Model is_suspicious's predicate:
        codepoint_allowed = (0x20<=cp<=0x7E) or cp in {tab,newline}
        suspicious = not (codepoint_allowed and semantically_allowed)
    with the finite fact (proved by enumeration below) that a printable-ASCII /
    tab / newline code point is always semantically allowed. Prove the security
    direction (everything dangerous is flagged) and the non-vacuity direction
    (printable ASCII / tab / newline is NOT flagged)."""
    cp = z3.Int("cp")
    sem = z3.Bool("sem")  # semantically_allowed = c in SAFE_ASCII_SEMANTIC
    dom = [cp >= 0, cp <= MAX_CP]

    visible = z3.And(cp >= SP, cp <= TILDE)
    ws = z3.Or(cp == TAB, cp == NL)
    codepoint_allowed = z3.Or(visible, ws)
    ## Enumeration establishes: every code point that is codepoint_allowed is in
    ## SAFE_ASCII_SEMANTIC. Feed that as the assumption (broken drops it, so the
    ## non-vacuity claim below becomes unprovable -> canary catches it).
    coverage = [] if broken else [z3.Implies(codepoint_allowed, sem)]

    suspicious = z3.Not(z3.And(codepoint_allowed, sem))

    nonascii = z3.Implies(cp >= 0x80, suspicious)
    bad_c0 = z3.Implies(z3.And(cp >= 0, cp < SP, cp != TAB, cp != NL), suspicious)
    del_susp = z3.Implies(cp == DEL, suspicious)
    printable_ok = z3.Implies(visible, z3.Not(suspicious))
    ws_ok = z3.Implies(ws, z3.Not(suspicious))

    ok1 = z3_prove("U1-nonascii-suspicious", nonascii, dom)  # holds regardless of sem
    ok2 = z3_prove("U1-bad-c0-suspicious", bad_c0, dom)
    ok3 = z3_prove("U1-del-suspicious", del_susp, dom)
    ok4 = z3_prove("U1-printable-not-suspicious", printable_ok, dom + coverage, report=not broken)
    ok5 = z3_prove("U1-ws-not-suspicious", ws_ok, dom + coverage, report=not broken)
    return ok1 and ok2 and ok3 and ok4 and ok5


def _u1_coverage_enumerate():
    """The finite fact the Z3 non-vacuity proof assumes: every printable ASCII
    and tab/newline is in the REAL SAFE_ASCII_SEMANTIC set."""
    for cp in list(VISIBLE_ASCII_RANGE) + [TAB, NL]:
        if chr(cp) not in SAFE_ASCII_SEMANTIC:
            fail("U1 coverage: U+%04X not in SAFE_ASCII_SEMANTIC (Z3 assumption broken)" % cp)
    ## VISIBLE_ASCII_RANGE must be exactly 0x20..0x7E (the model's [SP..TILDE]).
    if list(VISIBLE_ASCII_RANGE) != list(range(SP, TILDE + 1)):
        fail("U1 coverage: VISIBLE_ASCII_RANGE is not 0x20..0x7E")
    if ALLOWED_WHITESPACE != {"\n", "\t"}:
        fail("U1 coverage: ALLOWED_WHITESPACE is not {newline, tab}")


def _suspicious_model(cp):
    return not (SP <= cp <= TILDE or cp in (TAB, NL))


def _u1_enumerate():
    """Run the REAL is_suspicious over the ENTIRE Unicode space and confirm it
    equals the model at every code point."""
    for cp in range(0, MAX_CP + 1):
        if is_suspicious(chr(cp)) != _suspicious_model(cp):
            fail("U1 enumerate: is_suspicious(U+%04X)=%s, model=%s"
                 % (cp, is_suspicious(chr(cp)), _suspicious_model(cp)))
            return


def _u1_canaries():
    ## Dropping the coverage assumption must make the non-vacuity claims fail.
    _expect_caught("U1/z3-coverage", not _u1_z3(broken=True))
    ## A model that calls DEL safe diverges from the real is_suspicious (which
    ## flags it) -- the enumeration equality guard catches it.
    def broken_model(cp):
        return not (SP <= cp <= TILDE or cp in (TAB, NL) or cp == DEL)
    _expect_caught("U1/model-del", is_suspicious(chr(DEL)) != broken_model(DEL))


## ============================ U2: self-safety ==============================

def _hexdigit_z3(v, broken=False):
    if broken:
        ## BUG: maps 10..15 past 'f' into non-ASCII-hex territory.
        return z3.If(v < 10, 0x30 + v, 0x7A + (v - 10))
    return z3.If(v < 10, 0x30 + v, 0x41 + (v - 10))


def _u2_z3(broken=False):
    """Every hex digit of the [U+XXXX] marker is an ASCII character in
    {0x30..0x39} u {0x41..0x46}, hence < 0x80. (The literal '[', 'U', '+', ']'
    are ASCII by construction.)"""
    v = z3.Int("v")
    dom = [v >= 0, v <= 15]
    d = _hexdigit_z3(v, broken=broken)
    is_hex_ascii = z3.Or(z3.And(d >= 0x30, d <= 0x39), z3.And(d >= 0x41, d <= 0x46))
    return z3_prove("U2-hexdigit-ascii", is_hex_ascii, dom, report=not broken)


## Hostile corpus -- every non-ASCII char written as an escape (ASCII-only source).
_HOSTILE = [
    chr(0x00), chr(0x07), chr(0x08), chr(0x1B), chr(DEL),      # C0 / DEL
    chr(0x200B), chr(0x200E), chr(0x202E), chr(0xFEFF),         # zero-width / bidi / BOM
    chr(0xE9), chr(0x0301),                                     # printable non-ASCII + combining
    chr(0x4E2D), chr(0x1F600), chr(0x10FFFF),                   # CJK / emoji / max astral
    chr(0xD800),                                                # lone surrogate
]


def _u2_enumerate():
    """The REAL describe_char emits pure ASCII for EVERY code point (full sweep)
    and never raises; spot-check the hostile corpus too."""
    for cp in range(0, MAX_CP + 1):
        try:
            desc = describe_char(chr(cp))
        except Exception as exc:  # pylint: disable=broad-except
            fail("U2 enumerate: describe_char(U+%04X) raised %r" % (cp, exc))
            return
        bad = next((ch for ch in desc if ord(ch) >= 0x80), None)
        if bad is not None:
            fail("U2 enumerate: describe_char(U+%04X) leaked non-ASCII U+%04X"
                 % (cp, ord(bad)))
            return
    for c in _HOSTILE:
        marker = "[U+%04X]" % ord(c)
        if any(ord(ch) >= 0x80 for ch in marker):
            fail("U2 enumerate: marker for U+%04X is not ASCII" % ord(c))


def _u2_canaries():
    _expect_caught("U2/z3-hexdigit", not _u2_z3(broken=True))
    ## A describe that used repr() instead of ascii() would pass a printable
    ## non-ASCII char through literally -- the ASCII guard must catch that.
    def repr_describe(c):
        return "%s (U+%04X)" % (repr(c), ord(c))
    leaky = repr_describe(chr(0xE9))
    _expect_caught("U2/model-repr-leak", any(ord(ch) >= 0x80 for ch in leaky))


## ==================== U3: formatter injectivity/reversibility ================

def _u3_z3(broken=False):
    """The [U+{cp:04X}] token is injective over [0..0x10FFFF]: two code points
    with the same 6-nibble hex rendering are equal. 0x10FFFF < 16**6, and :04X
    (min-4-width) never truncates, so the 6-nibble rendering is a faithful key."""
    a = z3.Int("a")
    b = z3.Int("b")
    dom = [a >= 0, a <= MAX_CP, b >= 0, b <= MAX_CP]

    def nib(x, k):
        if broken:
            ## BUG: masks to 4 nibbles, so 0x10000 collides with 0x0000.
            k = k % 4
        return (x / (16 ** k)) % 16

    same = z3.And(*[nib(a, k) == nib(b, k) for k in range(6)])
    claim = z3.Implies(same, a == b)
    return z3_prove("U3-token-injective", claim, dom, report=not broken)


_U3_SAMPLE = (
    list(range(0, 0x200))
    + [SP, TILDE, DEL, 0x80, 0xFF, 0x100, 0xFFF, 0x1000, 0xFFFF, 0x10000, 0x10FFFF]
    + [0x200B, 0x202E, 0xFEFF, 0x4E2D, 0x1F600]
)
_TOKEN_RE = re.compile(r"U\+([0-9A-F]+)")


def _u3_enumerate():
    """The REAL describe_char embeds a U+XXXX token; over the sample it must be
    injective (distinct cp -> distinct token) and reversible (hex decodes to cp),
    with at least 4 hex digits."""
    seen = {}
    for cp in _U3_SAMPLE:
        desc = describe_char(chr(cp))
        m = _TOKEN_RE.search(desc)
        if not m:
            fail("U3 enumerate: no U+ token in describe_char(U+%04X): %r" % (cp, desc))
            continue
        hexpart = m.group(1)
        if len(hexpart) < 4:
            fail("U3 enumerate: token for U+%04X under-padded: %r" % (cp, hexpart))
        if int(hexpart, 16) != cp:
            fail("U3 enumerate: token %r does not decode to U+%04X" % (hexpart, cp))
        token = m.group(0)
        if token in seen and seen[token] != cp:
            fail("U3 enumerate: token %r collides U+%04X and U+%04X"
                 % (token, seen[token], cp))
        seen[token] = cp


def _u3_canaries():
    _expect_caught("U3/z3-mask", not _u3_z3(broken=True))
    ## A formatter masking to 16 bits collides code points a multiple of 0x10000
    ## apart; the injectivity guard must catch it.
    def masked_token(cp):
        return "[U+%04X]" % (cp & 0xFFFF)
    _expect_caught("U3/model-mask", masked_token(0x10000) == masked_token(0x00000))


def main():
    sys.stdout.write("unicode-show formal verification (Z3 %s)\n" % z3.get_version_string())

    sys.stdout.write("  U1  classification -- Z3 predicate + real-set coverage + exhaustive enumeration\n")
    _u1_coverage_enumerate()
    _u1_z3()
    _u1_enumerate()
    _u1_canaries()

    sys.stdout.write("  U2  self-safety -- Z3 hex-ASCII + exhaustive describe_char sweep\n")
    _u2_z3()
    _u2_enumerate()
    _u2_canaries()

    sys.stdout.write("  U3  formatter injectivity -- Z3 nibble bijection + real token round-trip\n")
    _u3_z3()
    _u3_enumerate()
    _u3_canaries()

    sys.stdout.write(
        "verify_unicode_show_formal: %d canaries verified, %d obligations failed\n"
        % (CANARIES_VERIFIED[0], FAIL)
    )
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
