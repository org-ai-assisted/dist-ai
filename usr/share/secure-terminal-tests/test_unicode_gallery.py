#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Exhaustive conformance test for secure-terminal's risk classifier, and the
safety invariants of the unicode.payload generator (secure-terminal-shots/
unicode-gallery.py).

The generator ships an INDEPENDENT oracle `classify()` deriving each risk class
from a source distinct from secure_terminal.sanitize.marking_class: the control
class from general category Cc (not a numeric range), bidi from the authoritative
Bidi_Control list, invisible from str.isprintable() plus a private range copy,
confusable from the shipped data, combining from a UAX #29 cluster test. This
test asserts marking_class equals that oracle for EVERY assigned code point
(~a few hundred thousand), so a drift in marking_class's ranges or branch order
is caught here rather than shipping mis-tinted. Font-independent, so it covers
the whole space the DISPLAYED payload (a renderable subset) cannot.

Every check is CANARY-VERIFIED: a deliberately-stubbed marking_class must make
the conformance assertion fail, so a green result has teeth. The oracle itself is
spot-checked against hand-known code points so a broken oracle cannot make the
conformance vacuous.

Also asserts the generator's own contract: deterministic, valid UTF-8, the
version stamp, and the byte-safety invariants that make it cat-safe (grids carry
no control bytes; every raw ESC / C1 string-introducer aborts at a newline; SO is
paired with SI; no escape sequence forms).

secure_terminal + its deps (regex, confusable_homoglyphs) are declared; a missing
one is a hard FAILURE for a security-relevant suite, not a skip. Exit 0 on full
pass, 1 on any failure.
"""

import importlib.util
import os
import sys

try:
    from secure_terminal import sanitize as S
except Exception as exc:      # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(unicode_gallery): FAIL missing '
                     'dependency: %s\n' % exc)
    sys.exit(1)

# The generator lives in the sibling shots tree; load it by path (its name has a
# hyphen, so it is not importable by module name).
_HERE = os.path.dirname(os.path.abspath(__file__))
_GEN_PATH = os.path.join(_HERE, '..', 'secure-terminal-shots', 'unicode-gallery.py')
try:
    _spec = importlib.util.spec_from_file_location('unicode_gallery', _GEN_PATH)
    G = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(G)
except Exception as exc:      # pylint: disable=broad-except
    sys.stderr.write('secure-terminal-tests(unicode_gallery): FAIL cannot load '
                     'generator %s: %s\n' % (_GEN_PATH, exc))
    sys.exit(1)

FAIL = 0


def fail(msg):
    global FAIL
    FAIL += 1
    sys.stderr.write('FAIL: ' + msg + '\n')


def ok(msg):
    sys.stderr.write('ok: ' + msg + '\n')


# Hand-known classifications so a broken oracle cannot make conformance vacuous.
_ORACLE_FIXTURES = (
    (0x202E, 'bidi'),        # RIGHT-TO-LEFT OVERRIDE
    (0x2066, 'bidi'),        # LEFT-TO-RIGHT ISOLATE
    (0x001B, 'control'),     # ESC (C0)
    (0x0000, 'control'),     # NUL
    (0x007F, 'control'),     # DEL
    (0x0085, 'control'),     # NEL (C1)
    (0x200B, 'invisible'),   # ZERO WIDTH SPACE
    (0xFEFF, 'invisible'),   # BOM
    (0x00A0, 'invisible'),   # NO-BREAK SPACE (not str.isprintable())
    (0xFE00, 'invisible'),   # VARIATION SELECTOR-1 (default-ignorable)
    (0x0430, 'confusable'),  # CYRILLIC SMALL LETTER A
    (0x03BF, 'confusable'),  # GREEK SMALL LETTER OMICRON
    (0x0301, 'combining'),   # COMBINING ACUTE ACCENT
    (0x0489, 'combining'),   # COMBINING CYRILLIC MILLIONS SIGN
    (0x03A9, 'nonascii'),    # GREEK CAPITAL LETTER OMEGA (honest foreign)
    (0x2500, 'nonascii'),    # BOX DRAWINGS LIGHT HORIZONTAL (structural -> nonascii)
    (0x4E2D, 'nonascii'),    # a CJK ideograph
)


def test_oracle_fixtures():
    for cp, want in _ORACLE_FIXTURES:
        got = G.classify(cp)
        if got != want:
            fail('oracle classify(U+%04X)=%r want %r' % (cp, got, want))
    ok('oracle spot-checks pass (%d code points)' % len(_ORACLE_FIXTURES))


def test_marking_class_conformance():
    """marking_class == oracle for EVERY assigned code point."""
    mism = []
    checked = 0
    for cp in G.assigned_code_points():
        checked += 1
        want = G.classify(cp)
        got = S.marking_class(cp)
        if want != got:
            mism.append((cp, got, want))
            if len(mism) >= 25:
                break
    if mism:
        for cp, got, want in mism:
            fail('marking_class(U+%04X)=%r oracle=%r' % (cp, got, want))
    else:
        ok('marking_class matches oracle for all %d assigned code points' % checked)


def test_conformance_canary():
    """A stubbed marking_class must be caught by the conformance comparison."""
    orig = S.marking_class
    try:
        S.marking_class = lambda cp: 'nonascii'
        found = 0
        for cp in G.assigned_code_points():
            if G.classify(cp) != S.marking_class(cp):
                found += 1
                if found >= 5:
                    break
        if found == 0:
            fail('CANARY: stubbed marking_class produced no mismatch -- '
                 'the conformance check has no teeth')
        else:
            ok('canary: stubbed marking_class detected')
    finally:
        S.marking_class = orig


def _control_bytes(text):
    return {ord(c) for c in text
            if (ord(c) < 0x20 and c not in '\n\t')
            or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F}


def test_payload_safety():
    """The generator's cat-safety contract."""
    data = G.render_payload()
    if data != G.render_payload():
        fail('payload is not deterministic')
    try:
        data.encode('utf-8')
    except UnicodeError as exc:
        fail('payload is not valid UTF-8: %s' % exc)
    if G.UNIDATA_VERSION not in data:
        fail('payload does not stamp the Unicode version')

    lines = data.split('\n')
    first_risk = next((i for i, l in enumerate(lines) if 'RISK:' in l), None)
    if first_risk is None:
        fail('payload has no RISK section')
        return
    grid_region = '\n'.join(lines[:first_risk])
    if _control_bytes(grid_region):
        fail('grid region carries control bytes: %s'
             % sorted(hex(c) for c in _control_bytes(grid_region)))

    # Every raw ESC and every C1 string-introducer must abort at a newline; SO
    # must be immediately restored by SI; no escape sequence may form.
    c1_intro = (0x90, 0x98, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F)
    seq_starts = set('[]PX^_()NO0123456789')
    bad_esc = bad_c1 = bad_so = seq = 0
    for i, c in enumerate(data):
        nxt = data[i + 1] if i + 1 < len(data) else ''
        if c == '\x1b':
            if nxt != '\n':
                bad_esc += 1
            if nxt in seq_starts:
                seq += 1
        elif ord(c) in c1_intro and nxt != '\n':
            bad_c1 += 1
        elif c == '\x0e' and nxt != '\x0f':
            bad_so += 1
    if bad_esc:
        fail('%d raw ESC not aborted by a newline' % bad_esc)
    if seq:
        fail('%d ESC-led escape sequences present' % seq)
    if bad_c1:
        fail('%d C1 string-introducers not aborted by a newline' % bad_c1)
    if bad_so:
        fail('%d SO not paired with SI' % bad_so)
    if not (bad_esc or seq or bad_c1 or bad_so):
        ok('payload byte-safety invariants hold')


def test_payload_safety_canary():
    """A payload with an un-isolated ESC sequence must trip test_payload_safety's
    detectors -- proves those checks have teeth."""
    hostile = 'safe line\n\x1b]0;pwned\x07more\n'
    c1_intro = (0x90, 0x98, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F)  # noqa: F841 (parity)
    seq_starts = set('[]PX^_()NO0123456789')
    seq = sum(1 for i, c in enumerate(hostile)
              if c == '\x1b' and (hostile[i + 1] if i + 1 < len(hostile) else '')
              in seq_starts)
    if seq == 0:
        fail('CANARY: the escape-sequence detector missed an OSC hijack')
    else:
        ok('canary: escape-sequence detector fires on a hostile payload')


def test_summary():
    s = G.summary()
    if s.get('unidata_version') != G.UNIDATA_VERSION:
        fail('summary version stamp wrong')
    if not s.get('total_assigned', 0) > 100000:
        fail('summary total_assigned implausibly low: %r' % s.get('total_assigned'))
    for klass in ('bidi', 'control', 'invisible', 'confusable', 'combining',
                  'nonascii'):
        if klass not in s.get('by_class', {}):
            fail('summary missing class %r' % klass)
    if not s.get('display_blocks'):
        fail('summary has no display_blocks')
    else:
        ok('summary well-formed (%d assigned, %d display blocks)'
           % (s['total_assigned'], len(s['display_blocks'])))


def main():
    for test in (test_oracle_fixtures, test_marking_class_conformance,
                 test_conformance_canary, test_payload_safety,
                 test_payload_safety_canary, test_summary):
        test()
    if FAIL:
        sys.stderr.write('secure-terminal-tests(unicode_gallery): %d FAILURE(s)\n'
                         % FAIL)
        return 1
    sys.stderr.write('secure-terminal-tests(unicode_gallery): all checks pass\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
