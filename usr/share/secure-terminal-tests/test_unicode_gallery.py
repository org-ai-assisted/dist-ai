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
    if _spec is None or _spec.loader is None:
        raise ImportError('no import spec for %s' % _GEN_PATH)
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


def test_honest_foreign_is_nonascii():
    """The footer's non-attack contrast row must be genuinely 'nonascii' (mild
    tint), not confusable -- else the caption lies about the colour. It is computed
    from this environment's confusables data, so the pool must yield some."""
    hf = G.honest_foreign()
    if not hf:
        fail('honest_foreign() is empty -- the candidate pool yielded no nonascii')
        return
    bad = [cp for cp in hf if G.classify(cp) != 'nonascii']
    if bad:
        fail('honest-foreign glyphs not nonascii: %s'
             % ' '.join('U+%04X=%s' % (cp, G.classify(cp)) for cp in bad))
    else:
        ok('honest-foreign row is all nonascii (%d glyphs)' % len(hf))


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


def _first_newline_not_in_ground(data):
    """Line number (1-based) of the first newline a terminal would reach while NOT
    in ground state -- an escape / control sequence / control string / single-shift
    / locking shift that spans a newline. None if every newline is reached in
    ground state (no active shift). A tiny ECMA-48 state model, INDEPENDENT of the
    generator: a newline does NOT terminate a control string, so an unterminated
    OSC/DCS/... is caught here."""
    string_intro = {0x90, 0x98, 0x9D, 0x9E, 0x9F}   # DCS/SOS/OSC/PM/APC (C1)
    single_shift = {0x8E, 0x8F, 0x99, 0x9A}         # SS2/SS3/SGC/SCI: consume one byte
    state = 'ground'
    string_is_osc = False        # only OSC is BEL-terminable; the rest need ST
    shifted_out = False          # SO locking shift, until SI restores it
    line = 1
    for ch in data:
        cp = ord(ch)
        if state == 'ground':
            if cp == 0x0E:
                shifted_out = True                  # SO: locking shift OUT
            elif cp == 0x0F:
                shifted_out = False                 # SI: restore
            elif cp == 0x1B:
                state = 'esc'
            elif cp in string_intro:
                state = 'string'
                string_is_osc = cp == 0x9D
            elif cp == 0x9B:
                state = 'csi'
            elif cp in single_shift:
                state = 'ss'
        elif state == 'esc':
            if ch == '[':
                state = 'csi'
            elif ch == ']':
                state = 'string'
                string_is_osc = True
            elif ch in 'PX^_':
                state = 'string'
                string_is_osc = False
            elif ch != '\n':
                state = 'ground'                    # ESC <final> (a 2-char escape)
        elif state == 'csi':
            if 0x40 <= cp <= 0x7E:
                state = 'ground'                    # a final byte ends the sequence
        elif state == 'string':
            if cp == 0x9C:
                state = 'ground'                    # ST ends any control string
            elif cp == 0x07 and string_is_osc:
                state = 'ground'                    # BEL ends ONLY OSC (xterm extension)
            elif cp == 0x1B:
                state = 'string_esc'                # maybe ESC \ (7-bit ST)
        elif state == 'string_esc':
            state = 'ground' if ch == '\\' else 'string'   # ESC \ = ST; else still open
        elif state == 'ss':
            if ch != '\n':
                state = 'ground'                    # the single consumed byte
        if ch == '\n':
            if state != 'ground' or shifted_out:
                return line
            line += 1
    return None


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
    first_risk = next((i for i, line in enumerate(lines) if 'RISK:' in line), None)
    if first_risk is None:
        fail('payload has no RISK section')
        return
    grid_region = '\n'.join(lines[:first_risk])
    if _control_bytes(grid_region):
        fail('grid region carries control bytes: %s'
             % sorted(hex(c) for c in _control_bytes(grid_region)))

    # The real containment: every control the payload emits is terminated before
    # its newline, so a terminal is in ground state at every line boundary. A
    # newline does NOT terminate a control string, so this catches an unterminated
    # OSC/DCS/... that would swallow the rest of the file.
    bad = _first_newline_not_in_ground(data)
    if bad is not None:
        fail('a control is unterminated at newline %d (spans the line boundary)'
             % bad)
    else:
        ok('payload returns to ground state at every newline')


def test_payload_safety_canary():
    """Each hostile pattern the newline does NOT contain must trip the ground-state
    check -- proves it has teeth for every control class it models."""
    hostile = {
        'unterminated OSC': 'x\n%sno ST\nmore\n' % chr(0x9D),
        'DCS closed only by BEL': 'x\n%s\x07\n' % chr(0x90),   # BEL ends OSC only, not DCS
        'SO without SI': 'x\n%sshifted\n' % chr(0x0E),
        'SCI eating the newline': 'x\n%s\n' % chr(0x9A),
        'ESC non-ST inside a string': 'x\n%s\x1bA\n' % chr(0x9D),
    }
    missed = [name for name, payload in hostile.items()
              if _first_newline_not_in_ground(payload) is None]
    if missed:
        fail('CANARY: ground-state check missed: %s' % ', '.join(missed))
    else:
        ok('canary: ground-state check fires on every hostile control pattern')


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

    # The COMMITTED artifact must match what the generator produces now: a Unicode
    # or confusables-data change alters summary() but not a stale committed file, so
    # compare bytes and force regeneration on drift (same dump params as --summary).
    import json as _json
    committed_path = os.path.join(os.path.dirname(_GEN_PATH),
                                  'unicode-gallery-summary.json')
    fresh = _json.dumps(s, indent=2, ensure_ascii=True, sort_keys=True) + '\n'
    try:
        with open(committed_path, encoding='utf-8') as handle:
            committed = handle.read()
    except OSError as exc:
        fail('cannot read committed summary %s: %s' % (committed_path, exc))
        return
    if committed != fresh:
        fail('committed unicode-gallery-summary.json is STALE -- regenerate it: '
             'unicode-gallery.py --summary > unicode-gallery-summary.json')
    else:
        ok('committed summary matches generated output')


def main():
    for test in (test_oracle_fixtures, test_honest_foreign_is_nonascii,
                 test_marking_class_conformance, test_conformance_canary,
                 test_payload_safety, test_payload_safety_canary, test_summary):
        test()
    if FAIL:
        sys.stderr.write('secure-terminal-tests(unicode_gallery): %d FAILURE(s)\n'
                         % FAIL)
        return 1
    sys.stderr.write('secure-terminal-tests(unicode_gallery): all checks pass\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
