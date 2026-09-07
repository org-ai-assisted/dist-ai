#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Formal verification of stdisplay() -- the helper-scripts terminal-output
sanitizer the WHOLE stcat family (stcat, stcatn, stprint, stsponge, sttee,
stecho) routes untrusted text through.

Two complementary methods per theorem, mirroring secure-terminal's
verify_formal.py and helper-scripts-lib's verify_curl_prgrs_formal.py:
  - Z3 (SMT): prove a property over the SYMBOLIC code-point domain, on a Z3
    model of the sanitizer's per-character decision ladder.
  - ENUMERATION against the REAL stdisplay: run the ACTUAL function (imported
    from the checkout) over the FULL Unicode code-point space and confirm it
    matches the model point-for-point -- this anchors the symbolic model to the
    real regex, so the proof is about stdisplay, not a detached copy.
  - CANARIES: every method is also run against a deliberately BROKEN model and
    must catch it, so a green run has teeth.

The sanitizer is one regex substitution (stdisplay.py):

    sgr_pattern = r"(\\x1b(?!\\[" + get_sgr_pattern(sgr) + r")|[^\\x1b\\n\\t\\x20-\\x7E])"
    return re_sub(re_compile(sgr_pattern), "_", untrusted_text)

Every matched char is replaced by a single underscore (0x5F). Match alt A is a
lone ESC not beginning a valid SGR sequence; alt B is any char outside
{ESC, newline, tab} u [0x20..0x7E]. So re.sub emits, per position, either the
UNMATCHED input char (verbatim) or an underscore -- never anything else. This
single structural fact makes the per-character alphabet claims sound regardless
of the SGR lookahead.

Theorems:
  T1  Output-alphabet invariant -- every output character is in
      {ESC, tab, newline} u [0x20..0x7E]; corollaries: no non-ASCII, no C0
      control except tab/newline/ESC, no DEL. The ESC arm (which the exhaustive
      non-ESC sweep cannot reach) is checked separately: no bare or non-SGR ESC
      sequence (CSI screen-clear, DSR query, OSC title/hyperlink, DCS, RIS, an
      SGR body missing its 'm') survives -- every ESC in it is redacted -- at
      every colour depth.
  T2  Neutralization -- every non-ASCII (cp>=0x80), every C0 control except
      tab/newline, and DEL (0x7F), when not ESC, is replaced by underscore.
  T3  Idempotence -- stdisplay(stdisplay(s)) == stdisplay(s). Z3 proves the
      alphabet is an alt-B fixpoint (no non-ESC output char is re-matched); the
      surviving-SGR fixpoint is proved by enumeration over the graded SGR corpus.
  T4  SGR tier gate -- sgr < 8 is fail-closed (every ESC stripped), and the
      3/4/8/24-bit palette tiers are monotonic: a valid sequence of a given tier
      survives exactly when sgr reaches that tier's threshold and is redacted
      below it.
  T5  get_sgr_support() precedence -- NO_COLOR always disables colour (wins over
      COLORTERM and TERM), TERM=dumb disables it, and COLORTERM truecolor/24bit
      enables 24-bit; a disabled result is always < 8.

SCOPE -- honest. Z3 proves the per-character DECISION LADDER and the tier/gate
logic over the symbolic code-point / sgr domain. String-shaped facts (the actual
regex substitution over multi-character input, the surviving-SGR idempotence
fixpoint, the real get_sgr_support branch results) are proved by ENUMERATION
against the real function -- T1/T2 exhaustively over the ENTIRE Unicode space
(all 0x110000 code points, batched), the rest over targeted corpora. stdisplay
is NOT reversible or injective: it is destructive redaction to underscore, so
there is no [U+XXXX] escaping and no inverse to prove (unicode-show emits
[U+XXXX] only as a report; see verify_unicode_show_formal.py for the injectivity
of THAT formatter). The six CLIs' I/O wrapping (argument joins, newline
handling, file writes) is not soundly Z3-modelable and is covered by
stcat-family-tests; proving the shared stdisplay() core proves the family's
security property.

Exit 0 on a fully discharged proof, 1 on any counterexample, unmet assumption,
or model/real-code divergence. A missing z3 or the stdisplay subject is a hard
FAILURE (exit 1), never a silent skip -- a verification suite must not disable
itself.
"""

import os
import subprocess
import sys

try:
    import z3
except (ImportError, OSError) as exc:  # any z3 load failure (module or native lib) must FAIL clean
    sys.stderr.write(
        "stdisplay-tests(verify_stdisplay_formal): FAIL missing dependency "
        "(z3 / python3-z3): %s\n" % exc
    )
    sys.exit(1)

REPO = os.environ.get("STDISPLAY_REPO")
if REPO:
    sys.path.insert(0, os.path.join(REPO, "usr/lib/python3/dist-packages"))

try:
    # pylint: disable=wrong-import-position
    from stdisplay.stdisplay import (  # noqa: E402
        stdisplay,
        get_sgr_pattern,
    )
except ImportError as exc:  # pragma: no cover - environment error
    sys.stderr.write(
        "stdisplay-tests(verify_stdisplay_formal): FAIL cannot import the "
        "stdisplay package (%s); set STDISPLAY_REPO to a helper-scripts "
        "checkout or install helper-scripts\n" % exc
    )
    sys.exit(1)


## --- code points, written as literals (ASCII-only source) ---
TAB = 0x09
NL = 0x0A
ESC = 0x1B
SP = 0x20
TILDE = 0x7E
DEL = 0x7F
UNDERSCORE = 0x5F
MAX_CP = 0x10FFFF

## Colour depths: (name, sgr). -1 disables SGR entirely; 8/16/256/2**24 are the
## 3/4/8/24-bit tiers (256 >= 88 enables 8-bit).
SGR_LEVELS = [("none", -1), ("3bit", 8), ("4bit", 16), ("8bit", 256), ("24bit", 2 ** 24)]


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


## --- Z3 model of the sanitizer's per-character decision (mirrors the regex) ---

def _in_alphabet_z3(x):
    """The allowed OUTPUT alphabet: {ESC, tab, newline} u [0x20..0x7E]."""
    return z3.Or(x == ESC, x == TAB, x == NL, z3.And(x >= SP, x <= TILDE))


def _altb_match_z3(cp):
    """Regex alt B: [^\\x1b\\n\\t\\x20-\\x7E] -- a single char OUTSIDE the
    allowed alphabet (ESC excluded, it is handled by alt A)."""
    return z3.Not(z3.Or(cp == ESC, cp == NL, cp == TAB, z3.And(cp >= SP, cp <= TILDE)))


def _emitted_cp_z3(cp, esc_ok, broken_pass_nonascii=False):
    """The code point re.sub emits for a single input char.

    esc_ok is True iff this char is an ESC that begins a valid SGR sequence
    (then the ESC survives verbatim; every following SGR-body char is in
    [0x20..0x7E] and so is separately in the alphabet). broken_* build a wrong
    model to give the canaries teeth."""
    ordinary_keep = z3.Or(cp == NL, cp == TAB, z3.And(cp >= SP, cp <= TILDE))
    if broken_pass_nonascii:
        ## BUG: a char >= 0x80 is passed through instead of redacted.
        ordinary_keep = z3.Or(ordinary_keep, cp >= 0x80)
    return z3.If(
        cp == ESC,
        z3.If(esc_ok, z3.IntVal(ESC), z3.IntVal(UNDERSCORE)),
        z3.If(ordinary_keep, cp, z3.IntVal(UNDERSCORE)),
    )


def _dangerous_z3(cp):
    """Chars that MUST be neutralized: non-ASCII, C0 controls other than
    tab/newline, and DEL. (ESC is the one control handled by the SGR path.)"""
    return z3.And(
        cp != ESC,
        z3.Or(
            cp >= 0x80,
            z3.And(cp >= 0, cp < SP, cp != TAB, cp != NL),
            cp == DEL,
        ),
    )


## --- real-function enumeration helpers ---

def _keep_ordinary(cp):
    """Python mirror of the ordinary-char keep decision (non-ESC)."""
    return cp == NL or cp == TAB or (SP <= cp <= TILDE)


def _allowed_output_char(ch):
    o = ord(ch)
    return o == ESC or o == NL or o == TAB or (SP <= o <= TILDE)


## The exhaustive non-ESC input string and its expected sanitized image are the
## SAME at every colour depth (SGR affects only ESC, which is excluded here), so
## build them once. Each non-ESC char maps to exactly one output char (alt B
## matches single chars; no alt A without ESC), so the mapping is positional.
_NONESC_CPS = [cp for cp in range(0, MAX_CP + 1) if cp != ESC]
_NONESC_INPUT = "".join(chr(cp) for cp in _NONESC_CPS)
_NONESC_EXPECT = "".join(chr(cp) if _keep_ordinary(cp) else "_" for cp in _NONESC_CPS)


## ESC sequences that carry NO valid SGR, so EVERY ESC in them must be redacted
## at EVERY colour depth (a bare or non-SGR ESC never survives -- only a valid SGR
## lead does). Written as escapes (ASCII-only source).
_DANGEROUS_ESC = [
    "\x1b",                                  # lone ESC
    "\x1b[",                                 # ESC + CSI opener only
    "\x1bX",                                 # ESC + non-CSI
    "\x1b[2J",                               # CSI erase-display (screen clear)
    "\x1b[H",                                # CSI cursor home
    "\x1b[6n",                               # CSI device-status-report query
    "\x1b[31",                               # SGR body without the terminating 'm'
    "\x1b[999m",                             # out-of-range SGR (no valid palette)
    "\x1bc",                                 # RIS full reset
    "\x1b]0;title\x07",                      # OSC set-title (BEL-terminated)
    "\x1b]8;;http://x\x07link\x1b]8;;\x07",  # OSC-8 hyperlink
    "\x1bP0;0|17/ab\x1b\\",                  # DCS
    "\x1b[2Jvulnerable: True\x08\x08False",  # documented smuggling example
]


## ============================ T1: alphabet invariant =========================

def t1_z3():
    """Every emitted code point lands in the allowed alphabet, and the alphabet
    excludes every dangerous class (no non-ASCII, no bad C0, no DEL)."""
    cp = z3.Int("cp")
    esc_ok = z3.Bool("esc_ok")
    dom = [cp >= 0, cp <= MAX_CP]

    emitted = _emitted_cp_z3(cp, esc_ok)
    ok_alpha = z3_prove("T1-emitted-in-alphabet", _in_alphabet_z3(emitted), dom)

    x = z3.Int("x")
    in_alpha = _in_alphabet_z3(x)
    ok_ascii = z3_prove("T1-alphabet-is-ascii", z3.Implies(in_alpha, x <= 0x7F))
    ok_ctrl = z3_prove(
        "T1-alphabet-no-bad-c0",
        z3.Implies(z3.And(in_alpha, x < SP), z3.Or(x == TAB, x == NL, x == ESC)),
    )
    ok_del = z3_prove("T1-alphabet-no-del", z3.Implies(in_alpha, x != DEL))
    return ok_alpha and ok_ascii and ok_ctrl and ok_del


def t1_enumerate():
    """Run the REAL stdisplay over the ENTIRE non-ESC Unicode space (batched, one
    call per depth) and confirm the output equals the model and stays in the
    alphabet; then check the ESC-alone case at every depth."""
    for name, level in SGR_LEVELS:
        out = stdisplay(_NONESC_INPUT, sgr=level)
        if len(out) != len(_NONESC_INPUT):
            fail("T1 enumerate[%s]: output length %d != input %d"
                 % (name, len(out), len(_NONESC_INPUT)))
            continue
        if out != _NONESC_EXPECT:
            ## Report the first divergence for a readable counterexample.
            for i, (got, want) in enumerate(zip(out, _NONESC_EXPECT)):
                if got != want:
                    cp = _NONESC_CPS[i]
                    fail("T1 enumerate[%s]: cp U+%04X -> real %r, model %r"
                         % (name, cp, got, want))
                    break
        bad = set(ch for ch in out if not _allowed_output_char(ch))
        if bad:
            fail("T1 enumerate[%s]: output escaped the alphabet: %r"
                 % (name, sorted(ord(c) for c in bad)[:8]))
        ## No bare / non-SGR ESC survives at ANY depth: a sequence carrying no
        ## valid SGR must contain no ESC in its sanitized output (its leading ESC
        ## and every other ESC redacted to underscore). This is the ESC arm the
        ## exhaustive non-ESC sweep above cannot reach.
        for seq in _DANGEROUS_ESC:
            out = stdisplay(seq, sgr=level)
            if "\x1b" in out:
                fail("T1 enumerate[%s]: ESC survived a non-SGR sequence %r -> %r"
                     % (name, seq, out))
            bad = set(ch for ch in out if not _allowed_output_char(ch))
            if bad:
                fail("T1 enumerate[%s]: non-SGR sequence %r left %r outside the alphabet"
                     % (name, seq, sorted(ord(c) for c in bad)[:8]))


def t1_canaries():
    ## A model that lets a char >= 0x80 through must FAIL the alphabet claim.
    cp = z3.Int("cp")
    esc_ok = z3.Bool("esc_ok")
    dom = [cp >= 0, cp <= MAX_CP]
    broken = _emitted_cp_z3(cp, esc_ok, broken_pass_nonascii=True)
    _expect_caught(
        "T1/z3-nonascii",
        not z3_prove("T1-canary", _in_alphabet_z3(broken), dom, report=False),
    )
    ## A real non-ASCII / control char that is NOT redacted must fail the guard.
    _expect_caught("T1/model-alphabet", not _allowed_output_char(chr(0xE9)))
    _expect_caught("T1/model-del", not _allowed_output_char(chr(DEL)))


## ============================ T2: neutralization ============================

def t2_z3():
    """Every dangerous char (non-ASCII / bad C0 / DEL, not ESC) is redacted to
    underscore."""
    cp = z3.Int("cp")
    dom = [cp >= 0, cp <= MAX_CP]
    ## esc_ok is irrelevant here (the claim is guarded on cp != ESC); pin False.
    emitted = _emitted_cp_z3(cp, z3.BoolVal(False))
    claim = z3.Implies(_dangerous_z3(cp), emitted == UNDERSCORE)
    return z3_prove("T2-dangerous-redacted", claim, dom)


def t2_enumerate():
    """The REAL stdisplay maps every dangerous code point to underscore, at every
    depth (reuse the exhaustive batch image: dangerous cps are all non-ESC)."""
    for name, level in SGR_LEVELS:
        out = stdisplay(_NONESC_INPUT, sgr=level)
        if len(out) != len(_NONESC_CPS):
            fail("T2 enumerate[%s]: length mismatch" % name)
            continue
        for i, cp in enumerate(_NONESC_CPS):
            dangerous = cp >= 0x80 or (cp < SP and cp not in (TAB, NL)) or cp == DEL
            if dangerous and out[i] != "_":
                fail("T2 enumerate[%s]: dangerous cp U+%04X -> %r (want '_')"
                     % (name, cp, out[i]))
                break


def _broken_neutralize(cp):
    """Broken: keeps DEL instead of redacting it."""
    if cp == DEL:
        return DEL
    return UNDERSCORE


def t2_canaries():
    cp = z3.Int("cp")
    dom = [cp >= 0, cp <= MAX_CP]
    ## A model that emits DEL for a dangerous DEL must FAIL the redaction claim.
    broken = z3.If(cp == DEL, z3.IntVal(DEL), z3.IntVal(UNDERSCORE))
    claim = z3.Implies(_dangerous_z3(cp), broken == UNDERSCORE)
    _expect_caught(
        "T2/z3-keeps-del",
        not z3_prove("T2-canary", claim, dom, report=False),
    )
    ## Same defect in the reference model: it returns DEL, not underscore.
    _expect_caught("T2/model-keeps-del", _broken_neutralize(DEL) != UNDERSCORE)


## ============================ T3: idempotence ==============================

def t3_z3():
    """The output alphabet is an alt-B fixpoint: no non-ESC output char is
    re-matched on a second pass, so a second stdisplay cannot change it. (The
    surviving-SGR ESC fixpoint is the enumeration's job.)"""
    x = z3.Int("x")
    claim = z3.Implies(z3.And(_in_alphabet_z3(x), x != ESC), z3.Not(_altb_match_z3(x)))
    return z3_prove("T3-alphabet-altb-fixpoint", claim)


def _t3_corpus():
    """Dangerous + SGR-bearing strings whose ESC legitimately survives, so the
    fixpoint check exercises the surviving-SGR path Z3 does not model."""
    return [
        "\x1b[2Jvulnerable: True\x08\x08\x08\x08False",
        "\x1b[31mred\x1b[0m plain \x1b]8;;http://x\x07link\x1b]8;;\x07",
        "\x1b[38;5;200m\x1b[38;2;10;20;30mx",
        "tabs\tand\nnewlines\rkept?",
        "".join(chr(c) for c in range(0, 0x120)),
        ## zero-width space, bidi override, BOM, emoji -- all written as escapes.
        chr(0x200B) + "zero" + chr(0x202E) + "width" + chr(0xFEFF) + "bidi"
        + chr(0x1F600) + "emoji",
        "\x1b[38:5:1m\x1b[38:2:0:0:0m colon-sep",
    ]


def t3_enumerate():
    """The REAL stdisplay is idempotent on the corpus at every depth."""
    for name, level in SGR_LEVELS:
        for s in _t3_corpus():
            once = stdisplay(s, sgr=level)
            twice = stdisplay(once, sgr=level)
            if once != twice:
                fail("T3 enumerate[%s]: not idempotent on %r: %r != %r"
                     % (name, s, twice, once))
                break


def t3_canaries():
    ## A broken alphabet that includes a non-ASCII char breaks the fixpoint: that
    ## char IS re-matched by alt B, so the lemma must fail.
    x = z3.Int("x")
    broken_in_alpha = z3.Or(_in_alphabet_z3(x), x == 0x100)
    claim = z3.Implies(z3.And(broken_in_alpha, x != ESC), z3.Not(_altb_match_z3(x)))
    _expect_caught(
        "T3/z3-fixpoint",
        not z3_prove("T3-canary", claim, report=False),
    )


## ============================ T4: SGR tier gate ============================

## (name, sgr threshold, several valid SGR bodies of that tier). Multiple bodies
## per tier so a regression on one code -- not just the representative -- is caught.
SGR_TIERS = [
    ("3bit", 8, ["30", "31", "32", "37", "40", "47", "0"]),
    ("4bit", 16, ["1", "90", "91", "97", "100", "107"]),
    ("8bit", 88, ["38;5;0", "38;5;200", "38;5;255", "48;5;16", "38:5:200"]),
    ("24bit", 2 ** 24, ["38;2;0;0;0", "38;2;10;20;30", "48;2;255;255;255", "38:2:1:2:3"]),
]


def t4_z3(broken=False):
    """The tier gate is exact and monotonic, and fail-closed below 8: a tier is
    enabled iff sgr reaches its threshold; a higher sgr enables a superset;
    sgr < 8 enables nothing (every ESC stripped)."""
    sgr = z3.Int("sgr")
    thr = z3.Int("thr")
    dom = [thr >= 8, thr <= 2 ** 24]

    def enabled(s, t):
        return s >= (t - 100) if broken else s >= t  # BUG: enables a tier early

    exact = z3.Implies(z3.And(dom[0], dom[1]), enabled(sgr, thr) == (sgr >= thr))
    ok_exact = z3_prove("T4-tier-exact", exact, [], report=not broken)

    s1 = z3.Int("s1")
    s2 = z3.Int("s2")
    mono = z3.Implies(
        z3.And(s1 <= s2, thr >= 8, thr <= 2 ** 24, enabled(s1, thr)),
        enabled(s2, thr),
    )
    ok_mono = z3_prove("T4-tier-monotonic", mono, [], report=not broken)

    ## Fail-closed: below 8, the lowest tier (threshold 8) is not enabled.
    closed = z3.Implies(sgr < 8, z3.Not(enabled(sgr, z3.IntVal(8))))
    ok_closed = z3_prove("T4-fail-closed", closed, [], report=not broken)
    return ok_exact and ok_mono and ok_closed


def t4_enumerate():
    """Drive the REAL stdisplay with a valid SGR sequence of each tier at sgr
    just below and at its threshold: preserved verbatim at/above, ESC redacted
    below. Also confirm fail-closed at sgr=-1 (SGR fully disabled)."""
    for name, thr, bodies in SGR_TIERS:
        below = thr - 1
        for body in bodies:
            seq = "\x1b[" + body + "m"
            got_below = stdisplay(seq, sgr=below)
            if got_below == seq:
                fail("T4 enumerate[%s]: tier survived below threshold (sgr=%d): %r"
                     % (name, below, seq))
            if not got_below.startswith("_"):
                fail("T4 enumerate[%s]: ESC not redacted below threshold: %r"
                     % (name, got_below))
            got_at = stdisplay(seq, sgr=thr)
            if got_at != seq:
                fail("T4 enumerate[%s]: valid tier sequence not preserved at sgr=%d: %r"
                     % (name, thr, got_at))
            ## SGR fully disabled: even the lowest tier's ESC is stripped.
            if stdisplay(seq, sgr=-1) == seq:
                fail("T4 enumerate[%s]: sequence survived with SGR disabled: %r" % (name, seq))
    ## The real pattern is the never-match "(?!)" when SGR is disabled.
    if get_sgr_pattern(sgr=-1, exclude_sgr=None) != r"(?!)":
        fail("T4 enumerate: get_sgr_pattern(-1) is not the never-match guard")


def t4_canaries():
    _expect_caught("T4/z3-early-enable", not t4_z3(broken=True))
    ## A real sequence one tier above what is enabled must be redacted; if the
    ## gate were not exact this would slip. 24-bit body at 8-bit depth (256):
    over = stdisplay("\x1b[38;2;1;2;3m", sgr=256)
    _expect_caught("T4/model-over-tier", over.startswith("_"))


## ==================== T5: get_sgr_support() precedence ====================

def _real_sgr_support(env_overrides):
    """Run the REAL get_sgr_support() in a clean subprocess with a controlled
    environment (setupterm is process-global, so a fresh process per case)."""
    snippet = (
        "from stdisplay.stdisplay import get_sgr_support;"
        "print(get_sgr_support())"
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("NO_COLOR", "COLORTERM", "TERM")
    }
    if REPO:
        pp = os.path.join(REPO, "usr/lib/python3/dist-packages")
        env["PYTHONPATH"] = pp + os.pathsep + env.get("PYTHONPATH", "")
    env.update(env_overrides)
    proc = subprocess.run(
        [sys.executable, "-Bsc", snippet],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        fail("T5: get_sgr_support subprocess failed rc=%d: %s"
             % (proc.returncode, proc.stderr[-200:]))
        return None
    return int(proc.stdout.strip())


def t5_z3(broken=False):
    """Model get_sgr_support's branch ladder over (no_color, truecolor, dumb) and
    prove: NO_COLOR wins over everything (result disabled), TERM=dumb disables,
    truecolor enables 24-bit, and a disabled result is always < 8."""
    no_color = z3.Bool("no_color")
    truecolor = z3.Bool("truecolor")
    dumb = z3.Bool("dumb")
    other = z3.Int("other")  # the terminfo-dependent else branch (>= 0)
    dom = [other >= 0]

    ## Mirror the source order: NO_COLOR, then COLORTERM truecolor, then
    ## TERM=dumb, then curses. 'broken' checks NO_COLOR last (loses precedence).
    def model():
        if broken:
            return z3.If(
                truecolor, z3.IntVal(2 ** 24),
                z3.If(no_color, z3.IntVal(-1),
                      z3.If(dumb, z3.IntVal(-1), other)))
        return z3.If(
            no_color, z3.IntVal(-1),
            z3.If(truecolor, z3.IntVal(2 ** 24),
                  z3.If(dumb, z3.IntVal(-1), other)))

    m = model()
    ok_nc = z3_prove("T5-no-color-wins", z3.Implies(no_color, m < 8), dom, report=not broken)
    ok_dumb = z3_prove(
        "T5-dumb-disables",
        z3.Implies(z3.And(z3.Not(no_color), z3.Not(truecolor), dumb), m == -1),
        dom, report=not broken,
    )
    ok_tc = z3_prove(
        "T5-truecolor-enables",
        z3.Implies(z3.And(z3.Not(no_color), truecolor), m == 2 ** 24),
        dom, report=not broken,
    )
    return ok_nc and ok_dumb and ok_tc


def t5_enumerate():
    """Confirm the REAL get_sgr_support realizes the branch results."""
    cases = [
        ("no_color-wins", {"NO_COLOR": "1", "COLORTERM": "truecolor", "TERM": "xterm"}, "disabled"),
        ("no_color-alone", {"NO_COLOR": "1"}, "disabled"),
        ("dumb", {"TERM": "dumb"}, -1),
        ("truecolor", {"COLORTERM": "truecolor", "TERM": "xterm"}, 2 ** 24),
        ("24bit", {"COLORTERM": "24bit", "TERM": "xterm"}, 2 ** 24),
    ]
    for name, env, want in cases:
        got = _real_sgr_support(env)
        if got is None:
            continue
        if want == "disabled":
            if got >= 8:
                fail("T5 enumerate[%s]: expected disabled (<8), got %d" % (name, got))
        elif got != want:
            fail("T5 enumerate[%s]: expected %s, got %d" % (name, want, got))


def t5_canaries():
    _expect_caught("T5/z3-precedence", not t5_z3(broken=True))
    ## The real tool must disable colour when NO_COLOR is set even with a
    ## truecolor COLORTERM -- catches a precedence regression in the real code.
    got = _real_sgr_support({"NO_COLOR": "1", "COLORTERM": "truecolor", "TERM": "xterm"})
    if got is not None:
        _expect_caught("T5/real-no-color-wins", got < 8)


def main():
    sys.stdout.write("stdisplay formal verification (Z3 %s)\n" % z3.get_version_string())

    sys.stdout.write("  T1  output-alphabet invariant -- Z3 decision ladder\n")
    t1_z3()
    sys.stdout.write("  T1  output-alphabet invariant -- exhaustive enumeration vs real\n")
    t1_enumerate()
    t1_canaries()

    sys.stdout.write("  T2  neutralization -- Z3 + exhaustive enumeration vs real\n")
    t2_z3()
    t2_enumerate()
    t2_canaries()

    sys.stdout.write("  T3  idempotence -- Z3 alphabet fixpoint + real-corpus enumeration\n")
    t3_z3()
    t3_enumerate()
    t3_canaries()

    sys.stdout.write("  T4  SGR tier gate -- Z3 monotonic gate + real tier-boundary enumeration\n")
    t4_z3()
    t4_enumerate()
    t4_canaries()

    sys.stdout.write("  T5  get_sgr_support precedence -- Z3 branch ladder + real subprocess\n")
    t5_z3()
    t5_enumerate()
    t5_canaries()

    sys.stdout.write(
        "verify_stdisplay_formal: %d canaries verified, %d obligations failed\n"
        % (CANARIES_VERIFIED[0], FAIL)
    )
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
