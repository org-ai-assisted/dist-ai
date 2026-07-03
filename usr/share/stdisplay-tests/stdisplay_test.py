#!/usr/bin/env python3
r"""
Comprehensive test + fuzz for stdisplay(): the helper-scripts stdisplay-package
function that sanitizes untrusted text to be safe to print to a terminal (the
security core the whole stcat family -- stcat, stcatn, stecho, stprint,
stsponge, sttee -- routes its input through).

This suite is a deliberately DIFFERENT layer from stcat-family-tests. That suite
drives the six CLIs and only exercises stdisplay() at two colour settings
(NO_COLOR, i.e. sgr=-1, and COLORTERM=truecolor, i.e. sgr=2**24). The bug-prone
part of stdisplay lives in between: get_sgr_pattern() builds a graded allow-list
regex whose behaviour changes at every colour depth (3-bit, 4-bit, 8-bit,
24-bit), plus an exclude_sgr negative-lookahead, plus the get_sgr_support()
environment logic. This suite tests the FUNCTION directly, across every colour
depth, and is intentionally exhaustive (too much to eyeball) -- which is why it
lives in dist-ai rather than as a basic test in helper-scripts.

Security contract (see stdisplay.py):
  stdisplay(untrusted_text, sgr, exclude_sgr) -> str
  The output must be safe to write to a terminal: the ONLY escape sequences that
  may survive are Select Graphic Rendition (SGR, "ESC [ ... m") colour/attribute
  codes -- and only those the colour depth (sgr) allows and exclude_sgr does not
  remove. Everything else -- every non-ASCII character, every control character
  other than newline and tab, DEL, and every non-SGR escape (cursor movement,
  screen clear, device-status *report* (an input-injection vector), OSC title /
  OSC-8 hyperlink, DCS/APC/PM, single-byte C1 CSI/OSC, RIS reset, charset
  selection) -- is replaced with an underscore.

Independent safety oracle
  Any "ESC [ <params> m" is, by definition, an SGR sequence (m is the SGR final
  byte); SGR can only set colour/attributes, never move the cursor, clear the
  screen, report, or set the title. So terminal-safety is exactly: strip every
  loose "\x1b\[[0-9;:]*m", then forbid any remaining ESC or any character that is
  not printable ASCII / newline / tab. This loose grammar is written by hand and
  does NOT validate palette ranges or separator consistency, so it is genuinely
  independent of the tool's own regex -- yet it is sound, because it permits
  exactly the SGR class and flags everything that could inject.

Checks
  [P] pins:      the module's own docstring examples (stdisplay, exclude_pattern,
                 get_sgr_pattern) -- exact-string regression pins.
  [B] benign:    printable ASCII / newline / tab pass through UNCHANGED at every
                 colour depth (proves the sanitizer does not over-redact).
  [G] graded:    a matrix of one representative sequence per SGR bit-mode against
                 every colour depth, asserting each survives exactly when its
                 depth is enabled and is redacted (ESC -> _) otherwise.
  [R] redaction: a corpus of dangerous non-SGR escapes / controls / C1 / Unicode
                 is neutralised at EVERY colour depth, including truecolor.
  [X] exclude:   exclude_sgr removes a code that the depth would otherwise allow,
                 while leaving the others intact.
  [E] env:       get_sgr_support() -- NO_COLOR (any non-empty disables; empty does
                 not), COLORTERM truecolor/24bit (case-insensitive), NO_COLOR
                 precedence, and the TERM/curses path fails closed (< 8, no
                 escapes) on an unknown or dumb terminal.
  [I] idempotence: stdisplay(stdisplay(x)) == stdisplay(x) over the corpus.
  [F] fuzz:      random Unicode, an escape-biased byte pool (the smuggling
                 channel), and random exclude lists never raise, never break the
                 safety oracle, and stay idempotent -- at every colour depth.

No root, no network. The source is ASCII-only: every control / non-ASCII
character is written as a Python escape. The function is imported from
STDISPLAY_REPO (a helper-scripts checkout) else the installed stdisplay package.

Usage: stdisplay_test.py [--iterations N] [--seed N] [--fuzz-only]
"""

import argparse
import os
import re
import subprocess
import sys

REPO = os.environ.get("STDISPLAY_REPO")
if REPO:
    sys.path.insert(0, os.path.join(REPO, "usr/lib/python3/dist-packages"))

try:
    # pylint: disable=wrong-import-position
    from stdisplay.stdisplay import (  # noqa: E402
        stdisplay,
        get_sgr_support,
        get_sgr_pattern,
        exclude_pattern,
    )
except ImportError as exc:  # pragma: no cover - environment error
    sys.stderr.write(
        "ERROR: cannot import the stdisplay package (%s); set STDISPLAY_REPO "
        "to a helper-scripts checkout or install helper-scripts\n" % exc
    )
    raise SystemExit(2) from exc


## Colour depths: (name, sgr value). -1 == no colour (SGR fully disabled),
## 8 == 3-bit, 16 == 4-bit, 256 == 8-bit, 2**24 == 24-bit truecolor.
SGR_LEVELS = [
    ("none", -1),
    ("3bit", 8),
    ("4bit", 16),
    ("8bit", 256),
    ("24bit", 2 ** 24),
]


## ---------------------------------------------------------------------------
## Independent safety oracle. Loose SGR grammar, hand-written, palette-agnostic.
## ---------------------------------------------------------------------------
_LOOSE_SGR = re.compile("\x1b\\[[0-9;:]*m")


def terminal_safe(text):
    r"""Return a list of violations that make `text` unsafe to print. Empty list
    == safe. Strip every loose SGR sequence, then nothing dangerous may remain:
    no ESC (a bare or non-SGR escape leaked) and only printable ASCII plus
    newline / tab."""
    stripped = _LOOSE_SGR.sub("", text)
    violations = []
    if "\x1b" in stripped:
        violations.append("leaked non-SGR ESC")
    bad = [c for c in stripped
           if c not in ("\t", "\n") and not 0x20 <= ord(c) <= 0x7E]
    if bad:
        violations.append("nonprintable " + str([hex(ord(c)) for c in bad[:6]]))
    return violations


def redacted(text):
    """The tool replaces each disallowed unit with a single underscore; a
    redacted escape therefore has its ESC turned into '_'. Used to assert the
    non-surviving branch of the graded matrix."""
    return "\x1b" not in text


## ---------------------------------------------------------------------------
## Graded matrix: one representative sequence per bit-mode, and the MINIMUM
## colour depth at which it must survive verbatim (None never survives here).
## ---------------------------------------------------------------------------
def graded_cases():
    return [
        ## 3-bit: foreground, background, reset -- allowed from sgr>=8.
        ("3bit-fg", "\x1b[31m", 8),
        ("3bit-bg", "\x1b[41m", 8),
        ("3bit-reset", "\x1b[0m", 8),
        ("3bit-leadzero", "\x1b[031m", 8),      # leading zeros are permitted
        ## 4-bit bright: allowed from sgr>=16 only.
        ("4bit-fg", "\x1b[91m", 16),
        ("4bit-bg", "\x1b[101m", 16),
        ## 8-bit indexed: allowed from sgr>=256; both ';' and ':' separators.
        ("8bit-fg-semi", "\x1b[38;5;200m", 256),
        ("8bit-bg-semi", "\x1b[48;5;0m", 256),
        ("8bit-fg-colon", "\x1b[38:5:200m", 256),
        ## 24-bit truecolor: allowed only at sgr==2**24; both separators.
        ("24bit-semi", "\x1b[38;2;10;20;30m", 2 ** 24),
        ("24bit-colon", "\x1b[38:2:10:20:30m", 2 ** 24),
    ]


## ---------------------------------------------------------------------------
## Dangerous corpus: must be neutralised at EVERY colour depth (incl. truecolor).
## name -> raw string (written with escapes to keep this file ASCII-only).
## ---------------------------------------------------------------------------
def dangerous_corpus():
    return {
        ## CSI sequences that are NOT SGR (final byte other than 'm').
        "csi-clear-screen": "\x1b[2J",
        "csi-cursor-home": "\x1b[H",
        "csi-cursor-up": "\x1b[10A",
        "csi-cursor-pos": "\x1b[5;9H",
        "csi-erase-line": "\x1b[2K",
        "csi-hide-cursor": "\x1b[?25l",
        "csi-alt-screen": "\x1b[?1049h",
        "csi-mouse-on": "\x1b[?1000h",
        ## Device-status / attribute REPORT: the terminal writes bytes back on
        ## stdin -- a genuine input-injection primitive. Must never survive.
        "csi-dsr": "\x1b[6n",
        "csi-da": "\x1b[c",
        ## OSC: window-title set and OSC-8 hyperlink (BEL- and ST-terminated).
        "osc-title-bel": "\x1b]0;pwned\x07",
        "osc-title-st": "\x1b]0;pwned\x1b\\",
        "osc8-hyperlink": "\x1b]8;;http://example.com\x1b\\link\x1b]8;;\x1b\\",
        ## Other escape families: RIS full reset, charset selection, DCS/APC/PM.
        "ris-reset": "\x1bc",
        "charset-g0": "\x1b(0",
        "charset-g1": "\x1b)B",
        "dcs": "\x1bP0;1|17/ab\x1b\\",
        "apc": "\x1b_payload\x1b\\",
        "pm": "\x1b^message\x1b\\",
        "bare-esc": "\x1b",
        ## Single-byte C1 controls (their own CSI / OSC / DCS introducers).
        "c1-csi": "\x9b31m",
        "c1-osc": "\x9d0;pwned\x07",
        "c1-dcs": "\x90payload\x1b\\",
        "c1-nel": "a\x85b",
        ## C0 controls (other than newline/tab) and DEL.
        "bell": "a\x07b",
        "backspace": "a\x08b",
        "vtab": "a\x0bb",
        "formfeed": "a\x0cb",
        "carriage-return": "a\rb",
        "nul": "a\x00b",
        "del": "a\x7fb",
        ## Non-ASCII: bidi Trojan-Source, zero-width, BOM, homoglyph, separators.
        "rlo": "a\u202eb",
        "lri": "a\u2066b",
        "zwsp": "a\u200bb",
        "bom": "a\ufeffb",
        "homoglyph": "p\u0430ypal",
        "line-sep": "a\u2028b",
        "para-sep": "a\u2029b",
        "c1-as-unicode": "a\u009bb",
    }


def sgr_support_subprocess(term):
    """Run get_sgr_support() in a CLEAN child with the given TERM (and NO_COLOR /
    COLORTERM unset). setupterm() is process-global -- it honours only the first
    call -- so each TERM must be probed in its own process. Returns the int, or
    None if the child failed."""
    code = (
        "import os, sys\n"
        "os.environ.pop('NO_COLOR', None)\n"
        "os.environ.pop('COLORTERM', None)\n"
        "sys.path[:0] = %r\n"
        "from stdisplay.stdisplay import get_sgr_support\n"
        "print(get_sgr_support())\n"
    ) % ([p for p in sys.path if p],)
    env = dict(os.environ)
    env.pop("NO_COLOR", None)
    env.pop("COLORTERM", None)
    env["TERM"] = term
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, env=env,
            stdin=subprocess.DEVNULL, timeout=30, check=False, text=True,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return None


def main():  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    parser = argparse.ArgumentParser(description="stdisplay test + fuzz")
    parser.add_argument("--iterations", type=int, default=400,
                        help="fuzz iterations per channel")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--fuzz-only", action="store_true")
    args = parser.parse_args()

    print("stdisplay test + fuzz")
    print("tool: " + (("checkout " + REPO) if REPO else "installed package"))
    print()

    passed = 0
    failed = 0
    skipped = 0
    fail_samples = []
    skip_notes = []

    def check(name, ok, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
            if len(fail_samples) < 40:
                fail_samples.append(name + ": " + detail)

    def skip(name, why):
        nonlocal skipped
        skipped += 1
        skip_notes.append(name + ": " + why)

    def safe(name, text, sgr, exclude=None):
        """stdisplay(text) must never raise and its output must pass the oracle."""
        try:
            out = stdisplay(text, sgr=sgr, exclude_sgr=exclude)
        except Exception as err:  # pylint: disable=broad-except
            check(name + ":no-raise", False, "%r on %r" % (err, text[:48]))
            return None
        check(name + ":safe", not terminal_safe(out),
              "; ".join(terminal_safe(out)) + " -> " + repr(out[:64]))
        return out

    if not args.fuzz_only:
        ## [P] pins: the module's own docstring examples, exact strings. These
        ## lock the documented behaviour and are deterministic (explicit sgr).
        print("[P] pins: module docstring examples (exact-string regression)")
        check("P:stdisplay:default-redact",
              stdisplay("\x1b[2Jvulnerable: True\b\b\b\bFalse", sgr=2 ** 24)
              == "_[2Jvulnerable: True____False")
        check("P:stdisplay:sgr-none",
              stdisplay("\x1b[38;5;0m\x1b[31m\x1b[38;2;0;0;0m", sgr=-1)
              == "_[38;5;0m_[31m_[38;2;0;0;0m")
        check("P:stdisplay:sgr-4bit",
              stdisplay("\x1b[38;5;0m\x1b[31m\x1b[38;2;0;0;0m", sgr=2 ** 4)
              == "_[38;5;0m\x1b[31m_[38;2;0;0;0m")
        check("P:exclude_pattern:3bit",
              exclude_pattern(r"(0*(30|31))", ["0*31"])
              == "(?!(?:0*31))(0*(30|31))")
        check("P:exclude_pattern:8bit",
              exclude_pattern(r"(0*38(:|;)0*5(:|;)0*[0-9])",
                              ["0*38;0*5(:|;)[0-9]+"])
              == "(?!(?:0*38;0*5(:|;)[0-9]+))(0*38(:|;)0*5(:|;)0*[0-9])")
        ## Below the 8-colour floor get_sgr_pattern must match nothing.
        check("P:get_sgr_pattern:below-floor",
              get_sgr_pattern(sgr=4, exclude_sgr=None) == "(?!)"
              and get_sgr_pattern(sgr=None, exclude_sgr=None) == "(?!)"
              and get_sgr_pattern(sgr=-1, exclude_sgr=None) == "(?!)")

        ## [B] benign: printable ASCII / newline / tab are unchanged at every
        ## depth -- proves the redaction is not vacuously "underscore everything".
        print("[B] benign: printable ASCII / newline / tab pass through unchanged")
        printable = "".join(chr(c) for c in range(0x20, 0x7F))
        benign = [printable, "hello world\n", "a\tb\tc\n",
                  "line one\nline two\n", "", "\n\n\t\t"]
        for name, sgr in SGR_LEVELS:
            for idx, text in enumerate(benign):
                out = stdisplay(text, sgr=sgr)
                check("B:%s:#%d" % (name, idx), out == text,
                      "changed benign input: %r -> %r" % (text[:40], out[:40]))

        ## [G] graded: each bit-mode sequence survives exactly when its depth is
        ## enabled, and is redacted (ESC -> _, oracle-safe) otherwise.
        print("[G] graded: each SGR bit-mode survives exactly at/above its depth")
        for case, seq, min_level in graded_cases():
            for name, sgr in SGR_LEVELS:
                out = stdisplay(seq, sgr=sgr)
                should_survive = sgr >= min_level
                if should_survive:
                    check("G:%s@%s:survive" % (case, name), out == seq,
                          "expected verbatim, got %r" % out)
                else:
                    check("G:%s@%s:redacted" % (case, name),
                          redacted(out) and not terminal_safe(out),
                          "expected ESC redacted, got %r" % out)

        ## [R] redaction: the dangerous corpus is neutralised at EVERY depth,
        ## including truecolor -- no ESC and nothing the oracle rejects survives.
        print("[R] redaction: dangerous escapes / controls / Unicode die at "
              "every depth")
        for case, raw in dangerous_corpus().items():
            for name, sgr in SGR_LEVELS:
                out = stdisplay(raw, sgr=sgr)
                check("R:%s@%s:no-esc" % (case, name), "\x1b" not in out,
                      "ESC survived: %r" % out)
                check("R:%s@%s:safe" % (case, name), not terminal_safe(out),
                      "; ".join(terminal_safe(out)) + " -> " + repr(out[:48]))

        ## [X] exclude: exclude_sgr strips a code the depth would otherwise
        ## allow, leaving the rest intact -- and output stays safe.
        print("[X] exclude: exclude_sgr removes only the excluded code")
        check("X:3bit-fg",
              stdisplay("\x1b[31m\x1b[32m", sgr=8, exclude_sgr=["0*31"])
              == "_[31m\x1b[32m")
        check("X:3bit-bg",
              stdisplay("\x1b[41m\x1b[31m", sgr=8, exclude_sgr=["0*4[0-7]"])
              == "_[41m\x1b[31m")
        check("X:8bit",
              stdisplay("\x1b[38;5;5m\x1b[31m", sgr=256,
                        exclude_sgr=["0*38(:|;)0*5(:|;)[0-9]+"])
              == "_[38;5;5m\x1b[31m")
        check("X:none-is-identity",
              stdisplay("\x1b[31m\x1b[41m", sgr=8, exclude_sgr=None)
              == "\x1b[31m\x1b[41m")
        for excl in (["0*31"], ["0*4[0-7]"], ["0*38(:|;)0*5(:|;)[0-9]+"], []):
            safe("X:oracle:%s" % "".join(excl)[:8],
                 "\x1b[31m\x1b[41m\x1b[38;5;9m\x1b[6ntext",
                 sgr=256, exclude=excl)

        ## [E] env: get_sgr_support() logic.
        print("[E] env: get_sgr_support() NO_COLOR / COLORTERM / fail-closed TERM")
        saved_env = {k: os.environ.get(k) for k in ("NO_COLOR", "COLORTERM")}

        def set_env(**vals):
            for key in ("NO_COLOR", "COLORTERM"):
                os.environ.pop(key, None)
            for key, val in vals.items():
                os.environ[key] = val

        try:
            ## NO_COLOR: any non-empty value disables SGR entirely (-1).
            set_env(NO_COLOR="1")
            check("E:no-color-1", get_sgr_support() == -1)
            set_env(NO_COLOR="anything")
            check("E:no-color-word", get_sgr_support() == -1)
            ## NO_COLOR precedence over COLORTERM.
            set_env(NO_COLOR="1", COLORTERM="truecolor")
            check("E:no-color-beats-colorterm", get_sgr_support() == -1)
            ## Empty NO_COLOR does NOT disable: COLORTERM still wins here.
            set_env(NO_COLOR="", COLORTERM="truecolor")
            check("E:empty-no-color-not-disable", get_sgr_support() == 2 ** 24)
            ## COLORTERM truecolor / 24bit, case-insensitive -> 24-bit.
            for val in ("truecolor", "24bit", "TrueColor", "24BIT"):
                set_env(COLORTERM=val)
                check("E:colorterm-%s" % val, get_sgr_support() == 2 ** 24)
            ## A non-truecolor COLORTERM must NOT be read as 24-bit (the check is
            ## specific); it falls through to the terminfo path.
            set_env(COLORTERM="256color")
            check("E:colorterm-256color-not-24bit",
                  get_sgr_support() != 2 ** 24)
        finally:
            for key, val in saved_env.items():
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val

        ## Fail-closed terminfo path (own subprocess per TERM, setupterm is
        ## process-global). Unknown / dumb terminals must yield < 8 so stdisplay
        ## permits no escapes; a known terminal enabling colour is asserted
        ## softly (skipped if this build lacks the terminfo database).
        dumb = sgr_support_subprocess("dumb")
        check("E:term-dumb-failclosed", dumb is not None and dumb < 8,
              "dumb -> %r (want < 8)" % dumb)
        unknown = sgr_support_subprocess("nonexistent-term-zzz")
        check("E:term-unknown-failclosed", unknown is not None and unknown < 8,
              "unknown -> %r (want < 8)" % unknown)
        known = sgr_support_subprocess("xterm-256color")
        if known is None or known < 0:
            skip("E:term-known-enables-color",
                 "terminfo database unavailable in this environment "
                 "(xterm-256color -> %r)" % known)
        else:
            check("E:term-known-enables-color", known >= 8,
                  "xterm-256color -> %r (want >= 8)" % known)
        ## The security-relevant consequence of a fail-closed support value: a
        ## non-positive sgr must let NO SGR through.
        for bad_sgr in (-2, -1, 0, 7):
            check("E:failclosed-redacts@%d" % bad_sgr,
                  stdisplay("\x1b[31m", sgr=bad_sgr) == "_[31m",
                  "sgr=%d did not redact" % bad_sgr)

        ## [I] idempotence: sanitizing twice equals sanitizing once. A stable
        ## fixed point is part of the contract (stcat pipelines rely on it).
        print("[I] idempotence: stdisplay(stdisplay(x)) == stdisplay(x)")
        idem_inputs = ([seq for _, seq, _ in graded_cases()]
                       + list(dangerous_corpus().values()))
        for name, sgr in (("none", -1), ("8bit", 256), ("24bit", 2 ** 24)):
            for idx, text in enumerate(idem_inputs):
                once = stdisplay(text, sgr=sgr)
                twice = stdisplay(once, sgr=sgr)
                check("I:%s:#%d" % (name, idx), once == twice,
                      "not idempotent: %r -> %r -> %r"
                      % (text[:32], once[:32], twice[:32]))

    ## -----------------------------------------------------------------------
    ## [F] fuzz. Three channels; each asserts never-raise + oracle-safe +
    ## idempotent, across colour depths. The escape-biased channel is the
    ## smuggling test: it tries to get a dangerous escape to survive.
    ## -----------------------------------------------------------------------
    import random
    rng = random.Random(args.seed)
    print("[F] fuzz: %d iterations/channel (seed %d)" % (args.iterations,
                                                          args.seed))

    def fuzz_one(name, text):
        """Assert the invariant at every colour depth: never raise, oracle-safe,
        idempotent. Every depth is checked because a leak may exist at one depth
        (e.g. truecolor is the most permissive) and not another."""
        for level_name, sgr in SGR_LEVELS:
            try:
                once = stdisplay(text, sgr=sgr)
                twice = stdisplay(once, sgr=sgr)
            except Exception as err:  # pylint: disable=broad-except
                check("%s@%s:no-raise" % (name, level_name), False,
                      "%r on %r" % (err, text[:48]))
                continue
            ok = not terminal_safe(once) and once == twice
            check("%s@%s" % (name, level_name), ok,
                  "safe=%r idem=%r in=%r out=%r"
                  % (terminal_safe(once), once == twice, text[:48], once[:48]))

    ## Channel 1: random Unicode scalars (surrogates excluded -- not valid str).
    for i in range(args.iterations):
        chars = []
        for _ in range(rng.randint(0, 32)):
            cp = rng.randint(0, 0x10FFFF)
            if 0xD800 <= cp <= 0xDFFF:
                cp = 0x41
            chars.append(chr(cp))
        fuzz_one("F:unicode#%d" % i, "".join(chars))

    ## Channel 2: escape-biased pool -- the smuggling channel. Heavy on ESC and
    ## the bytes that build CSI / OSC / DCS sequences, so the fuzzer keeps trying
    ## to assemble a non-SGR escape that slips past the allow-list.
    esc_pool = (["\x1b", "[", "]", "(", ")", "P", "_", "^", "c", "m", "n",
                 "A", "J", "K", "H", "R", ";", ":", "?", ">", "=", "\\"]
                + list("0123456789")
                + ["8", "5", "2", "3", "4", "9", "1", "0"]  # SGR-ish digits
                + list("abxyzst ")
                + ["\x07", "\x08", "\x9b", "\x9d", "\x90", "\x00", "\x7f",
                   "\n", "\t", "\u202e", "\u200b", "\ufeff"])
    for i in range(args.iterations):
        text = "".join(rng.choice(esc_pool) for _ in range(rng.randint(0, 40)))
        fuzz_one("F:escape#%d" % i, text)

    ## Channel 3: random exclude_sgr lists combined with SGR-ish input. A bad
    ## exclude must not crash the sanitizer or over-permit; output must stay safe.
    excl_fragments = ["0*31", "0*3[0-7]", "0*4[0-7]", "0*9[0-7]",
                      "0*10[0-7]", "0*38(:|;)0*5(:|;)[0-9]+",
                      "0*38(:|;)0*2(:|;)[0-9]+", "0*0", "0*1"]
    excl_input = "\x1b[31m\x1b[41m\x1b[91m\x1b[38;5;9m\x1b[38;2;1;2;3m\x1b[6nx"
    for i in range(args.iterations):
        k = rng.randint(0, 4)
        excl = [rng.choice(excl_fragments) for _ in range(k)]
        try:
            out = stdisplay(excl_input, sgr=2 ** 24, exclude_sgr=excl)
        except Exception as err:  # pylint: disable=broad-except
            check("F:exclude#%d:no-raise" % i, False,
                  "%r with exclude=%r" % (err, excl))
            continue
        check("F:exclude#%d:safe" % i, not terminal_safe(out),
              "; ".join(terminal_safe(out)) + " exclude=%r -> %r"
              % (excl, out[:48]))

    print()
    print("%d passed, %d failed, %d skipped" % (passed, failed, skipped))
    if skip_notes:
        print("skipped:")
        for note in skip_notes:
            print("  - " + note)
    if fail_samples:
        print("failures (sample):")
        for sample in fail_samples:
            print("  - " + sample)
    if failed:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS (stdisplay redacts everything but allowed SGR at every "
          "colour depth and never leaks an injecting escape)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
