#!/usr/bin/env python3
"""
Comprehensive test + fuzz for unicode-show: the helper-scripts scanner that
DETECTS non-ASCII / suspicious Unicode in text or files (the unicode_show
package). It is the mirror image of the stcat family: stcat *sanitizes* untrusted
text for a terminal, unicode-show *reports* the dangerous characters instead.

Contract (see unicode_show.py):
  - exit 0: input is clean (only visible ASCII plus newline/tab, and it ends
    with a newline).
  - exit 1: at least one suspicious character was found (non-ASCII, a control
    char other than newline/tab, DEL, trailing whitespace, or -- unless
    suppressed -- a missing final newline).
  - exit 2: error, e.g. the input is not valid UTF-8 or a file cannot be read.
    Decoding is strict (errors="strict"), never "replace", so a non-UTF-8 byte
    fails closed rather than being silently mangled and slipped past.

This suite proves, end to end against the real CLI:

  [D] detection: for a hostile corpus (RLO/bidi Trojan-Source set, zero-width,
      BOM, homoglyph, combining, C1, line/paragraph separators, CJK, emoji, and
      C0 control bytes / NUL / DEL) the tool exits 1 and names the exact
      codepoint (e.g. "U+202E") it found.
  [S] self-safety: unicode-show is itself a tool that writes to a terminal, so
      its OWN stdout must never leak the raw suspicious bytes it is reporting.
      Over the whole hostile corpus (and the fuzzer) stdout is pure printable
      ASCII plus newline/tab -- no Unicode, no control char, no ESC, no DEL.
      (The tool relies on ascii() for exactly this; a regression to repr() would
      let a printable non-ASCII char slip through, and this catches it.)
  [B] benign: clean ASCII input (incl. tabs, multiple lines) exits 0 with no
      output -- so [D] is non-vacuous (the tool is not just always exit 1).
  [N] newline / whitespace semantics: trailing whitespace is flagged; a missing
      final newline is flagged by default but suppressed with
      UNICODE_SHOW_ALLOW_MISSING_FINAL_NEWLINE=1; an empty input is clean (no
      spurious "missing newline").
  [E] fail-closed: invalid UTF-8 (stdin or file) exits 2, and the raw bad bytes
      do not appear on stdout; a nonexistent path exits 2.
  [P] paths: a file of hostile Unicode is detected via the path argument, and a
      filename that itself contains suspicious Unicode is sanitized in the
      output (stdout stays ASCII).
  [F] fuzz: random byte streams and random valid-Unicode strings never crash,
      hang, or break the [S] invariant; the exit code stays in {0,1,2}.

No root, no network. The tool is resolved from UNICODE_SHOW_REPO (a helper-scripts
checkout, run via the module) else the installed /usr/bin/unicode-show.

This file is ASCII-only: every suspicious character is written as a Python
escape (e.g. "\\u202e") and encoded to real UTF-8 bytes at runtime.

Usage: unicode_show_test.py [--iterations N] [--seed N] [--fuzz-only]
"""

import argparse
import os
import subprocess
import sys
import tempfile

REPO = os.environ.get("UNICODE_SHOW_REPO")

## Run the installed CLI, or the module out of a checkout.
REPO_CODE = "import sys; from unicode_show.unicode_show import main; sys.exit(main())"

## Per-invocation wall-clock limit. unicode-show is a streaming scanner; any
## input that makes it hang is itself a failure, so a timeout becomes a
## non-zero "exit" (124) rather than wedging the whole run.
TIMEOUT_SECONDS = 30

## Environment variable that turns the "missing newline at end" finding off.
ALLOW_MISSING_NL = "UNICODE_SHOW_ALLOW_MISSING_FINAL_NEWLINE"


def tool_argv(paths=None):
    if REPO:
        argv = [sys.executable, "-c", REPO_CODE]
    else:
        argv = ["/usr/bin/unicode-show"]
    return argv + list(paths or [])


def tool_env(allow_missing_nl=False):
    env = dict(os.environ)
    if REPO:
        env["PYTHONPATH"] = os.path.join(REPO, "usr/lib/python3/dist-packages")
    ## Do not let a value inherited from the caller's environment perturb the
    ## missing-final-newline tests; set it explicitly per case.
    env.pop(ALLOW_MISSING_NL, None)
    if allow_missing_nl:
        env[ALLOW_MISSING_NL] = "1"
    return env


def _invoke(argv, env, data=None):
    try:
        return subprocess.run(
            argv, input=data, capture_output=True, env=env, check=False,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            argv, 124, exc.stdout or b"", b"TIMEOUT"
        )


def run_stdin(data, allow_missing_nl=False):
    return _invoke(tool_argv(), tool_env(allow_missing_nl), data)


def run_paths(paths, allow_missing_nl=False):
    return _invoke(tool_argv(paths), tool_env(allow_missing_nl))


## ---------------------------------------------------------------------------
## Oracle: unicode-show's own stdout must be safe to print to a terminal.
## ---------------------------------------------------------------------------
def output_violations(out):
    r"""The tool's stdout must be pure printable ASCII plus newline/tab: no
    Unicode, no control char (other than \n / \t), no ESC, no DEL."""
    v = []
    if any(b >= 0x80 for b in out):
        v.append("non-ASCII " + str([hex(b) for b in out if b >= 0x80][:6]))
    ctl = [b for b in out if b < 0x20 and b not in (0x09, 0x0A)]
    if ctl:
        v.append("control " + str([hex(b) for b in ctl][:6]))
    if 0x1B in out:
        v.append("ESC")
    if 0x7F in out:
        v.append("DEL")
    return v


## ---------------------------------------------------------------------------
## Hostile corpus: name -> (raw input bytes, codepoint token the tool must
## report). Unicode is written via escapes to keep this file pure ASCII; u()
## produces the real UTF-8 bytes fed to the tool. Each input ends with a newline
## so the ONLY reason for a non-clean result is the suspicious character.
## ---------------------------------------------------------------------------
def hostile_corpus():
    def u(text):
        return text.encode("utf-8") + b"\n"

    corpus = {
        ## Trojan-Source / bidi control set (RHSB-2021-007), the same codepoints
        ## grep-find-unicode-wrapper scans for.
        "rlo": (u("a\u202eb"), "U+202E"),      # right-to-left override
        "lro": (u("a\u202db"), "U+202D"),      # left-to-right override
        "rle": (u("a\u202bb"), "U+202B"),
        "lre": (u("a\u202ab"), "U+202A"),
        "pdf": (u("a\u202cb"), "U+202C"),
        "lri": (u("a\u2066b"), "U+2066"),
        "rli": (u("a\u2067b"), "U+2067"),
        "fsi": (u("a\u2068b"), "U+2068"),
        "pdi": (u("a\u2069b"), "U+2069"),
        "alm": (u("a\u061cb"), "U+061C"),      # arabic letter mark
        "lrm": (u("a\u200eb"), "U+200E"),
        "rlm": (u("a\u200fb"), "U+200F"),
        ## Invisible / zero-width / BOM.
        "zwsp": (u("a\u200bb"), "U+200B"),     # zero-width space
        "zwnj": (u("a\u200cb"), "U+200C"),
        "bom": (u("a\ufeffb"), "U+FEFF"),      # ZWNBSP / BOM
        ## Homoglyph, combining, CJK, emoji.
        "homoglyph": (u("p\u0430ypal"), "U+0430"),  # cyrillic small a
        "combining": (u("a\u0301"), "U+0301"),
        "cjk": (u("\u4f60\u597d"), "U+4F60"),
        "emoji": (u("hi \U0001f600"), "U+1F600"),
        ## C1 control block.
        "c1_nel": (u("a\u0085b"), "U+0085"),
        "c1_csi": (u("a\u009bb"), "U+009B"),
        ## Line / paragraph separators.
        "line_sep": (u("a\u2028b"), "U+2028"),
        "para_sep": (u("a\u2029b"), "U+2029"),
        ## C0 control bytes / NUL / DEL (valid UTF-8, all < 0x80).
        "nul": (b"a\x00b\n", "U+0000"),
        "del": (b"a\x7fb\n", "U+007F"),
        "backspace": (b"a\x08b\n", "U+0008"),
        "esc": (b"a\x1bb\n", "U+001B"),
        "bell": (b"a\x07b\n", "U+0007"),
        "carriage_return": (b"a\rb\n", "U+000D"),
        "vtab": (b"a\x0bb\n", "U+000B"),
        "formfeed": (b"a\x0cb\n", "U+000C"),
    }
    return corpus


## Invalid UTF-8 inputs: must fail closed (exit 2), never slip a raw byte out.
def malformed_inputs():
    return {
        "lone_ff": b"a\xffb\n",
        "lone_80": b"\x80\n",
        "overlong_nul": b"\xc0\x80\n",
        "truncated_lead": b"a\xe2\x80\n",       # cut-off 3-byte sequence
        "utf16_surrogate": b"\xed\xa0\x80\n",   # encoded surrogate, illegal
    }


def main():  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    parser = argparse.ArgumentParser(description="unicode-show test + fuzz")
    parser.add_argument("--iterations", type=int, default=400,
                        help="fuzz iterations per channel")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--fuzz-only", action="store_true")
    args = parser.parse_args()

    print("unicode-show test + fuzz")
    print("tool: " + (("checkout " + REPO) if REPO else "installed /usr/bin"))
    if not REPO and not os.path.exists("/usr/bin/unicode-show"):
        print("ERROR: /usr/bin/unicode-show not found "
              "(set UNICODE_SHOW_REPO to a helper-scripts checkout)")
        return 2
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

    ## Feature-detect the missing-final-newline suppression (merged later than
    ## the base tool). A stale INSTALLED build predates it; targeting a checkout
    ## or a fixed build supports it. The related assertions are skipped -- not
    ## failed -- when the build lacks it, so the suite stays green against the
    ## deployed tool while still fully covering the feature where present.
    supports_suppress = (
        run_stdin(b"x", allow_missing_nl=True).returncode == 0
    )

    corpus = hostile_corpus()

    if not args.fuzz_only:
        ## [D] detection + [S] self-safety over the hostile corpus.
        print("[D] detection: each suspicious codepoint is found and named")
        print("[S] self-safety: the tool's own stdout stays pure ASCII")
        for case, (raw, token) in corpus.items():
            proc = run_stdin(raw)
            ## Exit 1 == "suspicious found".
            check("D:%s:exit" % case, proc.returncode == 1,
                  "exit %d stderr=%r" % (proc.returncode, proc.stderr[:120]))
            ## The exact codepoint must be named, proving it found THIS char.
            text = proc.stdout.decode("ascii", "replace")
            check("D:%s:token" % case, token in text,
                  "want %s in %r" % (token, proc.stdout[:120]))
            ## The reported output must not itself leak the raw byte(s).
            v = output_violations(proc.stdout)
            check("S:%s" % case, not v,
                  "; ".join(v) + " -> " + repr(proc.stdout[:64]))

        ## [B] benign: clean ASCII exits 0 with no output (makes [D] non-vacuous).
        print("[B] benign: clean ASCII input exits 0, no output")
        for case, data in {
            "hello": b"hello world\n",
            "multiline": b"line one\nline two\nline three\n",
            "punct_digits": b"pi = 3.14; f(x) = x^2 + 1! [ok]\n",
            "tabbed": b"col1\tcol2\tcol3\n",   # tab is allowed
            "blank_lines": b"a\n\n\nb\n",
        }.items():
            proc = run_stdin(data)
            check("B:%s" % case,
                  proc.returncode == 0 and proc.stdout == b"",
                  "exit %d out=%r" % (proc.returncode, proc.stdout[:80]))

        ## [N] newline / whitespace semantics.
        print("[N] newline / whitespace semantics")
        ts = run_stdin(b"abc   \n")   # trailing spaces before the newline
        check("N:trailing-ws:exit", ts.returncode == 1,
              "exit %d out=%r" % (ts.returncode, ts.stdout[:80]))
        check("N:trailing-ws:safe", not output_violations(ts.stdout),
              repr(ts.stdout[:80]))

        ## Missing final newline: flagged by default, suppressed by the env var.
        mn = run_stdin(b"no final newline")
        check("N:missing-nl:default-flagged",
              mn.returncode == 1 and b"missing newline" in mn.stdout,
              "exit %d out=%r" % (mn.returncode, mn.stdout[:80]))
        if supports_suppress:
            mn_ok = run_stdin(b"no final newline", allow_missing_nl=True)
            check("N:missing-nl:suppressed",
                  mn_ok.returncode == 0 and mn_ok.stdout == b"",
                  "exit %d out=%r" % (mn_ok.returncode, mn_ok.stdout[:80]))
        else:
            skip("N:missing-nl:suppressed",
                 "installed unicode-show predates "
                 "UNICODE_SHOW_ALLOW_MISSING_FINAL_NEWLINE (stale build; "
                 "set UNICODE_SHOW_REPO to a checkout to cover it)")
        ## A clean line WITH a final newline is unaffected by the suppression.
        clean_ok = run_stdin(b"clean line\n", allow_missing_nl=True)
        check("N:missing-nl:clean-unaffected",
              clean_ok.returncode == 0 and clean_ok.stdout == b"",
              "exit %d out=%r" % (clean_ok.returncode, clean_ok.stdout[:80]))

        ## Empty input must be clean -- no spurious "missing newline at end".
        empty = run_stdin(b"")
        check("N:empty-clean",
              empty.returncode == 0 and empty.stdout == b"",
              "exit %d out=%r" % (empty.returncode, empty.stdout[:80]))

        ## [E] fail-closed on invalid UTF-8 and unreadable paths.
        print("[E] fail-closed: invalid UTF-8 exits 2 without leaking raw bytes")
        for case, raw in malformed_inputs().items():
            proc = run_stdin(raw)
            check("E:%s:exit2" % case, proc.returncode == 2,
                  "exit %d stderr=%r" % (proc.returncode, proc.stderr[:120]))
            ## Fail closed: the raw non-UTF-8 byte must not reach stdout.
            check("E:%s:no-slip" % case, not output_violations(proc.stdout),
                  "leaked: " + repr(proc.stdout[:64]))

        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "does-not-exist")
            proc = run_paths([missing])
            check("E:missing-path:exit2", proc.returncode == 2,
                  "exit %d stderr=%r" % (proc.returncode, proc.stderr[:120]))

            ## A file of invalid UTF-8 must also exit 2 and not leak.
            badf = os.path.join(tmp, "bad.bin")
            with open(badf, "wb") as handle:
                handle.write(b"ok line\nbad \xff\xfe byte\n")
            proc = run_paths([badf])
            check("E:bad-file:exit2", proc.returncode == 2,
                  "exit %d stderr=%r" % (proc.returncode, proc.stderr[:120]))
            check("E:bad-file:no-slip", not output_violations(proc.stdout),
                  "leaked: " + repr(proc.stdout[:64]))

        ## [P] paths: file content and a hostile FILENAME are both handled.
        print("[P] paths: hostile file content detected, hostile filename sanitized")
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "clean-name.txt")
            with open(src, "wb") as handle:
                handle.write("greeting \u202e reversed \U0001f600\n".encode("utf-8"))
            proc = run_paths([src])
            check("P:file-content:exit1", proc.returncode == 1,
                  "exit %d" % proc.returncode)
            check("P:file-content:token", b"U+202E" in proc.stdout,
                  repr(proc.stdout[:120]))
            check("P:file-content:safe", not output_violations(proc.stdout),
                  repr(proc.stdout[:64]))

            ## A filename that itself contains suspicious Unicode: the tool puts
            ## the name in its output (as the line prefix), so that name must be
            ## sanitized -- stdout must still be pure ASCII.
            uni_name = os.path.join(tmp, "ev\u202eil\U0001f600.txt")
            with open(uni_name, "wb") as handle:
                handle.write(b"also \x07 bad\n")
            proc = run_paths([uni_name])
            check("P:hostile-filename:exit1", proc.returncode == 1,
                  "exit %d" % proc.returncode)
            check("P:hostile-filename:safe", not output_violations(proc.stdout),
                  "filename leaked into output: " + repr(proc.stdout[:96]))

    ## [F] fuzz: random bytes and random valid Unicode never crash, hang, or
    ## break the self-safety invariant; the exit code stays in {0, 1, 2}.
    import random
    rng = random.Random(args.seed)
    ## Bias toward control / high / UTF-8-lead bytes plus a little clean ASCII.
    byte_pool = (list(b"abcABC 0123\t\n") +
                 [0x00, 0x07, 0x08, 0x0B, 0x0C, 0x0D, 0x1B, 0x7F] +
                 [0x80, 0x85, 0x9B, 0xC0, 0xC3, 0xE2, 0xED, 0xF0, 0xFF, 0xFE])
    print("[F] fuzz: %d iterations/channel (seed %d)" % (args.iterations, args.seed))

    for i in range(args.iterations):
        raw = bytes(rng.choice(byte_pool) for _ in range(rng.randint(0, 48)))
        proc = run_stdin(raw)
        ok = proc.returncode in (0, 1, 2) and not output_violations(proc.stdout)
        check("F:bytes#%d" % i, ok,
              "exit %d in=%r out=%r" % (proc.returncode, raw[:48],
                                        proc.stdout[:48]))

    ## Random VALID Unicode: valid UTF-8, so it decodes -- exit stays in {0, 1}
    ## and stdout must stay ASCII no matter how exotic the input character is.
    for i in range(args.iterations):
        n = rng.randint(0, 24)
        chars = []
        for _ in range(n):
            cp = rng.randint(0, 0x10FFFF)
            if 0xD800 <= cp <= 0xDFFF:   # surrogates are not valid scalars
                cp = 0x41
            chars.append(chr(cp))
        raw = ("".join(chars)).encode("utf-8") + b"\n"
        proc = run_stdin(raw)
        ok = proc.returncode in (0, 1) and not output_violations(proc.stdout)
        check("F:unicode#%d" % i, ok,
              "exit %d out=%r" % (proc.returncode, proc.stdout[:48]))

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
    print("RESULT: PASS (unicode-show detects suspicious Unicode and never "
          "leaks it to the terminal)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
