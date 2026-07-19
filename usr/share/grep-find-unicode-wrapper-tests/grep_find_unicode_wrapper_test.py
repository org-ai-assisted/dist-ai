#!/usr/bin/env python3
"""
Comprehensive test + fuzz for grep-find-unicode-wrapper: the helper-scripts bash
wrapper around grep that scans FILES for suspicious content and lists the files
that contain any. It is grep-like: exit 0 if a match was found, exit 1 if not,
and it fails loud (grep's error code, e.g. 2) on a grep error such as an
unreadable path. Matching files are printed one path per line, sorted -u and
routed through stecho so a filename that itself contains Unicode cannot smuggle
anything to the terminal.

What counts as suspicious is the UNION of four greps (LC_ALL=C, byte-oriented):
  1/2. any non-ASCII byte (>= 0x80);
  3.   the bidi Trojan-Source control set (RHSB-2021-007) -- a subset of (1);
  4.   ASCII control bytes [\\x00-\\x08 \\x0B-\\x1F \\x7F] (C0 minus tab/newline,
       plus DEL / NUL).
So a file matches iff it contains ANY byte that is NOT printable ASCII
(0x20..0x7E) and NOT tab/newline (0x09/0x0A). grep #4 is the important one the
non-ASCII greps cannot cover: a pure-ASCII control byte (bell, DEL, NUL) is
caught only there.

Contrast with unicode-show (the sibling detector, its own suite): this wrapper
does NOT flag trailing whitespace or a missing final newline -- only the byte
classes above. The suite encodes that difference.

Checks, end to end against the real wrapper:

  [D] detection: a hostile corpus (bidi set, zero-width, BOM, homoglyph,
      combining, C1, CJK, emoji, accented, and C0 control / NUL / DEL) each
      makes the wrapper exit 0 and list the file.
  [C] control-isolation: a file whose ONLY suspicious content is an ASCII
      control byte (no non-ASCII at all) still exits 0 -- proving grep #4's
      independent contribution (greps #1-3 all miss it).
  [B] benign: a pure printable-ASCII file (incl. tabs, and even trailing
      whitespace, which this tool does NOT flag) exits 1 with no output, so [D]
      is non-vacuous.
  [M] multi-file: given clean + dirty files, only the dirty ones are listed,
      sorted and de-duplicated.
  [P] self-safety: a filename that itself contains suspicious Unicode is
      sanitized by stecho -- the wrapper's stdout stays pure ASCII.
  [E] errors: a nonexistent path fails loud (exit 2), not a silent "no match".
  [K] known limitation: stdin is broken (documented in the tool). Only the FIRST
      of the four greps consumes the piped bytes, so a control-only stdin input
      is a FALSE NEGATIVE. Encoded as a strict known-limitation assertion: it
      pins the current (buggy) behaviour and flips to a hard failure if stdin is
      ever fixed, prompting a test update.
  [F] fuzz: random byte files checked against an independent byte-level oracle
      (matches iff any non-clean byte) -- exit code must agree exactly, and the
      output must stay pure ASCII.

No root, no network. The wrapper is resolved from GREP_FIND_UNICODE_WRAPPER_REPO
(a helper-scripts checkout, whose usr/bin is put on PATH so its stecho is used)
else the installed /usr/bin/grep-find-unicode-wrapper.

This file is ASCII-only: every suspicious character is written as a Python escape
and encoded to real UTF-8 bytes at runtime.

Usage: grep_find_unicode_wrapper_test.py [--iterations N] [--seed N] [--fuzz-only]
"""

import argparse
import os
import subprocess
import tempfile

REPO = os.environ.get("GREP_FIND_UNICODE_WRAPPER_REPO")
INSTALLED = "/usr/bin/grep-find-unicode-wrapper"

TIMEOUT_SECONDS = 30

## Bytes the wrapper considers CLEAN: printable ASCII plus tab and newline.
## Any other byte (non-ASCII, a C0 control other than tab/newline, or DEL) makes
## a file match. This is the oracle the fuzzer checks the tool against.
CLEAN_BYTES = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A}


def tool_path():
    return os.path.join(REPO, "usr/bin/grep-find-unicode-wrapper") if REPO \
        else INSTALLED


def tool_env():
    env = dict(os.environ)
    if REPO:
        ## The wrapper calls stecho / sort from PATH; put the checkout's usr/bin
        ## first so its stecho is used, and set PYTHONPATH so that stecho (a thin
        ## python entry point) can import its stdisplay module from the checkout.
        env["PATH"] = os.path.join(REPO, "usr/bin") + os.pathsep + env.get("PATH", "")
        env["PYTHONPATH"] = os.path.join(REPO, "usr/lib/python3/dist-packages")
    return env


def _invoke(argv, data=None):
    try:
        return subprocess.run(
            argv, input=data, capture_output=True, env=tool_env(),
            check=False, timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            argv, 124, exc.stdout or b"", b"TIMEOUT"
        )


def run_paths(paths):
    return _invoke([tool_path()] + list(paths))


def run_stdin(data):
    return _invoke([tool_path()], data)


def output_violations(out):
    r"""The wrapper's stdout (a list of file paths via stecho) must be pure
    printable ASCII plus newline/tab: no Unicode, no control char (other than
    \n / \t), no ESC, no DEL."""
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


def should_match(data):
    """Independent oracle: the wrapper matches iff the bytes contain anything
    that is not clean printable ASCII / tab / newline."""
    return any(b not in CLEAN_BYTES for b in data)


## ---------------------------------------------------------------------------
## Hostile corpus: name -> (payload bytes, class). "nonascii" is caught by greps
## #1-3; "control" is caught ONLY by grep #4. Unicode via escapes (ASCII source).
## ---------------------------------------------------------------------------
def hostile_corpus():
    def u(text):
        return text.encode("utf-8")

    return {
        ## Non-ASCII (bidi Trojan-Source set, invisibles, homoglyph, CJK, etc).
        "rlo": (u("\u202e"), "nonascii"),        # U+202E right-to-left override
        "lre": (u("\u202a"), "nonascii"),        # U+202A
        "pdi": (u("\u2069"), "nonascii"),        # U+2069
        "alm": (u("\u061c"), "nonascii"),        # U+061C arabic letter mark
        "zwsp": (u("\u200b"), "nonascii"),       # U+200B zero-width space
        "bom": (u("\ufeff"), "nonascii"),        # U+FEFF
        "homoglyph": (u("\u0430"), "nonascii"),   # U+0430 cyrillic small a
        "combining": (u("\u0301"), "nonascii"),    # U+0301
        "cjk": (u("\u4f60"), "nonascii"),        # U+4F60
        "emoji": (u("\U0001f600"), "nonascii"),
        "accented": (u("\u00e9"), "nonascii"),    # U+00E9
        "c1_nel": (u("\u0085"), "nonascii"),      # U+0085 NEL -> 0xC2 0x85
        "c1_csi": (u("\u009b"), "nonascii"),      # U+009B CSI -> 0xC2 0x9B
        ## ASCII control bytes -- caught ONLY by grep #4.
        "nul": (b"\x00", "control"),
        "bell": (b"\x07", "control"),
        "backspace": (b"\x08", "control"),
        "vtab": (b"\x0b", "control"),
        "formfeed": (b"\x0c", "control"),
        "carriage_return": (b"\r", "control"),
        "esc": (b"\x1b", "control"),
        "unit_sep": (b"\x1f", "control"),
        "del": (b"\x7f", "control"),
    }


def main():  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    parser = argparse.ArgumentParser(
        description="grep-find-unicode-wrapper test + fuzz")
    parser.add_argument("--iterations", type=int, default=400,
                        help="fuzz iterations")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--fuzz-only", action="store_true")
    args = parser.parse_args()

    print("grep-find-unicode-wrapper test + fuzz")
    print("tool: " + (("checkout " + REPO) if REPO else "installed /usr/bin"))
    if not REPO and not os.path.exists(INSTALLED):
        print("ERROR: %s not found "
              "(set GREP_FIND_UNICODE_WRAPPER_REPO to a helper-scripts checkout)"
              % INSTALLED)
        return 2
    print()

    passed = 0
    failed = 0
    fail_samples = []

    def check(name, ok, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
            if len(fail_samples) < 40:
                fail_samples.append(name + ": " + detail)

    def write(tmp, name, payload):
        path = os.path.join(tmp, name)
        with open(path, "wb") as handle:
            handle.write(b"prefix " + payload + b" suffix\n")
        return path

    if not args.fuzz_only:
        with tempfile.TemporaryDirectory() as tmp:
            ## [D] detection + [S] self-safety over the hostile corpus.
            print("[D] detection: each suspicious file is found and listed")
            print("[C] control-isolation: pure-ASCII control bytes are caught")
            for case, (payload, cls) in hostile_corpus().items():
                path = write(tmp, "case_" + case + ".txt", payload)
                proc = run_paths([path])
                tag = "D" if cls == "nonascii" else "C"
                check("%s:%s:exit" % (tag, case), proc.returncode == 0,
                      "exit %d stderr=%r" % (proc.returncode, proc.stderr[:120]))
                check("%s:%s:listed" % (tag, case),
                      os.path.basename(path).encode() in proc.stdout,
                      "path not listed: %r" % proc.stdout[:120])
                check("%s:%s:safe" % (tag, case),
                      not output_violations(proc.stdout),
                      repr(proc.stdout[:64]))

        ## [B] benign: clean ASCII files exit 1 with no output.
        print("[B] benign: clean ASCII (incl. trailing ws) is not flagged")
        with tempfile.TemporaryDirectory() as tmp:
            benign = {
                "plain": b"hello world\nsecond line\n",
                "tabs": b"col1\tcol2\tcol3\n",              # tab is clean
                "trailing_ws": b"line with trailing spaces   \n",  # NOT flagged
                "empty": b"",
                "punct": b"pi=3.14; f(x)=x^2+1! [ok] {y}\n",
            }
            for case, data in benign.items():
                path = os.path.join(tmp, "benign_" + case + ".txt")
                with open(path, "wb") as handle:
                    handle.write(data)
                proc = run_paths([path])
                check("B:%s" % case,
                      proc.returncode == 1 and proc.stdout == b"",
                      "exit %d out=%r" % (proc.returncode, proc.stdout[:80]))

        ## [M] multi-file: only the dirty files are listed, sorted and unique.
        print("[M] multi-file: only dirty files listed, sorted -u")
        with tempfile.TemporaryDirectory() as tmp:
            clean1 = os.path.join(tmp, "a_clean.txt")
            clean2 = os.path.join(tmp, "b_clean.txt")
            dirty1 = os.path.join(tmp, "c_dirty.txt")
            dirty2 = os.path.join(tmp, "d_dirty.txt")
            for p in (clean1, clean2):
                with open(p, "wb") as handle:
                    handle.write(b"totally fine\n")
            with open(dirty1, "wb") as handle:
                handle.write("bidi \u202e here\n".encode("utf-8"))
            with open(dirty2, "wb") as handle:
                handle.write(b"control \x07 here\n")
            proc = run_paths([clean1, dirty1, clean2, dirty2])
            listed = proc.stdout.decode("ascii", "replace").split()
            check("M:exit", proc.returncode == 0, "exit %d" % proc.returncode)
            check("M:only-dirty",
                  set(os.path.basename(x) for x in listed)
                  == {"c_dirty.txt", "d_dirty.txt"},
                  "listed=%r" % proc.stdout[:160])
            check("M:sorted",
                  listed == sorted(listed),
                  "not sorted: %r" % proc.stdout[:160])

        ## [P] self-safety: a hostile FILENAME must be sanitized in the output.
        print("[P] self-safety: hostile filename sanitized in output")
        with tempfile.TemporaryDirectory() as tmp:
            uni_name = "ev\u202eil\U0001f600.txt"
            path = os.path.join(tmp, uni_name)
            with open(path, "wb") as handle:
                handle.write(b"content \x07 here\n")
            proc = run_paths([path])
            check("P:exit", proc.returncode == 0, "exit %d" % proc.returncode)
            check("P:safe", not output_violations(proc.stdout),
                  "filename leaked into output: " + repr(proc.stdout[:96]))

        ## [E] errors: a nonexistent path must fail loud, not report "no match".
        print("[E] errors: nonexistent path fails loud (not a silent no-match)")
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_paths([os.path.join(tmp, "does-not-exist")])
            check("E:nonexistent:exit", proc.returncode not in (0, 1),
                  "expected a loud grep error, got exit %d" % proc.returncode)

        ## [K] known limitation: stdin is broken (see the tool's TODO). Only the
        ## first grep consumes the pipe, so a control-only stdin input is a FALSE
        ## NEGATIVE. Pin the current behaviour; if stdin is ever fixed these flip
        ## to failures and the test must be updated.
        print("[K] known limitation: stdin (documented broken) -- pinned")
        stdin_nonascii = run_stdin("x \u202e y\n".encode("utf-8"))
        ## Non-ASCII IS caught, because the FIRST grep scans for it.
        check("K:stdin-nonascii-detected", stdin_nonascii.returncode == 0,
              "exit %d (first grep should catch non-ASCII on stdin)"
              % stdin_nonascii.returncode)
        check("K:stdin-nonascii-safe",
              not output_violations(stdin_nonascii.stdout),
              repr(stdin_nonascii.stdout[:64]))
        stdin_control = run_stdin(b"x \x07 y\n")
        ## Control-only is MISSED on stdin (grep #4 sees EOF). This is the bug;
        ## returncode 1 == "no match" is the current, wrong-but-documented result.
        check("K:stdin-control-false-negative(known)",
              stdin_control.returncode == 1,
              "stdin control handling CHANGED (exit %d): the wrapper's stdin "
              "limitation may be fixed -- update this test"
              % stdin_control.returncode)

    ## [F] fuzz: random byte files vs an independent byte-level oracle. The exit
    ## code must agree exactly (0 iff a non-clean byte is present), and the
    ## output must stay pure ASCII.
    import random
    rng = random.Random(args.seed)
    ## Bias toward the exact clean/dirty boundary bytes plus clean ASCII.
    byte_pool = (list(b"abcABC 0123\t\n") +
                 [0x00, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1B, 0x1F,
                  0x20, 0x7E, 0x7F, 0x80, 0x85, 0x9B, 0xC2, 0xE2, 0xF0, 0xFF])
    print("[F] fuzz: %d iterations vs byte-level oracle (seed %d)"
          % (args.iterations, args.seed))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "fuzz.bin")
        for i in range(args.iterations):
            data = bytes(rng.choice(byte_pool) for _ in range(rng.randint(0, 48)))
            with open(path, "wb") as handle:
                handle.write(data)
            proc = run_paths([path])
            want = should_match(data)
            got = proc.returncode == 0
            ok = (got == want) and proc.returncode in (0, 1) \
                and not output_violations(proc.stdout)
            check("F:#%d" % i, ok,
                  "want match=%s got exit=%d in=%r out=%r"
                  % (want, proc.returncode, data[:48], proc.stdout[:48]))

    print()
    print("%d passed, %d failed" % (passed, failed))
    if fail_samples:
        print("failures (sample):")
        for sample in fail_samples:
            print("  - " + sample)
    if failed:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS (grep-find-unicode-wrapper flags exactly the suspicious "
          "byte classes and never leaks a filename to the terminal)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
