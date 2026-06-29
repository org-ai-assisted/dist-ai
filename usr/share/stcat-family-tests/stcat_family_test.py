#!/usr/bin/env python3
"""
Comprehensive test + fuzz for the stcat family: the stdisplay CLI tools that
make untrusted text safe to print to a terminal -- stcat, stcatn, stecho,
stprint, stsponge, sttee (helper-scripts, stdisplay package).

Threat model: each tool reads untrusted input (stdin, a file, or argv) and
writes it to a terminal (and, for stsponge/sttee, to a file). The output must
not be able to smuggle anything dangerous to the terminal: no non-ASCII /
Unicode (RLO, zero-width, homoglyphs, C1), no control characters other than
newline and tab, and no escape sequences other than colour (SGR), and only
when colour is enabled.

Each tool applies two layers: it routes input through stdisplay() and forces
its stdout (and file outputs) to ASCII with errors="replace". This suite
proves, across all six tools, that:

  [U] no-colour mode (NO_COLOR=1, i.e. stdisplay sgr=-1): output is pure
      printable ASCII plus newline/tab -- no Unicode, no control char, no ESC,
      no DEL -- for a hostile corpus and a byte-level fuzzer.
  [C] colour mode (COLORTERM=truecolor): Unicode is still stripped, and the
      ONLY escape sequences that survive are well-formed SGR (ESC [ ... m);
      non-SGR escapes (OSC-8 hyperlinks, CSI cursor/clear) are neutralised.
  [S] semantics: on benign input each tool still does its job (cat / numbered
      cat-with-trim / echo / print / sponge / tee), including file paths.
  [F] fuzz: random byte streams (Unicode, control, escapes, malformed UTF-8,
      NUL) never break the [U] invariant.

No root, no network. Tools are resolved from STDISPLAY_REPO (a helper-scripts
checkout, run via the module) else the installed /usr/bin/<tool>.

Usage: stcat_family_test.py [--iterations N] [--seed N] [--fuzz-only]
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

REPO = os.environ.get("STDISPLAY_REPO")
STDIN_TOOLS = ["stcat", "stcatn", "stsponge", "sttee"]
ARG_TOOLS = ["stecho", "stprint"]
ALL_TOOLS = STDIN_TOOLS + ARG_TOOLS

## A well-formed SGR sequence: ESC [ , then only digits / ; / : , then m.
SGR_RE = re.compile(rb"\x1b\[[0-9;:]*m")


def tool_argv(name):
    if REPO:
        return [sys.executable, "-c", "from stdisplay.%s import main; main()" % name]
    return ["/usr/bin/" + name]


def tool_env(color):
    env = dict(os.environ)
    if REPO:
        env["PYTHONPATH"] = os.path.join(REPO, "usr/lib/python3/dist-packages")
    env.pop("NO_COLOR", None)
    if color:
        env["COLORTERM"] = "truecolor"
    else:
        env["NO_COLOR"] = "1"
        env.pop("COLORTERM", None)
    return env


## Per-invocation wall-clock limit. These tools are streaming sanitizers; any
## input that makes one hang is itself a failure, so a timeout becomes a
## non-zero "exit" rather than wedging the run.
TIMEOUT_SECONDS = 30


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


def run_stdin(name, data, color=False, args=None):
    return _invoke(tool_argv(name) + (args or []), tool_env(color), data)


def run_args(name, str_args, color=False):
    return _invoke(tool_argv(name) + str_args, tool_env(color))


## ---------------------------------------------------------------------------
## Oracles
## ---------------------------------------------------------------------------
def violations_nocolor(out):
    """[U] output must be pure printable ASCII + newline/tab."""
    v = []
    if any(b >= 0x80 for b in out):
        v.append("non-ASCII " + str([hex(b) for b in out if b >= 0x80][:6]))
    if any(b < 0x20 and b not in (0x09, 0x0A) for b in out):
        v.append("control " + str([hex(b) for b in out if b < 0x20
                                    and b not in (0x09, 0x0A)][:6]))
    if 0x1B in out:
        v.append("ESC")
    if 0x7F in out:
        v.append("DEL")
    return v


def violations_color(out):
    """[C] Unicode still stripped; the only escapes left are valid SGR."""
    v = []
    if any(b >= 0x80 for b in out):
        v.append("non-ASCII " + str([hex(b) for b in out if b >= 0x80][:6]))
    ## Remove every well-formed SGR run, then nothing dangerous may remain.
    rest = SGR_RE.sub(b"", out)
    if 0x1B in rest:
        v.append("non-SGR ESC survived")
    if any(b < 0x20 and b not in (0x09, 0x0A) for b in rest):
        v.append("control")
    if 0x7F in rest:
        v.append("DEL")
    return v


def proc_violations(proc, color):
    """Combine a non-zero-exit check (these tools must always succeed) with the
    byte-level output check, so a crash or rejection cannot pass as 'clean'."""
    v = []
    if proc.returncode != 0:
        v.append("exit %d stderr=%r" % (proc.returncode, proc.stderr[:120]))
    v += violations_color(proc.stdout) if color else violations_nocolor(proc.stdout)
    return v


## ---------------------------------------------------------------------------
## Hostile corpus (bytes). Unicode is written via escapes to keep this file
## ASCII; .encode() turns it into the real UTF-8 bytes fed to the tool.
## ---------------------------------------------------------------------------
def hostile_corpus():
    return {
        "emoji": "\U0001f600".encode("utf-8"),
        "rlo": "\u202e".encode("utf-8"),          # right-to-left override
        "lro": "\u202d".encode("utf-8"),
        "zero_width": "a\u200bb".encode("utf-8"),  # zero-width space
        "cjk": "\u4f60\u597d".encode("utf-8"),
        "combining": "a\u0301".encode("utf-8"),
        "nel": "a\u0085b".encode("utf-8"),         # C1 NEL
        "line_sep": "a\u2028b".encode("utf-8"),
        "para_sep": "a\u2029b".encode("utf-8"),
        "ansi_sgr": b"\x1b[31mRED\x1b[0m",
        "osc8": b"\x1b]8;;http://example.com\x07link\x1b]8;;\x07",
        "csi_cursor": b"\x1b[2J\x1b[1;1Hcleared",
        "bell_bs": b"a\x07b\x08c",
        "cr_vt_ff": b"a\rb\x0bc\x0cd",
        "del": b"a\x7fb",
        "c1_block": bytes(range(0x80, 0xA0)),
        "malformed": b"a\xffb\xfec\xc0\x80d\x80e\xed\xa0\x80f",
        "nul": b"a\x00b",
        "overlong_slash": b"\xc0\xaf",
    }


def main():  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    parser = argparse.ArgumentParser(description="stcat family test + fuzz")
    parser.add_argument("--iterations", type=int, default=250,
                        help="fuzz iterations per tool")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--fuzz-only", action="store_true")
    args = parser.parse_args()

    print("stcat family test + fuzz")
    print("tools: " + (("checkout " + REPO) if REPO else "installed /usr/bin"))
    missing = [t for t in ALL_TOOLS
               if not REPO and not os.path.exists("/usr/bin/" + t)]
    if missing:
        print("ERROR: tools not found: " + ", ".join(missing)
              + " (set STDISPLAY_REPO to a helper-scripts checkout)")
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
            if len(fail_samples) < 30:
                fail_samples.append(name + ": " + detail)

    def feed(tool, raw, color):
        """Drive a tool with one hostile/byte input via its natural channel."""
        if tool in ARG_TOOLS:
            if b"\x00" in raw:
                return None  # argv cannot carry NUL
            return run_args(tool, [raw.decode("utf-8", "surrogateescape")], color)
        return run_stdin(tool, raw, color)

    def semantic(name, proc, expected):
        check(name, proc.returncode == 0 and proc.stdout == expected,
              "exit %d out=%r (want %r)" % (proc.returncode, proc.stdout[:48],
                                            expected[:48]))

    corpus = hostile_corpus()

    if not args.fuzz_only:
        ## [U] no-colour: nothing but printable ASCII + \n/\t may survive, and
        ## the tool must exit 0 (a crash/rejection is a failure, not a pass).
        print("[U] no-colour: output is pure ASCII (no Unicode/control/ESC/DEL)")
        for tool in ALL_TOOLS:
            for case, raw in corpus.items():
                proc = feed(tool, raw, color=False)
                if proc is None:
                    continue
                v = proc_violations(proc, color=False)
                check("U:%s:%s" % (tool, case), not v,
                      "; ".join(v) + " -> " + repr(proc.stdout[:48]))

        ## [C] colour: Unicode still stripped, only SGR escapes survive.
        print("[C] colour: Unicode stripped, only well-formed SGR survives")
        for tool in ALL_TOOLS:
            for case, raw in corpus.items():
                proc = feed(tool, raw, color=True)
                if proc is None:
                    continue
                v = proc_violations(proc, color=True)
                check("C:%s:%s" % (tool, case), not v,
                      "; ".join(v) + " -> " + repr(proc.stdout[:48]))
        ## SGR must actually pass through in colour mode (not over-stripped).
        sgr = run_stdin("stcat", b"\x1b[31mRED\x1b[0m\n", color=True)
        check("C:stcat:sgr-preserved",
              sgr.returncode == 0 and b"\x1b[31m" in sgr.stdout,
              "SGR colour was stripped in colour mode: " + repr(sgr.stdout))

        ## [S] semantics on benign input.
        print("[S] semantics: each tool still performs its function")
        semantic("S:stcat", run_stdin("stcat", b"hello world\n"), b"hello world\n")
        semantic("S:stcatn-trim",
                 run_stdin("stcatn", b"trailing   \nno final nl"),
                 b"trailing\nno final nl\n")
        semantic("S:stecho", run_args("stecho", ["a", "b", "c"]), b"a b c\n")
        semantic("S:stprint", run_args("stprint", ["a", "b", "c"]), b"abc")
        semantic("S:stsponge", run_stdin("stsponge", b"l1\nl2\n"), b"l1\nl2\n")
        semantic("S:sttee-stdout", run_stdin("sttee", b"tee me\n"), b"tee me\n")

        ## [S] file paths: stcat reads a file; stsponge/sttee write a file, and
        ## the file content must be sanitised too (opened ASCII/errors=replace).
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src")
            with open(src, "wb") as handle:
                handle.write("hi \u202e \U0001f600 \x1b[31m bye\n".encode("utf-8"))
            cat = run_args("stcat", [src])
            check("S:stcat-file", not proc_violations(cat, color=False),
                  "file read not sanitised: " + repr(cat.stdout))

            sp_out = os.path.join(tmp, "sponge_out")
            sp = run_stdin("stsponge", "x\u202e\U0001f600\x1b[2Jy\n".encode("utf-8"),
                           args=[sp_out])
            with open(sp_out, "rb") as handle:
                sp_bytes = handle.read()
            check("S:stsponge-file",
                  sp.returncode == 0 and not violations_nocolor(sp_bytes),
                  "sponge file not sanitised: exit %d %r" % (sp.returncode, sp_bytes))

            tee_out = os.path.join(tmp, "tee_out")
            tee = run_stdin("sttee", "z\u202e\U0001f600\x07w\n".encode("utf-8"),
                            args=[tee_out])
            with open(tee_out, "rb") as handle:
                tee_bytes = handle.read()
            ## sttee writes to BOTH the file and stdout: check both.
            check("S:sttee-file",
                  tee.returncode == 0 and not violations_nocolor(tee_bytes),
                  "tee file not sanitised: exit %d %r" % (tee.returncode, tee_bytes))
            check("S:sttee-file-stdout", not proc_violations(tee, color=False),
                  "tee stdout not sanitised: " + repr(tee.stdout))

    ## [F] fuzz: random byte streams must never break the [U] invariant.
    import random
    rng = random.Random(args.seed)
    ## Bias toward escape / Unicode / control / malformed bytes.
    pool = (list(b"\x1b[];:m0123456789abcABC \t\n/") +
            [0x00, 0x07, 0x08, 0x0B, 0x0C, 0x0D, 0x7F, 0x80, 0x9B, 0xFF, 0xFE]
            + list("\u202e\u200b\u4f60\u0301\u0085\u2028".encode("utf-8")))
    print("[F] fuzz: %d iterations/tool (seed %d)" % (args.iterations, args.seed))
    for tool in ALL_TOOLS:
        for i in range(args.iterations):
            raw = bytes(rng.choice(pool) for _ in range(rng.randint(0, 40)))
            proc = feed(tool, raw, color=False)
            if proc is None:
                continue
            v = proc_violations(proc, color=False)
            check("F:%s#%d" % (tool, i), not v,
                  "; ".join(v) + " in=" + repr(raw[:48])
                  + " out=" + repr(proc.stdout[:48]))

    print()
    print("%d passed, %d failed" % (passed, failed))
    if fail_samples:
        print("failures (sample):")
        for sample in fail_samples:
            print("  - " + sample)
    if failed:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS (no Unicode/control/escape bypass across the stcat family)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
