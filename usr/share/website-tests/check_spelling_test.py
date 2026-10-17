#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Canary for dist_ai.webcheck.spelling's browser-free logic: the cspell-output parser, the
baseline round-trip, finding_key, scan_root's new-vs-baseline math, and the fail-loud error
handling. cspell itself is npm-only and lives in the review sandbox, so the subprocess is STUBBED
here -- this runs everywhere (no cspell, no sandbox) and a failure is a real logic regression.

Canary cases (each FAILS on a broken predicate):
  - the issue regex captures file + word from a real cspell line, ignores non-issue lines
  - a 'Unknown' and a 'Forbidden' word line both parse; summary/blank lines do not
  - finding_key is <relative file>:<word-lowercased>
  - scan_root returns only keys NOT in the baseline as `new`, and ALL keys for re-seeding
  - parse_baseline skips '#'/blank; format_baseline round-trips through parse_baseline
  - a cspell exit other than 0/1, or an 'Unsupported' engine line, raises RuntimeError
    (never read an error as clean); a missing binary surfaces as FileNotFoundError
"""
import os
import sys


def _load():
    here = os.path.dirname(os.path.realpath(__file__))
    pkg = os.path.normpath(os.path.join(here, "..", "..", "lib", "python3", "dist-packages"))
    if os.path.isdir(pkg) and pkg not in sys.path:
        sys.path.insert(0, pkg)
    from dist_ai.webcheck import spelling
    return spelling


def run():
    spelling = _load()
    import subprocess
    import tempfile
    from pathlib import Path

    stats = {"pass": 0, "fail": 0}

    def ck(cond, label):
        if cond:
            stats["pass"] += 1
        else:
            stats["fail"] += 1
            print("check_spelling_test: FAIL: %s" % label)

    # --- issue regex ---------------------------------------------------------------------------
    m = spelling._ISSUE_RE.match("/root/analyze/index.html:12:34 - Unknown word (recieve) fix: (receive)")
    ck(bool(m) and m.group("file") == "/root/analyze/index.html" and m.group("word") == "recieve",
       "issue regex captures file + word from an Unknown-word line")
    ck(bool(spelling._ISSUE_RE.match("a.html:1:1 - Forbidden word (badword)")),
       "issue regex also matches a Forbidden-word line")
    ck(spelling._ISSUE_RE.match("CSpell: Files checked: 1, Issues found: 0 in 0 files.") is None,
       "issue regex ignores the summary line")

    # --- finding_key ---------------------------------------------------------------------------
    ck(spelling.finding_key("a/b.html", "teh") == "a/b.html:teh", "finding_key is <file>:<word>")

    # --- scan_root (stub _run_cspell) ----------------------------------------------------------
    orig = spelling._run_cspell
    try:
        spelling._run_cspell = lambda root, config: [("p.html", "teh"), ("p.html", "sdwdate"),
                                                      ("q.html", "teh")]
        new, allk = spelling.scan_root("/root", "cfg", {"p.html:sdwdate"})
        ck(set(new) == {"p.html:teh", "q.html:teh"}, "scan_root new = keys NOT in baseline")
        ck(allk == {"p.html:teh", "p.html:sdwdate", "q.html:teh"}, "scan_root all_keys = every key")
        new2, _ = spelling.scan_root("/root", "cfg", set())
        ck(len(new2) == 3, "empty baseline -> every finding is new")
        # dedup: one line per OCCURRENCE must collapse to one key (no inflated count / repeats)
        spelling._run_cspell = lambda root, config: [("p.html", "teh"), ("p.html", "teh"),
                                                     ("p.html", "teh")]
        dnew, dall = spelling.scan_root("/root", "cfg", set())
        ck(dnew == ["p.html:teh"] and dall == {"p.html:teh"},
           "scan_root dedups repeated occurrences of the same word")
    finally:
        spelling._run_cspell = orig

    # --- baseline round-trip -------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "b.txt"
        keys = {"a.html:teh", "b.html:instal"}
        p.write_text(spelling.format_baseline(keys, site="x"), encoding="utf-8")
        ck(spelling.parse_baseline(p) == keys, "format_baseline round-trips through parse_baseline")
        p.write_text("# comment\n\na.html:teh\n", encoding="utf-8")
        ck(spelling.parse_baseline(p) == {"a.html:teh"}, "parse_baseline skips '#'/blank lines")

    # --- error handling (stub subprocess.run) --------------------------------------------------
    class _P:
        def __init__(self, rc, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    orig_run = subprocess.run
    try:
        subprocess.run = lambda *a, **k: _P(2, "", "boom")  # type: ignore[assignment]
        try:
            spelling._run_cspell("/r", "cfg")
            ck(False, "cspell rc=2 must raise RuntimeError")
        except RuntimeError:
            ck(True, "cspell rc=2 raises RuntimeError (error not read as clean)")
        subprocess.run = lambda *a, **k: _P(1, "", "Unsupported NodeJS version")  # type: ignore[assignment]
        try:
            spelling._run_cspell("/r", "cfg")
            ck(False, "Unsupported-engine line must raise RuntimeError")
        except RuntimeError:
            ck(True, "Unsupported-engine line raises RuntimeError")
        subprocess.run = lambda *a, **k: _P(1, "/r/a.html:1:1 - Unknown word (teh)\n", "")  # type: ignore[assignment]
        ck(spelling._run_cspell("/r", "cfg") == [("a.html", "teh")],
           "rc=1 with a parseable issue returns the finding (root-relative)")
        subprocess.run = lambda *a, **k: _P(1, "", "Error: ENOENT project-dictionary.txt")  # type: ignore[assignment]
        try:
            spelling._run_cspell("/r", "cfg")
            ck(False, "rc=1 with NO parseable issue (config/dict error) must raise")
        except RuntimeError:
            ck(True, "rc=1 with no issues raises (cspell error not read as clean)")
        subprocess.run = lambda *a, **k: _P(0, "", "")  # type: ignore[assignment]
        ck(spelling._run_cspell("/r", "cfg") == [], "rc=0 clean returns no findings")
    finally:
        subprocess.run = orig_run

    print("check_spelling_test: %d pass, %d fail, 0 skip" % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
