#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for dist_ai.webcheck.secrets (gitleaks secret-scan lane).

Drives the REAL module. The detection tests need the gitleaks binary; when it is absent they
SKIP (waived) rather than fail, matching the lane's own standalone/CI contract. The pure
baseline/parse/fingerprint logic is tested unconditionally."""
import contextlib
import io
import os
import shutil
import sys
import tempfile
from pathlib import Path


def _load():
    here = os.path.dirname(os.path.realpath(__file__))
    pkg = os.path.normpath(os.path.join(here, "..", "..", "lib", "python3", "dist-packages"))
    if os.path.isdir(pkg) and pkg not in sys.path:
        sys.path.insert(0, pkg)
    from dist_ai.webcheck import secrets
    return secrets


def run() -> int:
    s = _load()
    stats = {"pass": 0, "fail": 0, "skip": 0}

    def ck(cond, label):
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write("check_secrets_test: %s %s\n" % (status, label))

    def _main(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = s.main(argv)
        return rc, out.getvalue() + err.getvalue()

    # F10: gitleaks ABSENT is a BROKEN INSTALL, not a mere finding. main() must exit a DISTINCT
    # env-unmet code (ENV_UNMET_EXIT, neither 0 nor the exit-1 of a real finding) so the wrapper
    # suppresses suite-complete and site-deploy cannot publish past an un-run secret scan. Force
    # absence by emptying PATH (sandbox-free; no gitleaks on PATH -> FileNotFoundError). Runs
    # regardless of whether gitleaks is installed on this host.
    ck(s.ENV_UNMET_EXIT not in (0, 1), "ENV_UNMET_EXIT is a distinct non-0/non-1 code")
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as bdir, \
            tempfile.TemporaryDirectory() as emptybin:
        Path(root, "index.html").write_text("<html></html>", encoding="utf-8")
        _saved_path = os.environ.get("PATH", "")
        os.environ["PATH"] = emptybin
        try:
            rc, text = _main(["--baseline-dir", bdir, root])
        finally:
            os.environ["PATH"] = _saved_path
        ck(rc == s.ENV_UNMET_EXIT,
           "gitleaks absent -> main returns the distinct env-unmet code (not 0/1): %r" % rc)
        ck("FATAL" in text and "gitleaks not found" in text,
           "gitleaks absent prints a FATAL not-found message")

    # pure: baseline parse/format roundtrip (sorted, comments skipped).
    accepted = {"a.txt:aws-access-token:1", "b.txt:github-pat:1"}
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "b.txt"
        p.write_text(s.format_baseline(accepted, site="demo"), encoding="utf-8")
        ck(s.parse_baseline(p) == accepted, "baseline parse/format roundtrip")
        p.write_text("# only a comment\n\n", encoding="utf-8")
        ck(s.parse_baseline(p) == set(), "comment/blank-only baseline -> empty set")

    # pure: finding_key is <File>:<RuleID>:<StartLine> and IGNORES gitleaks' absolute Fingerprint
    # (which would embed the checkout path and never match a committed baseline elsewhere).
    ck(s.finding_key({"File": "x.txt", "RuleID": "r", "StartLine": 7}) == "x.txt:r:7",
       "finding_key is File:RuleID:StartLine")
    ck(s.finding_key({"Fingerprint": "/abs/x.txt:r:1", "File": "x.txt",
                      "RuleID": "r", "StartLine": 1}) == "x.txt:r:1",
       "finding_key ignores gitleaks' absolute Fingerprint")

    # integration: a planted secret is detected; baseline excuses it; a clean tree yields
    # nothing. gitleaks is a REQUIRED dependency (dist-ai Depends), so its absence is an
    # environment bug that FAILS here, never a skip ("no unauthorized skips").
    have_gitleaks = shutil.which("gitleaks") is not None
    ck(have_gitleaks, "gitleaks (required dependency) is installed")
    if have_gitleaks:
        with tempfile.TemporaryDirectory() as root:
            # a well-known detectable pattern (GitHub PAT), plus a clean page.
            Path(root, "leak.txt").write_text(
                "token = ghp_1234567890abcdefghijklmnopqrstuvwxyzAB\n", encoding="utf-8")
            Path(root, "index.html").write_text("<html><body>clean</body></html>", encoding="utf-8")
            new, all_keys = s.scan_root(root, set())
            ck(len(new) >= 1 and any(f.get("RuleID") == "github-pat" for f in new),
               "scan_root detects a planted github-pat: %r" % [f.get("RuleID") for f in new])
            ck(all("leak.txt" == f.get("File") for f in new),
               "finding File is root-relative: %r" % [f.get("File") for f in new])
            ck(all("Secret" not in f and "Match" not in f for f in new),
               "finding carries NO secret value (redacted-by-field-drop)")
            # baseline the found keys -> a second scan reports NOTHING new.
            new2, _ = s.scan_root(root, all_keys)
            ck(new2 == [], "a baselined finding is not re-reported: %r" % new2)
        with tempfile.TemporaryDirectory() as root:
            Path(root, "index.html").write_text("<html><body>no secrets here</body></html>",
                                                encoding="utf-8")
            new, all_keys = s.scan_root(root, set())
            ck(new == [] and all_keys == set(), "a clean tree yields no findings: %r" % new)
        # checkout-INDEPENDENCE: the identical secret at two DIFFERENT absolute roots must yield
        # the SAME key, so a baseline seeded at one path excuses it at another (claude/codex: the
        # gitleaks Fingerprint embeds the absolute path and would spuriously re-fail in CI).
        with tempfile.TemporaryDirectory() as ra, tempfile.TemporaryDirectory() as rb:
            for r in (ra, rb):
                Path(r, "leak.txt").write_text(
                    "token = ghp_1234567890abcdefghijklmnopqrstuvwxyzAB\n", encoding="utf-8")
            _, keys_a = s.scan_root(ra, set())
            new_b, _ = s.scan_root(rb, keys_a)
            ck(new_b == [], "a baseline from one checkout path excuses the identical finding at "
                            "a different path: %r" % new_b)
        # a tree shipping its own gitleaks config is REFUSED (it could weaken the scan).
        with tempfile.TemporaryDirectory() as root:
            Path(root, ".gitleaks.toml").write_text("[extend]\nuseDefault = false\n", encoding="utf-8")
            Path(root, "index.html").write_text("<html></html>", encoding="utf-8")
            raised = False
            try:
                s.scan_root(root, set())
            except RuntimeError:
                raised = True
            ck(raised, "scan refuses a tree shipping .gitleaks.toml (could disable detection)")
        # main(): write-baseline then gate-clean roundtrip on a planted tree.
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as bdir:
            Path(root, "leak.txt").write_text(
                "token = ghp_1234567890abcdefghijklmnopqrstuvwxyzAB\n", encoding="utf-8")
            rc, _ = _main(["--baseline-dir", bdir, "--write-baseline", root])
            ck(rc == 0, "main --write-baseline exits 0")
            rc, _ = _main(["--baseline-dir", bdir, root])
            ck(rc == 0, "main gate is clean once the finding is baselined")
            os.remove(s._baseline_path(Path(bdir), root))
            rc, text = _main(["--baseline-dir", bdir, root])
            # a real secret finding stays exit 1 -- DISTINCT from the env-unmet code (F10): a
            # finding must read as a finding, not as a broken install, and vice versa.
            ck(rc == 1 and rc != s.ENV_UNMET_EXIT and "SECRET" in text,
               "main FAILs (rc 1, not the env code) on an un-baselined secret")

    passed, failed, skipped = stats["pass"], stats["fail"], stats["skip"]
    sys.stdout.write("check_secrets_test: %d pass, %d fail, %d skip\n" % (passed, failed, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
