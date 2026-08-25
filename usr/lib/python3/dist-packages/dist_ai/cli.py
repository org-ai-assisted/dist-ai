## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Command-line logic for the one style tool, dist-ai-style. A single binary
with three modes selected by flag; the bin is a thin wrapper over main().

  --detect  -- emit US-delimited findings for a machine caller (the gate reads
               these). Crash-distinct exit 3.
  --fix     -- apply (or, with --check, report) the mechanical fixes.
  (default) -- the unified human front: fix-then-check, or --check for read-only.

Exit codes are uniform: 0 clean, 1 findings/changes-needed, 2 usage or a
required tool (shfmt) absent; 3 an unexpected crash in --detect (so a caller
never mistakes a crash for 'no findings')."""

import argparse
import sys
import traceback

from dist_ai import bash_ast
from dist_ai import engine
from dist_ai import gitdiff
from dist_ai import model

US = "\x1f"


def _load(files, staged, prog):
    """(contexts, error_code). error_code is an int to return on failure, else
    None. A missing path or a broken staged query is exit 2, never a silent skip."""
    try:
        pairs = gitdiff.given_pairs(files)
    except FileNotFoundError as exc:
        print("%s: no such path: %s" % (prog, exc), file=sys.stderr)
        return None, 2
    if staged:
        try:
            pairs += gitdiff.staged_pairs()
        except gitdiff.StagedDiscoveryError as exc:
            print("%s: could not list staged files: %s" % (prog, exc),
                  file=sys.stderr)
            return None, 2
    return gitdiff.contexts(pairs), None


def _emit_findings(findings, out):
    """Append US-delimited records for FINDINGS to OUT; return True if any FAIL."""
    any_fail = False
    for finding in findings:
        if finding.severity == model.FAIL:
            any_fail = True
            out.append(US.join(
                (model.FAIL, finding.message,
                 "'%s:%d'" % (finding.path, finding.line))))
        else:
            out.append(US.join((model.NOTE, finding.message)))
    return any_fail


def detect_main(argv, prog="dist-ai-style --detect"):
    """Emit US-delimited findings for the files named on the command line
    (SHELL + CONFIG + TEXT rules), and, with --message-file, the non-ASCII floor
    over a commit-message blob that is not a tree file."""
    parser = argparse.ArgumentParser(prog=prog, add_help=True)
    parser.add_argument("--message-file",
                        help="check this commit-message blob for R-001 non-ASCII")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv[1:])
    if not args.files and args.message_file is None:
        print("usage: %s [--message-file MSG] <file|dir>..." % prog,
              file=sys.stderr)
        return 2
    contexts, code = _load(args.files, staged=False, prog=prog)
    if code is not None:
        return code
    out = []
    any_fail = False
    for ctx in contexts:
        try:
            findings = engine.detect(ctx, include_text=True)
        except bash_ast.ShfmtMissing as exc:
            print("%s: shfmt is required but unavailable: %s" % (prog, exc),
                  file=sys.stderr)
            return 2
        any_fail = _emit_findings(findings, out) or any_fail
    if args.message_file is not None:
        try:
            with open(args.message_file, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            print("%s: cannot read --message-file: %s" % (prog, exc),
                  file=sys.stderr)
            return 2
        any_fail = _emit_findings(engine.detect_message(raw), out) or any_fail
    if out:
        sys.stdout.write("\n".join(out) + "\n")
    return 1 if any_fail else 0


def _fix_summary(prog, path, changes, check):
    verb = "would fix" if check else "fixed"
    summary = ", ".join("%s x%d" % (rule, num) for rule, num in changes.items())
    print("%s: %s %s: %s" % (prog, verb, path, summary), file=sys.stderr)


def fix_main(argv, prog="dist-ai-style --fix"):
    """Apply the mechanical fixes in place (or, with --check, only report them)."""
    parser = argparse.ArgumentParser(prog=prog, add_help=True)
    parser.add_argument("--check", action="store_true",
                        help="report only; exit 1 if changes are needed")
    parser.add_argument("--staged", action="store_true",
                        help="operate on the repo's staged files")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv[1:])
    contexts, code = _load(args.files, args.staged, prog)
    if code is not None:
        return code
    if not contexts:
        return 0
    any_changed = False
    for ctx in contexts:
        try:
            changes = engine.apply_fixes(ctx, check=args.check)
        except bash_ast.ShfmtMissing as exc:
            print("%s: shfmt is required to parse shell files but is "
                  "unavailable: %s" % (prog, exc), file=sys.stderr)
            return 2
        if changes:
            any_changed = True
            _fix_summary(prog, ctx.path, changes, args.check)
    if args.check and any_changed:
        return 1
    return 0


def style_main(argv, prog="dist-ai-style"):
    """The unified front. Default: fix-then-check -- apply the mechanical fixes,
    print what changed, then report the residual violations. --check: read-only
    (no writes), report every violation."""
    parser = argparse.ArgumentParser(prog=prog, add_help=True)
    parser.add_argument("--check", action="store_true",
                        help="read-only: report violations, do not fix")
    parser.add_argument("--staged", action="store_true",
                        help="operate on the repo's staged files")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv[1:])
    if not args.files and not args.staged:
        print("usage: %s [--check] [--staged] <file|dir>..." % prog,
              file=sys.stderr)
        return 2
    contexts, code = _load(args.files, args.staged, prog)
    if code is not None:
        return code

    ## Fix first (unless read-only), then re-read from disk so the detect pass
    ## judges the FIXED file -- the residual is exactly what a human must fix.
    if not args.check:
        for ctx in contexts:
            try:
                changes = engine.apply_fixes(ctx, check=False)
            except bash_ast.ShfmtMissing as exc:
                print("%s: shfmt is required but unavailable: %s" % (prog, exc),
                      file=sys.stderr)
                return 2
            if changes:
                _fix_summary(prog, ctx.path, changes, check=False)
        contexts, code = _load(args.files, args.staged, prog)
        if code is not None:
            return code

    any_fail = False
    for ctx in contexts:
        try:
            findings = engine.detect(ctx, include_text=True)
        except bash_ast.ShfmtMissing as exc:
            print("%s: shfmt is required but unavailable: %s" % (prog, exc),
                  file=sys.stderr)
            return 2
        for finding in findings:
            if finding.severity == model.FAIL:
                any_fail = True
                print("%s: FAIL %s: '%s:%s'" % (
                    prog, finding.message, finding.path, finding.line),
                    file=sys.stderr)
            else:
                print("%s: %s" % (prog, finding.message), file=sys.stderr)
    return 1 if any_fail else 0


def main(argv):
    """The dist-ai-style entry: dispatch on the mode flag. The mode selector is
    ONLY the FIRST argument -- so a FILE named '--detect'/'--fix' (every caller
    passes the mode first, then the file list) is never mistaken for the mode
    and silently dropped from the scan. Stripping every '--detect' let such a
    file bypass the gate."""
    rest = argv[1:]
    if rest and rest[0] == "--detect":
        try:
            return detect_main([argv[0]] + rest[1:])
        except SystemExit:
            raise
        except Exception:  # noqa: BLE001 -- a crash must exit DISTINCTLY (3)
            ## Exit 3, not 1, so a machine caller (the gate) tells a CRASH --
            ## where no rule actually ran -- from a clean "findings present"
            ## exit 1. Treating a crash as "no findings" would be a false green.
            traceback.print_exc()
            return 3
    if rest and rest[0] == "--fix":
        return fix_main([argv[0]] + rest[1:])
    return style_main(argv)
