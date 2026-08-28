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
import os
import sys
import traceback

from dist_ai import bash_ast
from dist_ai import engine
from dist_ai import gate
from dist_ai import gitdiff
from dist_ai import model
from dist_ai import precommit

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
    if contexts is None:
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
    if contexts is None:
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


def _print_finding(prog, finding):
    """Render one Finding through the gate's own voice. FAIL carries a
    'path:line' locator; a NOTE is advisory (never fails the gate)."""
    if finding.severity == model.FAIL:
        if finding.path is not None and finding.line is not None:
            print("%s: FAIL %s: '%s:%s'" % (
                prog, finding.message, finding.path, finding.line),
                file=sys.stderr)
        elif finding.path is not None:
            print("%s: FAIL %s: '%s'" % (prog, finding.message, finding.path),
                  file=sys.stderr)
        else:
            print("%s: FAIL %s" % (prog, finding.message), file=sys.stderr)
    else:
        print("%s: %s" % (prog, finding.message), file=sys.stderr)


def _detect_contexts(contexts, prog):
    """Run the per-file rules (AST + text + external) over CONTEXTS, printing
    each finding. Returns (fail_count, error_code): error_code is set only when
    shfmt is absent (exit 2)."""
    fail_count = 0
    for ctx in contexts:
        try:
            findings = engine.detect(ctx, include_text=True,
                                     include_external=True)
        except bash_ast.ShfmtMissing as exc:
            print("%s: shfmt is required but unavailable: %s" % (prog, exc),
                  file=sys.stderr)
            return fail_count, 2
        for finding in findings:
            if finding.severity == model.FAIL:
                fail_count += 1
            _print_finding(prog, finding)
    return fail_count, None


def _fix_contexts(contexts, prog, check=False):
    """Apply the mechanical fixes over CONTEXTS in place, printing a summary per
    changed file. With CHECK, report the would-fix counts WITHOUT writing -- for
    --staged index blobs, whose content is the index, not a writable file on disk
    (writing a blob-derived fix to the working tree would clobber it). Returns an
    error_code only when shfmt is absent (exit 2)."""
    for ctx in contexts:
        try:
            changes = engine.apply_fixes(ctx, check=check)
        except bash_ast.ShfmtMissing as exc:
            print("%s: shfmt is required but unavailable: %s" % (prog, exc),
                  file=sys.stderr)
            return 2
        if changes:
            _fix_summary(prog, ctx.path, changes, check=check)
    return None


def _enumerate(args, prog):
    """Resolve the mode to (pairs, names, base_ref, base_cwd, staged_mode) or an
    (None, error_code). names is the FULL changed-path list (for the batch
    checks -- symlinks and binaries the per-file engine skips still count);
    base_cwd is the repo root for a git mode, else None."""
    ## Git modes judge a range / the index and drive the repo-level batch;
    ## direct file mode is the per-file linter only.
    if args.staged:
        pathspecs = args.files if args.paths else None
        try:
            pairs = gitdiff.staged_pairs(all_tracked=args.all,
                                         pathspecs=pathspecs)
        except gitdiff.StagedDiscoveryError as exc:
            print("%s: could not list staged files: %s" % (prog, exc),
                  file=sys.stderr)
            return None, 2
        return (pairs, [rel for _, rel in pairs], "HEAD",
                gitdiff._repo_root(), True), None
    if args.range is not None:
        try:
            gitdiff.resolve_base(args.range)
        except gitdiff.BaseRefError as exc:
            print("%s: cannot resolve base ref '%s'. Pass a base, e.g. "
                  "'origin/master'." % (prog, exc), file=sys.stderr)
            return None, 2
        ## Measure the range from the MERGE BASE, not base_ref's tip, so every
        ## range check (files, added-large-files, changelog, message) shares the
        ## same fork point range_pairs' triple-dot already uses.
        base = gitdiff.merge_base(args.range)
        try:
            pairs = gitdiff.range_pairs(base)
        except gitdiff.StagedDiscoveryError as exc:
            print("%s: could not list changed files: %s" % (prog, exc),
                  file=sys.stderr)
            return None, 2
        return (pairs, [rel for _, rel in pairs], base,
                gitdiff._repo_root(), False), None
    ## Direct file mode.
    try:
        pairs = gitdiff.given_pairs(args.files)
    except FileNotFoundError as exc:
        print("%s: no such path: %s" % (prog, exc), file=sys.stderr)
        return None, 2
    return (pairs, [rel for _, rel in pairs], None, None, False), None


def _batch_findings(names, base_ref, staged_mode, base_cwd, message_file,
                    tool_dir, skew_ref):
    """The repo-level checks that judge the whole changed set / range: the
    pre-commit-hooks batch, the changelog convention, the commit-message floor,
    and the advisory comment audit. Yields Findings. SKEW_REF drives the
    working-tree-skew NOTE (the content is read off disk, so a mode that records
    something else must say so); None suppresses it."""
    yield from precommit.run(names, base_ref, staged_mode, base_cwd)
    if staged_mode:
        yield from gate.check_changelog_staged(names, message_file, base_cwd)
    else:
        yield from gate.check_changelog_range(base_ref, base_cwd)
    yield from gate.check_message(base_ref, staged_mode, message_file, base_cwd)
    yield from gate.comments_audit(names, base_cwd, tool_dir)
    yield from gate.warn_worktree_skew(names, skew_ref, base_cwd)
    yield from gate.check_untracked(base_cwd)


def style_main(argv, prog="dist-ai-style"):
    """The unified front. Default: fix-then-check -- apply the mechanical fixes,
    print what changed, then report the residual. --check: read-only.

    Direct file mode runs the per-file rules only. A git mode (--staged /
    --range) additionally drives the repo-level batch (pre-commit-hooks,
    changelog, commit message, comment audit) -- the full push/commit gate."""
    parser = argparse.ArgumentParser(prog=prog, add_help=True)
    parser.add_argument("--check", action="store_true",
                        help="read-only: report violations, do not fix")
    parser.add_argument("--staged", action="store_true",
                        help="gate the repo's staged index (or --all: the "
                             "working tree vs HEAD)")
    parser.add_argument("--all", action="store_true",
                        help="with --staged: all tracked modifications vs HEAD")
    parser.add_argument("--paths", action="store_true",
                        help="with --staged: treat the positionals as "
                             "pathspecs restricting the staged set")
    parser.add_argument("--range", metavar="BASE",
                        help="gate the files changed in BASE...HEAD")
    parser.add_argument("--message-file",
                        help="the pending commit message, for the R-001 / "
                             "changelog-trailer checks")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv[1:])

    if args.staged and args.range is not None:
        print("%s: --staged and --range are mutually exclusive" % prog,
              file=sys.stderr)
        return 2
    if args.all and not args.staged:
        print("%s: --all only applies with --staged" % prog, file=sys.stderr)
        return 2
    if args.paths and not args.staged:
        print("%s: --paths only applies with --staged" % prog, file=sys.stderr)
        return 2
    if not args.files and not args.staged and args.range is None:
        print("usage: %s [--check] [--staged [--all] [--paths]] "
              "[--range BASE] [--message-file MSG] <file|dir>..." % prog,
              file=sys.stderr)
        return 2

    enumerated, code = _enumerate(args, prog)
    if enumerated is None:
        return code
    pairs, names, base_ref, base_cwd, staged_mode = enumerated
    git_mode = args.staged or args.range is not None
    ## Bare / --paths --staged gate the INDEX (git diff --cached), so the content
    ## judged must be the STAGED BLOB, not the working tree that may have diverged
    ## since staging. --staged --all records the working tree (like 'commit -a'),
    ## and --range / direct mode read disk too -- those keep the on-disk read.
    from_index = args.staged and not args.all

    def _mode_contexts():
        if from_index:
            return gitdiff.staged_blob_contexts(pairs)
        return gitdiff.contexts(pairs)

    ## A --paths pathspec that matched nothing checks nothing -- SAY so, never a
    ## silent clean sweep (a narrow-to-nothing would otherwise read as a pass).
    if args.paths and not names:
        print("%s: the pathspec(s) matched no added/modified file; nothing "
              "checked" % prog, file=sys.stderr)

    ## Fix first (unless read-only), then re-read so the detect pass judges the
    ## FIXED file -- the residual is exactly what a human must fix. Index blobs
    ## have no writable file target, so there the fixer only REPORTS (check).
    if not args.check:
        code = _fix_contexts(_mode_contexts(), prog, check=from_index)
        if code is not None:
            return code

    fail_count, code = _detect_contexts(_mode_contexts(), prog)
    if code is not None:
        return code

    if git_mode:
        tool_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        ## Index modes judged the STAGED BLOB, so note (informational) when the
        ## working tree has since diverged; a range read disk against HEAD's
        ## commits, so warn vs HEAD; --all read the working tree itself (like
        ## 'commit -a'), so there is nothing to skew against.
        if from_index:
            skew_ref = ""
        elif args.range is not None:
            skew_ref = "HEAD"
        else:
            skew_ref = None
        for finding in _batch_findings(names, base_ref, staged_mode, base_cwd,
                                       args.message_file, tool_dir, skew_ref):
            if finding.severity == model.FAIL:
                fail_count += 1
            _print_finding(prog, finding)

    ## Terminal verdict: a clear pass/fail line a human -- and a caller's own
    ## liveness check -- can key on, so an absent result is never mistaken for a
    ## clean one.
    if fail_count:
        print("%s: %d check(s) failed" % (prog, fail_count), file=sys.stderr)
    else:
        print("%s: all static checks passed" % prog, file=sys.stderr)
    return 1 if fail_count else 0


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
