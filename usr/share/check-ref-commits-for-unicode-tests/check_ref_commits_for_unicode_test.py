#!/usr/bin/env python3
"""
Comprehensive test + fuzz for check-ref-commits-for-unicode: the helper-scripts
git-ref guard that scans every commit a ref introduces (git log HEAD..<ref>) for
suspicious Unicode and fails if any is found. For each new commit it runs

    git show --no-ext-diff --unified=0 --no-textconv \
        --format='Author: %an\\nAuthor email: %ae\\nCommitter: %cn\\n\
                  Committer email: %ce\\n%B' <commit>

and pipes the result through unicode-show. So it scans, per commit, not just the
DIFF but the commit MESSAGE and the AUTHOR / COMMITTER name and email -- the
places a Trojan-Source style attack can hide that a plain content scan misses.

Contract (observed):
  - exit 0: every new commit is clean (unicode-show found nothing, exit 0);
    logs "No unicode detected." on stderr.
  - exit 1: EITHER suspicious Unicode was found in some commit (a per-commit
    "Potentially malicious unicode detected in commit '<sha>'" warning, with
    unicode-show's report on stdout), OR a usage / setup error (no ref given,
    ref does not exist, cwd not a git work tree, or no new commits in the ref).
    Exit 1 is thus overloaded; these tests distinguish detection from error by
    the message, not the code.

The design choices matter and are pinned here: --unified=0 avoids false positives
from unmodified empty context lines (which unicode-show would flag as trailing
whitespace); --no-ext-diff / --no-textconv stop an external driver or textconv
filter from hiding or altering the bytes; and the format line pulls the identity
fields into the scan.

Checks, end to end against the real tool on throwaway repos (no root, no network,
hermetic git -- global/system config neutralised):

  [D] detection by LOCATION: a hostile codepoint hidden in the file content, the
      commit message, the author name, the author email, the committer name, or
      the committer email each makes the tool exit 1 and name the offending
      commit. Plus a few different suspicious characters in content.
  [S] self-safety: even while reporting a commit stuffed with hostile Unicode,
      the tool's combined stdout+stderr stays pure ASCII (unicode-show renders
      the finding as [U+XXXX]; nothing raw reaches the terminal).
  [B] benign: a ref whose new commits are clean (including blank lines and a
      clean merge commit) exits 0, so [D] is non-vacuous.
  [M] multi-commit: given clean + dirty + clean new commits, the tool flags the
      dirty one (by sha) and logs the clean ones as clean.
  [E] errors, each exit 1 with its own message: no ref argument, a nonexistent
      ref, a ref with no new commits (HEAD..ref empty), and a cwd that is not a
      git work tree.
  [F] fuzz: random commits whose payload is either clean ASCII or carries a
      suspicious character in a random location, checked against an independent
      oracle -- exit 1 iff something suspicious was injected, else exit 0, and
      the output always pure ASCII.

The tool is resolved from CHECK_REF_COMMITS_REPO (a helper-scripts checkout,
whose usr/bin goes on PATH so its unicode-show is used and HELPER_SCRIPTS_PATH
points at it so it sources the checkout's log_run_die.sh) else the installed
/usr/bin/check-ref-commits-for-unicode.

This file is ASCII-only: suspicious characters are Python escapes, encoded to
real UTF-8 at runtime.

Usage: check_ref_commits_for_unicode_test.py [--iterations N] [--seed N] [--fuzz-only]
"""

import argparse
import os
import subprocess
import sys
import tempfile

REPO = os.environ.get("CHECK_REF_COMMITS_REPO")
INSTALLED = "/usr/bin/check-ref-commits-for-unicode"

TIMEOUT_SECONDS = 60

## A representative hostile codepoint (right-to-left override) and a few others.
RLO = "\u202e"
SUSPICIOUS_CHARS = {
    "rlo": "\u202e",
    "zwsp": "\u200b",
    "homoglyph": "\u0430",
    "emoji": "\U0001f600",
}

def tool_path():
    return os.path.join(REPO, "usr/bin/check-ref-commits-for-unicode") if REPO \
        else INSTALLED


def base_env():
    """Hermetic git: never read the operator's global/system git config."""
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    if REPO:
        env["HELPER_SCRIPTS_PATH"] = REPO
        env["PATH"] = os.path.join(REPO, "usr/bin") + os.pathsep + env.get("PATH", "")
        env["PYTHONPATH"] = os.path.join(REPO, "usr/lib/python3/dist-packages")
    return env


def git(repo, args, extra_env=None, check=True):
    env = base_env()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["git", "-C", repo] + args, env=env, check=check,
        capture_output=True, timeout=TIMEOUT_SECONDS,
    )


def run_tool(cwd, args):
    return subprocess.run(
        [tool_path()] + list(args), cwd=cwd, env=base_env(), check=False,
        capture_output=True, timeout=TIMEOUT_SECONDS,
    )


def output_violations(out):
    r"""The tool's output must be pure printable ASCII plus newline/tab: no
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


def new_repo(parent, name):
    """A fresh repo with a clean base commit on 'main'. HEAD == main == base."""
    repo = os.path.join(parent, name)
    os.mkdir(repo)
    git(repo, ["init", "-q", "-b", "main"])
    git(repo, ["config", "user.name", "Test User"])
    git(repo, ["config", "user.email", "test@example.com"])
    with open(os.path.join(repo, "f.txt"), "w", encoding="utf-8") as handle:
        handle.write("base line\n")
    git(repo, ["add", "f.txt"])
    git(repo, ["commit", "-q", "-m", "base commit"])
    return repo


def commit(repo, content_line, message="clean message", author=None,
           committer_env=None):
    """Append a line and commit it, optionally with a custom author string or
    committer identity. Returns the new commit's full sha."""
    with open(os.path.join(repo, "f.txt"), "a", encoding="utf-8") as handle:
        handle.write(content_line)
    git(repo, ["add", "f.txt"])
    args = ["commit", "-q", "-m", message]
    if author is not None:
        args.append("--author=" + author)
    git(repo, args, extra_env=committer_env)
    return git(repo, ["rev-parse", "HEAD"]).stdout.decode().strip()


def build_case(parent, name, where, ch):
    """Build a repo with one hostile commit on branch 'feature'; return
    (repo, feature_sha). 'where' selects where the char 'ch' is hidden."""
    repo = new_repo(parent, name)
    git(repo, ["checkout", "-q", "-b", "feature"])
    content = "added line\n"
    message = "clean message"
    author = None
    committer_env = None
    if where == "content":
        content = "added %sline\n" % ch
    elif where == "message":
        message = "message with %s here" % ch
    elif where == "author_name":
        author = "Ev%sil <evil@example.com>" % ch
    elif where == "author_email":
        author = "Name <ev%sl@example.com>" % ch
    elif where == "committer_name":
        committer_env = {"GIT_COMMITTER_NAME": "Comm%sitter" % ch}
    elif where == "committer_email":
        committer_env = {"GIT_COMMITTER_EMAIL": "comm%sr@example.com" % ch}
    sha = commit(repo, content, message=message, author=author,
                 committer_env=committer_env)
    git(repo, ["checkout", "-q", "main"])
    return repo, sha


def main():  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    parser = argparse.ArgumentParser(
        description="check-ref-commits-for-unicode test + fuzz")
    ## Each iteration builds a real commit and runs the tool, so this is heavier
    ## per iteration than the byte-level sibling suites; the default is lower.
    parser.add_argument("--iterations", type=int, default=80,
                        help="fuzz iterations (each builds a real commit)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--fuzz-only", action="store_true")
    args = parser.parse_args()

    print("check-ref-commits-for-unicode test + fuzz")
    print("tool: " + (("checkout " + REPO) if REPO else "installed /usr/bin"))
    if not REPO and not os.path.exists(INSTALLED):
        print("ERROR: %s not found "
              "(set CHECK_REF_COMMITS_REPO to a helper-scripts checkout)"
              % INSTALLED)
        return 2
    ## git is required to build the fixtures.
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True,
                       timeout=TIMEOUT_SECONDS)
    except (OSError, subprocess.CalledProcessError):
        print("ERROR: git not available")
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

    if not args.fuzz_only:
        ## [D] detection by location + [S] self-safety.
        print("[D] detection: hostile Unicode in content / message / "
              "author / committer is caught")
        print("[S] self-safety: the tool's own output stays pure ASCII")
        with tempfile.TemporaryDirectory() as tmp:
            locations = ["content", "message", "author_name", "author_email",
                         "committer_name", "committer_email"]
            for i, where in enumerate(locations):
                repo, sha = build_case(tmp, "loc_%d" % i, where, RLO)
                proc = run_tool(repo, ["feature"])
                check("D:%s:exit" % where, proc.returncode == 1,
                      "exit %d stderr=%r" % (proc.returncode, proc.stderr[:160]))
                check("D:%s:names-commit" % where, sha.encode() in proc.stderr,
                      "sha %s not flagged: %r" % (sha[:12], proc.stderr[:200]))
                combined = proc.stdout + proc.stderr
                check("S:%s" % where, not output_violations(combined),
                      "leaked: " + repr(combined[:96]))

            ## A few different suspicious characters, all in content.
            for name, ch in SUSPICIOUS_CHARS.items():
                repo, sha = build_case(tmp, "char_%s" % name, "content", ch)
                proc = run_tool(repo, ["feature"])
                check("D:char:%s:exit" % name, proc.returncode == 1,
                      "exit %d" % proc.returncode)
                check("D:char:%s:safe" % name,
                      not output_violations(proc.stdout + proc.stderr),
                      "leaked for %s" % name)

        ## [B] benign: clean new commits (incl. blank lines) exit 0.
        print("[B] benign: a clean ref (incl. blank lines) exits 0")
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp, "benign")
            git(repo, ["checkout", "-q", "-b", "feature"])
            commit(repo, "one clean line\n", message="a perfectly clean message")
            commit(repo, "\nblank above and below\n\n",
                   message="another clean message")
            git(repo, ["checkout", "-q", "main"])
            proc = run_tool(repo, ["feature"])
            check("B:clean:exit0",
                  proc.returncode == 0 and b"No unicode detected" in proc.stderr,
                  "exit %d stderr=%r" % (proc.returncode, proc.stderr[:160]))
            check("B:clean:safe",
                  not output_violations(proc.stdout + proc.stderr),
                  repr((proc.stdout + proc.stderr)[:96]))

        ## [B] benign: a clean MERGE commit exits 0 (exercises the combined-diff
        ## path the --unified=0 comment calls out).
        print("[B] benign: a clean merge commit exits 0")
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp, "merge")
            git(repo, ["checkout", "-q", "-b", "side"])
            with open(os.path.join(repo, "g.txt"), "w", encoding="utf-8") as h:
                h.write("side clean\n")
            git(repo, ["add", "g.txt"])
            git(repo, ["commit", "-q", "-m", "add g clean"])
            git(repo, ["checkout", "-q", "-b", "target", "main"])
            git(repo, ["merge", "-q", "--no-ff", "-m", "merge clean", "side"])
            git(repo, ["checkout", "-q", "main"])
            proc = run_tool(repo, ["target"])
            check("B:merge:exit0", proc.returncode == 0,
                  "exit %d stderr=%r" % (proc.returncode, proc.stderr[:160]))

        ## [M] multi-commit: only the dirty commit is flagged; clean ones logged.
        print("[M] multi-commit: dirty commit flagged, clean ones logged clean")
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp, "multi")
            git(repo, ["checkout", "-q", "-b", "feature"])
            clean1 = commit(repo, "first clean\n", message="first")
            dirty = commit(repo, "dirty %sline\n" % RLO, message="second")
            clean2 = commit(repo, "third clean\n", message="third")
            git(repo, ["checkout", "-q", "main"])
            proc = run_tool(repo, ["feature"])
            check("M:exit1", proc.returncode == 1, "exit %d" % proc.returncode)
            check("M:dirty-flagged", dirty.encode() in proc.stderr,
                  "dirty sha not flagged: %r" % proc.stderr[:240])
            check("M:clean-logged",
                  clean1.encode() in proc.stderr and clean2.encode() in proc.stderr,
                  "clean shas not logged clean: %r" % proc.stderr[:240])

        ## [E] error / usage cases -- each exit 1, distinguished by message.
        print("[E] errors: each fails loud (exit 1) with its own message")
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp, "errs")
            no_arg = run_tool(repo, [])
            check("E:no-arg",
                  no_arg.returncode == 1 and b"No target ref specified" in no_arg.stderr,
                  "exit %d stderr=%r" % (no_arg.returncode, no_arg.stderr[:160]))
            bad_ref = run_tool(repo, ["no-such-ref"])
            check("E:bad-ref",
                  bad_ref.returncode == 1 and b"Target ref does not exist" in bad_ref.stderr,
                  "exit %d stderr=%r" % (bad_ref.returncode, bad_ref.stderr[:160]))
            ## HEAD..main is empty (main IS HEAD) -> no new commits.
            empty = run_tool(repo, ["main"])
            check("E:no-new-commits",
                  empty.returncode == 1 and b"No new commits" in empty.stderr,
                  "exit %d stderr=%r" % (empty.returncode, empty.stderr[:160]))
            ## Not inside a git work tree.
            nogit = os.path.join(tmp, "nogit")
            os.mkdir(nogit)
            outside = run_tool(nogit, ["main"])
            check("E:not-a-work-tree",
                  outside.returncode == 1
                  and b"not inside a Git working tree" in outside.stderr,
                  "exit %d stderr=%r" % (outside.returncode, outside.stderr[:160]))

    ## [F] fuzz: random commits vs an independent oracle. Each iteration puts a
    ## clean-or-suspicious payload in a random location; the tool must exit 1 iff
    ## something suspicious was injected, and its output must stay ASCII.
    import random
    rng = random.Random(args.seed)
    print("[F] fuzz: %d iterations (each builds a real commit, seed %d)"
          % (args.iterations, args.seed))
    locations = ["content", "message", "author_name", "author_email",
                 "committer_name", "committer_email"]
    sus_values = list(SUSPICIOUS_CHARS.values())
    with tempfile.TemporaryDirectory() as tmp:
        repo = new_repo(tmp, "fuzz")
        for i in range(args.iterations):
            suspicious = rng.random() < 0.5
            ch = rng.choice(sus_values) if suspicious else ""
            where = rng.choice(locations)
            ## Reset a throwaway branch to base each time so HEAD..fuzzbr is
            ## exactly this one commit.
            git(repo, ["checkout", "-q", "-B", "fuzzbr", "main"])
            content = "fuzz clean %d\n" % i
            message = "fuzz message %d" % i
            author = None
            committer_env = None
            if suspicious:
                if where == "content":
                    content = "fuzz %s%d\n" % (ch, i)
                elif where == "message":
                    message = "fuzz %smsg %d" % (ch, i)
                elif where == "author_name":
                    author = "Au%sthor <a@example.com>"  % ch
                elif where == "author_email":
                    author = "Author <a%sb@example.com>" % ch
                elif where == "committer_name":
                    committer_env = {"GIT_COMMITTER_NAME": "Co%smmitter" % ch}
                elif where == "committer_email":
                    committer_env = {"GIT_COMMITTER_EMAIL": "c%sm@example.com" % ch}
            commit(repo, content, message=message, author=author,
                   committer_env=committer_env)
            git(repo, ["checkout", "-q", "main"])
            proc = run_tool(repo, ["fuzzbr"])
            want = 1 if suspicious else 0
            ok = proc.returncode == want \
                and not output_violations(proc.stdout + proc.stderr)
            check("F:#%d" % i, ok,
                  "suspicious=%s where=%s want-exit=%d got=%d out=%r"
                  % (suspicious, where, want, proc.returncode,
                     (proc.stdout + proc.stderr)[:80]))

    print()
    print("%d passed, %d failed" % (passed, failed))
    if fail_samples:
        print("failures (sample):")
        for sample in fail_samples:
            print("  - " + sample)
    if failed:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS (check-ref-commits-for-unicode catches hidden Unicode in "
          "a ref's commits -- diff, message, and identity -- and stays "
          "terminal-safe)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
