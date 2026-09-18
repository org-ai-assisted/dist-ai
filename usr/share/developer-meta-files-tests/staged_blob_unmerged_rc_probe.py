#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_engine_hardening.sh: an UNMERGED (conflicted)
## '.shellcheckrc' in the index must NOT silently govern the staged shellcheck run.
## 'git ls-files --stage' emits one record per conflict stage (1=base, 2=ours,
## 3=theirs) and NO stage-0 entry for a conflicted path; the walk-up rc lookup used
## to key by path and keep whichever git listed LAST (stage 3, "theirs"), so a
## conflict side carrying 'disable=all' suppressed real findings on the PR's own
## scripts. Canary: leave 'sub/.shellcheckrc' unmerged with theirs='disable=all'
## and a failing 'sub/prog.sh', then check the staged blob (source_rev=''). A fix
## that skips nonzero-stage entries finds NO staged rc, so SC2016 STILL fires.
## argv[1]=test_dir; prints the SC2016 FAIL count (want non-zero: theirs not used).
import sys, os, subprocess, pathlib
from dist_ai import context, engine, model
D = os.path.join(sys.argv[1], "unmerged")
os.makedirs(os.path.join(D, "sub"))
## '-c core.hooksPath=/dev/null': do not fire the operator's global hooks on these
## throwaway commits.
def git(*a): subprocess.run(["git", "-C", D, "-c", "core.hooksPath=/dev/null"] + list(a), check=True, capture_output=True)
git("init", "--quiet"); git("config", "user.email", "t@e.st"); git("config", "user.name", "t")
## The operator's global config may set merge.verifySignatures=true; the fixture's
## throwaway commits are unsigned, so the merge would abort before conflicting.
git("config", "merge.verifySignatures", "false"); git("config", "commit.gpgsign", "false")
base_branch = subprocess.run(
    ["git", "-C", D, "symbolic-ref", "--short", "HEAD"],
    capture_output=True, text=True).stdout.strip() or "master"
prog = "sub/prog.sh"
pathlib.Path(D + "/" + prog).write_text("#!/bin/bash\necho \x27$x\x27\n")   # SC2016
rc = pathlib.Path(D + "/sub/.shellcheckrc")
rc.write_text("# clean base\n")
git("add", "-A"); git("commit", "--quiet", "-m", "base")
git("checkout", "--quiet", "-b", "feature")
rc.write_text("disable=all\n")                                              # theirs
git("commit", "--quiet", "-am", "feature rc")
git("checkout", "--quiet", base_branch)
rc.write_text("# clean ours\n")                                            # ours
git("commit", "--quiet", "-am", "ours rc")
## Content differs on all three sides -> an UNRESOLVED conflict on sub/.shellcheckrc
## (git leaves it unmerged in the index; merge exits non-zero, so not check=True).
subprocess.run(["git", "-C", D, "-c", "core.hooksPath=/dev/null", "merge", "--quiet", "feature"],
               capture_output=True)
ctx = context.FileContext(prog, pathlib.Path(D + "/" + prog).read_text(),
                          abspath=D + "/" + prog, source_rev="")
findings = engine.detect(ctx, include_external=True)
print(sum(1 for f in findings if f.rule == "shellcheck" and f.severity == model.FAIL))
