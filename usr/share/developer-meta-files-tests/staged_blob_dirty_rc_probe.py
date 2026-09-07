#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_engine_hardening.sh: staged-blob shellcheck
## reads .shellcheckrc from the BLOB'S TREE, not the dirty worktree. In
## --staged/--range mode the file is a committed/staged BLOB, so its
## '.shellcheckrc' must come from the blob's OWN git tree (source_rev), NEVER the
## working tree -- else a dirty/unstaged 'disable=...' would suppress a real
## finding in the object that SHIPS (the dirty-rc bypass). argv[1]=test_dir;
## prints the SC2016 FAIL count (want non-zero: the dirty rc is ignored).
import sys, os, subprocess, pathlib
from dist_ai import context, engine, model
D = os.path.join(sys.argv[1], "blobtree")
os.makedirs(D)
def git(*a): subprocess.run(["git", "-C", D] + list(a), check=True, capture_output=True)
git("init", "--quiet"); git("config", "user.email", "t@e.st"); git("config", "user.name", "t")
pathlib.Path(D + "/prog.sh").write_text("#!/bin/bash\necho \x27$x\x27\n")   # SC2016
git("add", "prog.sh"); git("commit", "--quiet", "-m", "init")
pathlib.Path(D + "/.shellcheckrc").write_text("disable=SC2016\n")           # DIRTY, unstaged, not in the tree
## source_rev="" -> the INDEX (a staged blob); the rc must come from the tree.
ctx = context.FileContext("prog.sh", pathlib.Path(D + "/prog.sh").read_text(),
                          abspath=D + "/prog.sh", source_rev="")
findings = engine.detect(ctx, include_external=True)
print(sum(1 for f in findings if f.rule == "shellcheck" and f.severity == model.FAIL))
