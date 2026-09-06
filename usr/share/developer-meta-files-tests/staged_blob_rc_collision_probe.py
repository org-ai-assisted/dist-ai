#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_engine_hardening.sh: staged-blob shellcheck
## rc lookup resists a git object-spec collision. A blob path PREFIX is
## attacker-controlled: a PR that names a directory '0:pwn' made the walk-up rc
## lookup 'git show :0:pwn/.shellcheckrc', which git MISPARSES as
## ':<stage 0>:pwn/.shellcheckrc' -- reading a DIFFERENT, attacker-planted rc to
## SUPPRESS shellcheck on the PR's own scripts. argv[1]=test_dir; prints the
## SC2016 FAIL count (want non-zero: the collision does not suppress the finding).
import sys, os, subprocess
from dist_ai import context, engine, model
D = os.path.join(sys.argv[1], "collide")
os.makedirs(os.path.join(D, "0:pwn"))
os.makedirs(os.path.join(D, "pwn"))
def git(*a): subprocess.run(["git", "-C", D] + list(a), check=True, capture_output=True)
git("init", "--quiet"); git("config", "user.email", "t@e.st"); git("config", "user.name", "t")
open(D + "/0:pwn/prog.sh", "w").write("#!/bin/bash\necho \x27$x\x27\n")   # SC2016
open(D + "/pwn/.shellcheckrc", "w").write("disable=all\n")               # the misparse target
git("add", "-A"); git("commit", "--quiet", "-m", "init")
ctx = context.FileContext("0:pwn/prog.sh", open(D + "/0:pwn/prog.sh").read(),
                          abspath=D + "/0:pwn/prog.sh", source_rev="")
findings = engine.detect(ctx, include_external=True)
print(sum(1 for f in findings if f.rule == "shellcheck" and f.severity == model.FAIL))
