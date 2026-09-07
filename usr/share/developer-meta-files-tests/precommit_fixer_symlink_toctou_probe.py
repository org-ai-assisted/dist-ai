#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_gate.sh: the pre-commit fixer refuses a
## symlink swapped in after the scan (a TOCTOU that let a fixer rewrite an
## arbitrary victim outside the repo). Drive precommit._run_fixer directly with a
## symlink where a regular file was scanned; the O_NOFOLLOW copy must refuse it
## and leave the victim untouched. dist_ai resolved via PYTHONPATH set by the
## caller. argv[1]=base dir, argv[2]=victim; prints the victim's content.
import pathlib
import sys
from dist_ai import precommit
base, victim = sys.argv[1], sys.argv[2]
list(precommit._run_fixer("end-of-file-fixer", ["target.sh"], base))
## repr so a trailing-newline corruption (all end-of-file-fixer can add) is
## VISIBLE: the caller reads this via $(...), which strips a trailing newline,
## so printing the raw content would hide exactly the byte this probes for.
print(repr(pathlib.Path(victim).read_text()))
