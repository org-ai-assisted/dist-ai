#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_gate.sh: the pre-commit content fixers must
## name the TRUE offender in detect mode (NOT files[0]) and APPLY fixes in place
## in a writing mode. Drives precommit._run_fixer directly with two files where
## only the SECOND needs fixing. dist_ai resolved via PYTHONPATH set by the
## caller. argv[1]=base dir, argv[2]=mode ('detect' or 'apply').
import pathlib
import sys

from dist_ai import precommit

base, mode = sys.argv[1], sys.argv[2]
clean = pathlib.Path(base, "a_clean.txt")
needs = pathlib.Path(base, "b_needs.txt")
clean.write_bytes(b"clean\n")     ## already EOF-correct: the fixer leaves it
needs.write_bytes(b"needs\n\n")   ## double trailing newline: the fixer trims it
files = ["a_clean.txt", "b_needs.txt"]

if mode == "detect":
    ## Detect only (apply defaults False): each finding's path must be the real
    ## offender. The old files[0] code names 'a_clean.txt' (first in the list).
    for finding in precommit._run_fixer("end-of-file-fixer", files, base):
        print(finding.path)
elif mode == "apply":
    list(precommit._run_fixer("end-of-file-fixer", files, base, apply=True))
    ## repr so a trailing-newline delta (all end-of-file-fixer changes) is VISIBLE
    ## even though $(...) would strip a real trailing newline.
    print("b_needs_fixed=%s" % (needs.read_bytes() == b"needs\n"))
    print("b_needs_bytes=%r" % needs.read_bytes())
    print("a_clean_intact=%s" % (clean.read_bytes() == b"clean\n"))
    print("a_clean_bytes=%r" % clean.read_bytes())
else:
    print("unknown mode: %s" % mode, file=sys.stderr)
    sys.exit(2)
