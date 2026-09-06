#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_engine_hardening.sh: the fixer's write
## refuses a symlink swapped in AFTER the scan (TOCTOU). from_disk refuses a
## symlink when the context is BUILT; apply_fixes must refuse to write through
## one that replaces the path afterwards. Canary: a plain open() followed the
## symlink and overwrote an arbitrary victim file. argv[1]=target, argv[2]=victim;
## prints the victim's (must be unchanged) content.
import os, sys
from dist_ai import context, engine
target, victim = sys.argv[1], sys.argv[2]
ctx = context.FileContext.from_disk(target)     ## built against the regular file
os.remove(target); os.symlink(victim, target)   ## swap in a symlink to the victim
engine.apply_fixes(ctx, check=False)            ## must NOT write through it
with open(victim) as handle:
    print(handle.read().strip())
