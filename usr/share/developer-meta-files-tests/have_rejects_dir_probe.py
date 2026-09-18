#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_engine_hardening.sh: have_on_path() must treat a
## same-named DIRECTORY on PATH as ABSENT, not present. os.access(dir, X_OK) is
## True for any traversable directory, so a bare check reported a 'shellcheck'
## DIRECTORY on PATH as the tool being present; detect() then tried to exec it,
## hit PermissionError (an OSError subclass), and the bare 'except OSError'
## swallowed it -- yielding no NOTE and no FAIL, a silent fail-open with zero
## visibility. argv[1]=test_dir; sets PATH to a dir whose only 'shellcheck' entry
## is a SUBDIRECTORY and prints have_on_path('shellcheck') (want 'False').
import sys, os
from dist_ai import model
d = os.path.join(sys.argv[1], "fakepath")
os.makedirs(os.path.join(d, "shellcheck"))          # a DIRECTORY named 'shellcheck'
os.environ["PATH"] = d                              # nothing else resolvable here
print(model.have_on_path("shellcheck"))
