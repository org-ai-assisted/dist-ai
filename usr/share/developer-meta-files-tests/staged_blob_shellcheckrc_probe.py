#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_engine_hardening.sh: a staged-blob
## shellcheck honors the project .shellcheckrc. A virtual (staged) context
## materializes to a temp file; shellcheck discovers '.shellcheckrc' by walking
## up from the CHECKED file's dir, so a temp-dir blob dropped the project rc and
## the gate failed a file that is clean IN PLACE. Canary: the rc disables SC2016
## and the content triggers ONLY SC2016, so a finding here means the rc was not
## applied to the blob. argv[1]=rcdir/f.sh; prints the SC2016 FAIL count (want 0).
import sys
from dist_ai import context, engine, model
abspath = sys.argv[1]
## disk_backed=False -> a VIRTUAL (staged) context: materialized() writes the
## bytes to a temp file; abspath only supplies the real source dir + rc location.
ctx = context.FileContext("proj/f.sh", "#!/bin/bash\necho \x27$x\x27\n",
                          abspath=abspath, disk_backed=False)
findings = engine.detect(ctx, include_external=True)
print(sum(1 for f in findings if f.rule == "shellcheck" and f.severity == model.FAIL))
