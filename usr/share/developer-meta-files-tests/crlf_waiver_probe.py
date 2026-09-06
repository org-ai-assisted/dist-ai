#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for test_pre_push_engine_hardening.sh: a '## style-ok:'
## waiver on a CRLF-terminated line is honored. Canary: the old '(?:[ \t]|$)'
## boundary matched '$' before '\n' (AFTER the '\r'), so a CRLF waiver with no
## space after the tag was dropped and the rule fired fail-closed. Drives the
## REAL dist_ai package (PYTHONPATH set by the harness). Prints True/False.
from dist_ai import context
src = "#!/bin/bash\r\n## style-ok: allow-non-ascii\r\nx = 1\r\n"
print(context.FileContext("f.sh", src).has_waiver("allow-non-ascii"))
