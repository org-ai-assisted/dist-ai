#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Map a GitHub compare-endpoint JSON body (on stdin) to one verdict token on
## stdout:
##   resolvable      status behind / identical (ancestor-or-equal of master)
##   not-resolvable  status ahead / diverged, OR the head SHA is not in the
##                   upstream repo at all ('message': 'Not Found')
##   error           anything else (rate limit, transient 5xx, bad JSON) --
##                   never fails the check, only warns, to avoid a flaky red

import json
import sys

try:
    data = json.load(sys.stdin)
    ## A body that parses but is not an object (a bare list or null, which an
    ## intercepting proxy or an error page can produce) has no .get, and the
    ## AttributeError would escape as a non-zero exit with no verdict printed.
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    status = data.get("status")
    message = data.get("message")
except Exception:
    print("error")
    sys.exit(0)

if status in ("behind", "identical"):
    print("resolvable")
elif status in ("ahead", "diverged"):
    print("not-resolvable")
elif message == "Not Found":
    print("not-resolvable")
else:
    print("error")
