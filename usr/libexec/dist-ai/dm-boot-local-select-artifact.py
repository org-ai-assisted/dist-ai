#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Print the id of the unexpired boot-image artifact for $IMAGE_TYPE.
## Reads the GitHub `artifacts` JSON on stdin; env IMAGE_TYPE selects the name.

import json
import os
import sys

want = 'boot-image-' + os.environ['IMAGE_TYPE']
## The stdin body is a network payload whose shape is not guaranteed (a GitHub
## error object, a bare list/null from a proxy, a truncated read); it must yield
## no id and exit 0, never a stack-trace crash under the caller's errexit. A
## partial artifact entry missing 'expired'/'name'/'id' is skipped, not fatal.
try:
    payload = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
if not isinstance(payload, dict):
    raise SystemExit(0)
live = [a for a in payload.get('artifacts', [])
        if isinstance(a, dict) and not a.get('expired')]
hit = [a for a in live if a.get('name') == want]
if hit and hit[0].get('id') is not None:
    print(hit[0]['id'])
else:
    sys.stderr.write('no unexpired %r artifact; available: %s\n'
                     % (want, ', '.join(sorted(a.get('name') or '' for a in live)) or '(none)'))
    print('')
