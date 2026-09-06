#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Print the id of the newest successful Build/Boot Test workflow run.
## Reads the GitHub `actions/runs` JSON on stdin; prints one run id (or nothing).

import json,sys
d=json.load(sys.stdin)
for r in d['workflow_runs']:
    if r['name'] in ('Boot Test','Build') and r['conclusion']=='success':
        print(r['id']); break
