#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Print the id of the unexpired boot-image artifact for $IMAGE_TYPE.
## Reads the GitHub `artifacts` JSON on stdin; env IMAGE_TYPE selects the name.

import json,os,sys
want='boot-image-'+os.environ['IMAGE_TYPE']
d=json.load(sys.stdin)
live=[a for a in d.get('artifacts',[]) if not a['expired']]
hit=[a for a in live if a['name']==want]
if hit:
    print(hit[0]['id'])
else:
    sys.stderr.write('no unexpired %r artifact; available: %s\n'
                     % (want, ', '.join(sorted(a['name'] for a in live)) or '(none)'))
    print('')
