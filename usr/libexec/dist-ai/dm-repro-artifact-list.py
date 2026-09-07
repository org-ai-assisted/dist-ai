#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Read a GitHub run-artifacts API response on stdin and print one
## "id<TAB>name" line per unexpired artifact.

import json
import sys


def is_safe_name(name):
    ## The name flows unquoted into the caller as a filename component
    ## ("${work_dir}/${name}.zip", unzip -d): reject anything that is not a
    ## plain basename. A path separator, a ".." segment, or any control
    ## character (tab/newline included, which would also break this TSV line)
    ## is untrusted GitHub-API input and must not pass through.
    if not name:
        return False
    if "/" in name or "\\" in name:
        return False
    if name in (".", ".."):
        return False
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        return False
    return True


try:
    payload = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
for item in payload.get("artifacts") or []:
    if item.get("expired"):
        continue
    name = item["name"]
    if not is_safe_name(name):
        print(
            "dm-repro-artifact-list: skipping artifact with unsafe name: %r" % (name,),
            file=sys.stderr,
        )
        continue
    print("%s\t%s" % (item["id"], name))
