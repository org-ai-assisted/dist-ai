#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mock 'id' for apparmor_info_clean_boot_test.sh. Reports uid 0 for EXACTLY 'id -u' so
## the subject's root guard passes without the test needing real root (the dist-ai suite
## runs unprivileged; on the installed system apparmor-info runs as root, so the guard
## passes there too -- bypassing it reaches the real code under test faithfully).
## apparmor-info only ever calls 'id -u'; matching only the exact single-arg form (not
## 'id -u <user>') keeps any other invocation delegated to the real binary, so the stub
## never silently changes unrelated behaviour.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ "$#" -eq 1 ] && [ "${1}" = "-u" ]; then
   printf '%s\n' 0
   exit 0
fi
## Delegate any non '-u' invocation to the real binary by absolute path (the stub
## is named 'id' on PATH, so a bare 'id' would recurse). apparmor-info only calls
## 'id -u', so this branch is a safety net, not a hot path.
/usr/bin/id "$@"
