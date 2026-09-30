#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced fragment; the caller owns strict mode.
## style-ok: no-has -- probing bwrap capability, not depending on it as a tool

## Sourced helper. `command -v bwrap` only proves the binary exists; on
## Debian/Kicksecure with unprivileged user namespaces disabled (the historical
## default), or in a container without CAP_SYS_ADMIN, bwrap exists but FAILS at
## runtime. So actually ATTEMPT the sandbox shape the use_leaprun bwrap tests use
## and check the real exit status -- letting an unavailable sandbox SKIP (77)
## rather than collapse into a false test FAILURE.
bwrap_can_sandbox() {
   command -v bwrap >/dev/null 2>&1 || return 1
   bwrap --bind / / --dev /dev --proc /proc --tmpfs /run/privleapd true \
      >/dev/null 2>&1
}
