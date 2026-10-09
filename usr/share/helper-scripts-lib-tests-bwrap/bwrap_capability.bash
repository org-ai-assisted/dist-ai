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
## and check the real exit status.
bwrap_can_sandbox() {
   command -v bwrap >/dev/null 2>&1 || return 1
   bwrap --bind / / --dev /dev --proc /proc --tmpfs /run/privleapd true \
      >/dev/null 2>&1
}

## An unusable sandbox is env-unmet (78), and only a run dist-ai-tests-all
## authorized (DIST_AI_SKIP_AUTHORIZED=1, set for an --allow-skip'd suite) may
## skip on it. Anywhere else it is FATAL: these cases then tested nothing.
bwrap_require() {
   bwrap_can_sandbox && return 0
   if [ "${DIST_AI_SKIP_AUTHORIZED:-}" = '1' ]; then
      printf '%s\n' "SKIP: unprivileged bwrap sandbox unavailable (authorized)" >&2
      exit 78  ## style-ok: allow-skip: unprivileged bwrap sandbox unavailable, orchestrator-authorized
   fi
   printf '%s\n' "FATAL: unprivileged bwrap sandbox unavailable and the skip is not authorized (DIST_AI_SKIP_AUTHORIZED=1)" >&2
   exit 1
}
