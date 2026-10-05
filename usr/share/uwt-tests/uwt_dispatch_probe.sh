#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: a sourced-driver probe that
## must not impose its own strict mode on the pure seam it drives. Sources the
## sourceable dnf-3.anondist (SUBJECT, which resolves check_runtime.bsh via
## HELPER_SCRIPTS_PATH) and runs its tor-wait dispatch. The direct-helper seam
## run_tor_wait_direct is overridden to print a marker instead of invoking the
## real /usr/libexec helper; the leaprun branch is observed through a PATH stub
## that prints its own marker. So the caller (tor_wait_dispatch_test.sh) sees
## which branch ran -- root/leaprun/fallback -- with no real helper, uwtwrapper
## or Tor. Prints exactly one 'RAN:direct' or 'RAN:leaprun' line.

# shellcheck disable=SC1090,SC1091,SC2154  # SUBJECT: the dnf-3.anondist path, from the env
source "${SUBJECT}"

## Override the direct-helper seam: record instead of running the real
## /usr/libexec/helper-scripts/try-wait-for-tor-service-running.
run_tor_wait_direct() {
  printf '%s\n' 'RAN:direct'
}

wait_for_tor_service
