#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: a sourced-driver probe that
## must not impose its own strict mode on the real dnf-3.anondist (SUBJECT) it
## drives. Sources the sourceable SUBJECT (which resolves check_runtime.bsh via
## HELPER_SCRIPTS_PATH); was_executed is false when sourced so main does NOT
## auto-run. Two seams are overridden before dispatch:
##   - exec_uwtwrapper -> RECORD argv (one arg per line) to PROBE_RECORD then
##     exit. The exit models the real 'exec' being terminal: exactly one call
##     ends the process, so the first exec site main reaches is the recorded one.
##   - wait_for_tor_service -> no-op that only appends to PROBE_WAIT, so the
##     caller can tell whether the Tor wait was reached (no leaprun/Tor).
## PROBE_MODE selects what to drive:
##   rand -> random_alpha_numeric "$@"   (charset/length of the proxy password)
##   main -> main "$@"                   (proxy-injection vs passthrough logic)
## No real uwtwrapper, Tor, leaprun or 127.0.0.1:9050 proxy probe is touched.

# shellcheck disable=SC1090,SC1091,SC2154  # SUBJECT: the dnf-3.anondist path, from the env
source "${SUBJECT}"

exec_uwtwrapper() {
  printf '%s\n' "$@" > "${PROBE_RECORD}"
  exit 0
}

wait_for_tor_service() {
  printf '%s\n' 'waited' >> "${PROBE_WAIT}"
}

case "${PROBE_MODE}" in
  rand)
    random_alpha_numeric "$@"
    ;;
  main)
    main "$@"
    ;;
  *)
    printf '%s\n' "probe: unknown PROBE_MODE '${PROBE_MODE}'" >&2
    exit 2
    ;;
esac
