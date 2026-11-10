#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NON-strict: in 'source' mode this probe
## must start with errexit OFF to observe whether sourcing SUBJECT turns it ON.
## Run by repair_torrc_authdir_perm_test.sh, which asserts on its exit code and
## on the dir modes 'create' leaves behind.
##
## arg1:
##   source          -- just source SUBJECT (strict-leak / no-auto-run probe)
##   create <authdir> -- source SUBJECT, then create <authdir> honoring the
##                       INHERITED umask (the real consumer path: errexit +
##                       inherit_errexit, exactly as repair-torrc's main() calls it)
##
## Exit: 0 ok; non-zero sourcing leaked strict-mode -- errexit OR nounset; 3 the
## function is undefined. In 'source' mode the sentinel 'PROBE_SOURCE_END' is
## printed ONLY if control falls through to the end: a subject that auto-ran its
## main and hit 'exit' never emits it, so the test fails loud instead of passing
## vacuously.

# shellcheck disable=SC1090,SC1091,SC2154  # SUBJECT: the repair-torrc path, from the env
source "${SUBJECT}"

if ! declare -F repair_torrc_create_authdir >/dev/null ; then
   exit 3
fi

if [ "${1:-}" = "create" ]; then
   set -o errexit
   set -o nounset
   set -o pipefail
   set -o errtrace
   shopt -s inherit_errexit
   repair_torrc_create_authdir "${2}"
   exit 0
fi

## 'source' mode: detect a strict-mode LEAK before the sentinel. If sourcing
## enabled errexit, the 'false' aborts the probe (non-zero exit, no sentinel);
## if it enabled nounset, expanding the unset canary aborts the probe; if
## sourcing auto-ran main, its 'exit' never reaches the sentinel either.
## Reaching the sentinel at exit 0 proves sourcing leaked NEITHER errexit NOR
## nounset and did not auto-run. The sentinel is the ONLY stdout.
false
# shellcheck disable=SC2154  # deliberately-unset canary: a nounset leak aborts here
: "${__repair_torrc_probe_nounset_canary__}"
printf '%s\n' PROBE_SOURCE_END
