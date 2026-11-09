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
## Exit: 0 ok; 1 sourcing enabled errexit (strict leak); 3 the function is undefined.

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

## 'source' mode: if sourcing enabled errexit, this 'false' aborts (exit 1);
## otherwise 'true' yields exit 0. Any stdout here would also fail the
## no-auto-run assertion in the test.
false
true
