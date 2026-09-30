#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Fixture for the use_leaprun.sh lib tests -- EXECUTED, never sourced (so a
## real script file replaces an inline `bash -c` payload). Sources the REAL
## use_leaprun.sh named by ${USE_LEAPRUN_SH} and prints its verdict:
##   use_leaprun=<yes|no|empty>
##   result_len=<N>
## use_leaprun.sh's own warning goes wherever use_leaprun.sh routes it (stderr),
## so the caller captures the two streams separately.
##
## When LEAPRUN_FAKE_USABLE=1 (run under an unprivileged bwrap with a tmpfs
## /run/privleapd), first fake a USABLE privleap: a live pid file, a UID-named
## comm socket, and a stub leaprun on PATH -- so the probe must resolve the comm
## socket by UID (as privleapd names it) to report 'yes'.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v USE_LEAPRUN_SH ] || { printf '%s\n' "FATAL: USE_LEAPRUN_SH unset" >&2; exit 1; }

if [ "${LEAPRUN_FAKE_USABLE:-}" = '1' ]; then
   mkdir -p /run/privleapd/comm
   ## This shell is alive, so /proc/$$ exists -> the pid check passes.
   printf '%s\n' "$$" > /run/privleapd/pid
   ## privleapd names the comm socket by UID; create that path.
   touch -- "/run/privleapd/comm/$(id --user)"
   ## Stub leaprun so the PATH existence check passes without installing privleap.
   stubdir="$(mktemp --directory)"
   printf '%s\n' '#!/bin/sh' 'exit 0' > "${stubdir}/leaprun"
   chmod +x "${stubdir}/leaprun"
   PATH="${stubdir}:${PATH}"
   export PATH
fi

use_leaprun=''
leaprun_useable_result=''
## use_leaprun.sh runs its probe at source time and returns 0 on every branch.
# shellcheck disable=SC1090
source "${USE_LEAPRUN_SH}"

printf 'use_leaprun=%s\n' "${use_leaprun:-empty}"
printf 'result_len=%s\n' "${#leaprun_useable_result}"
