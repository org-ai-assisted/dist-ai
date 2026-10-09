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
## use_leaprun.sh's reachability check does a REAL connect() to the per-user
## AF_UNIX comm socket, so a usable privleap cannot be faked with a mere `touch`
## (connect() refuses a regular file or a dead socket inode). The fake modes
## below (run under an unprivileged bwrap with a tmpfs /run/privleapd) use the
## privleapd_fake_socket.py helper to create a real listener or a real stale
## inode, plus a stub leaprun on PATH. Each writes a pid file too, only so the
## OLD pidfile/'/proc/<pid>' heuristic resolves -- it lets the stale/hidepid
## cases double as canaries that FAIL on the pre-connect-probe code:
##   LEAPRUN_FAKE_USABLE=1   live listener + live pid        -> expect 'yes'
##   LEAPRUN_FAKE_STALE=1    dead socket inode + live pid     -> expect 'no'
##                           (false-POSITIVE on the old heuristic)
##   LEAPRUN_FAKE_HIDEPID=1  live listener + a pid with no    -> expect 'yes'
##                           '/proc/<pid>' (as under hidepid=2); false-NEGATIVE
##                           on the old heuristic
##   LEAPRUN_FAKE_SOCAT_DENIED=1  live listener + a stub socat  -> expect 'no'
##                           failing like an AppArmor exec denial (exit code
##                           126, 'Permission denied'); the warning must carry both

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v USE_LEAPRUN_SH ] || { printf '%s\n' "FATAL: USE_LEAPRUN_SH unset" >&2; exit 1; }

## EXIT-trap target (R-051: never an inline command). Reaps the background fake
## listener; fake_socket_pid is a global set before the trap is armed.
reap_fake_socket() {
   [ -n "${fake_socket_pid:-}" ] && kill "${fake_socket_pid}" 2>/dev/null
   return 0
}

setup_fake_privleapd() {
   ## $1 = socket state: 'listen' (reachable) or 'stale' (dead inode)
   ## $2 = pid written to /run/privleapd/pid (for the old heuristic's sake)
   ## Resolve the fake-socket helper here, not at top level: the non-fake path
   ## (use_leaprun_test.sh) runs with PATH=/nonexistent, where only builtins work.
   local socket_state="$1" pid_value="$2"
   local fixture_dir fake_socket
   fixture_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
   fake_socket="${fixture_dir}/privleapd_fake_socket.py"
   mkdir -p /run/privleapd/comm
   printf '%s\n' "${pid_value}" > /run/privleapd/pid
   local comm_socket
   comm_socket="/run/privleapd/comm/$(id --user)"
   if [ "${socket_state}" = 'stale' ]; then
      "${fake_socket}" stale "${comm_socket}"
   else
      local ready_marker='/run/privleapd/fake_ready'
      ## fake_socket_pid is intentionally global so the EXIT trap can reap it.
      "${fake_socket}" listen "${comm_socket}" "${ready_marker}" >/dev/null 2>&1 &
      fake_socket_pid="$!"
      trap reap_fake_socket EXIT
      local waited=0
      while [ ! -e "${ready_marker}" ]; do
         sleep 0.05
         waited=$(( waited + 1 ))
         if [ "${waited}" -ge 100 ]; then
            printf '%s\n' "FATAL: fake privleapd listener did not become ready" >&2
            exit 1
         fi
      done
   fi
   ## Stub leaprun so 'command -v leaprun' passes without installing privleap.
   ## In the tmpfs so it vanishes with the bwrap namespace (no /tmp leak).
   local stubdir='/run/privleapd/stub'
   mkdir -p "${stubdir}"
   printf '%s\n' '#!/bin/sh' 'exit 0' > "${stubdir}/leaprun"
   chmod +x "${stubdir}/leaprun"
   PATH="${stubdir}:${PATH}"
   export PATH
}

if [ "${LEAPRUN_FAKE_USABLE:-}" = '1' ]; then
   setup_fake_privleapd listen "$$"
elif [ "${LEAPRUN_FAKE_STALE:-}" = '1' ]; then
   setup_fake_privleapd stale "$$"
elif [ "${LEAPRUN_FAKE_HIDEPID:-}" = '1' ]; then
   ## pid_max is the exclusive upper bound, so no process can own it: a valid
   ## positive integer whose '/proc/<pid>' never exists -- a deterministic stand
   ## in for a daemon pid hidden by hidepid=2.
   setup_fake_privleapd listen "$(cat /proc/sys/kernel/pid_max)"
elif [ "${LEAPRUN_FAKE_SOCAT_DENIED:-}" = '1' ]; then
   setup_fake_privleapd listen "$$"
   ## Shadows the real socat via the stub dir setup_fake_privleapd put first on PATH.
   printf '%s\n' '#!/bin/sh' \
      'printf "%s\n" "socat: Permission denied" >&2' \
      'exit 126' > /run/privleapd/stub/socat
   chmod +x /run/privleapd/stub/socat
fi

use_leaprun=''
leaprun_useable_result=''
## use_leaprun.sh runs its probe at source time and returns 0 on every branch.
# shellcheck disable=SC1090
source "${USE_LEAPRUN_SH}"

printf 'use_leaprun=%s\n' "${use_leaprun:-empty}"
printf 'result_len=%s\n' "${#leaprun_useable_result}"
