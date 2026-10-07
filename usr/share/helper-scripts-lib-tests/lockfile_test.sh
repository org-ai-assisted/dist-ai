#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: helper-scripts lockfile.sh is the per-user single-instance lock
## (flock(1) FLOCKER re-exec) that dist-installer-cli now sources instead of an
## inline holder subshell. Drives the REAL lockfile.sh in its documented execute
## mode -- 'lockfile.sh <key> -- <command>' -- under a private, owned
## XDG_RUNTIME_DIR, so nothing touches the caller's real runtime dir. No root, no
## network.
##
## Assertions (each a canary -- a missing subject is FATAL, never a skip):
##   1. a free lock is ACQUIRED and held (confirmed by a DIRECT flock probe on the
##      lock file, not by message text), and a second acquirer is REFUSED while the
##      lock is genuinely held;
##   2. after the holder exits the lock is re-acquirable;
##   3. flock --close: a backgrounded grandchild that OUTLIVES the locked command
##      (the real dist-installer-cli case: a detached VirtualBox GUI) does NOT pin
##      the lock. Without --close the grandchild inherits the lock fd and this
##      FAILS -- the canary that keeps --close load-bearing.
##
## Exit: 0 pass | 1 fail.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Execute mode needs these unset so lockfile.sh treats "${1}" as the lock key and
## performs the FLOCKER re-exec.
unset LOCK_NAME FLOCKER 2>/dev/null || true

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
## usr/share/helper-scripts-lib-tests -> repo root is three levels up (installed: '/').
repo="${DIST_AI_REPO:-${test_dir}/../../..}"
proc_lib="${repo}/usr/share/dist-ai-tests-common/proc-lib.bash"
[ -r "${proc_lib}" ] || { printf '%s\n' "FATAL: proc-lib.bash not found: ${proc_lib}" >&2; exit 1; }
# shellcheck source=../dist-ai-tests-common/proc-lib.bash
. "${proc_lib}"

## Subject: the shipped lockfile.sh. HELPER_SCRIPTS_REPO points the suite at a
## checkout; unset means the installed package. A checkout stores it under
## '<repo>/usr/libexec/...'; installed it is '/usr/libexec/...' (not '/usr/usr/...').
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   hs_root="${HELPER_SCRIPTS_REPO}"
else
   hs_root='/usr'
fi
subject="${hs_root}/usr/libexec/helper-scripts/lockfile.sh"
[ "${hs_root}" = "/usr" ] && subject='/usr/libexec/helper-scripts/lockfile.sh'
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: lockfile.sh not readable: '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout." >&2
   exit 1
fi

work="$(mktemp --directory)"
## Private, owned runtime dir so the lock lives here, not the caller's real one.
export XDG_RUNTIME_DIR="${work}/xdg"
mkdir --mode=0700 -- "${XDG_RUNTIME_DIR}"

holder_pid=""
sleep_pid=""
gchild_pid=""
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   ## End every process we started; each guard tolerates an already-gone target so
   ## errexit cannot abort the trap before the work dir is removed. No blocking
   ## primitive (FIFO/pipe) is used, so cleanup cannot hang on a dead holder.
   if [ -n "${sleep_pid}" ]; then kill -s KILL -- "${sleep_pid}" 2>/dev/null || true; fi
   if [ -n "${holder_pid}" ]; then kill -s KILL -- "${holder_pid}" 2>/dev/null || true; fi
   if [ -n "${gchild_pid}" ]; then kill -s KILL -- "${gchild_pid}" 2>/dev/null || true; fi
   safe-rm --recursive --force -- "${work}" || true
}
trap cleanup EXIT

## Keys with no '_' '/' '.' so lockfile.sh's path substitution is an identity and
## the lock file path is predictable for a direct flock probe.
key_one="guardkeyone"
key_two="guardkeytwo"
lockfile_one="${XDG_RUNTIME_DIR}/flocker-temp-folder/${key_one}"

pass_count=0
fail_count=0
ok() {
   printf '%s\n' "PASS: ${1}"
   pass_count=$(( pass_count + 1 ))
}
notok() {
   printf '%s\n' "FAIL: ${1}" >&2
   [ -n "${2:-}" ] && printf '%s\n' "      ${2}" >&2
   fail_count=$(( fail_count + 1 ))
}

## Does a DIRECT, independent flock probe find the lock held? (true = held.)
lock_held() {
   [ -e "${lockfile_one}" ] && ! flock --exclusive --nonblock "${lockfile_one}" true 2>/dev/null
}

## --- Assertion 1: acquire + hold + refuse a second acquirer ------------------
## Holder: 'sleep' holds the lock for the whole command; a simple command, no
## detached child. Captured by PARENT pid ('pgrep -P', no pattern -> self-safe) so
## assertion 2 can end it precisely and leave no orphan.
bash "${subject}" "${key_one}" -- sleep 3600 >/dev/null 2>&1 &
holder_pid="$!"

for _ in $(seq 1 200); do
   sleep_pid="$(pgrep -P "${holder_pid}" 2>/dev/null | head -n 1 || true)"
   if [ -n "${sleep_pid}" ] && lock_held; then
      break
   fi
   sleep 0.05
done

if [ -n "${sleep_pid}" ] && lock_held; then
   ok "free lock acquired and held (direct flock probe confirms, holder pid=${holder_pid})"
else
   notok "holder never acquired the lock" "lockfile='${lockfile_one}'"
fi

## Refusal requires BOTH: the second acquirer exits non-zero AND the lock is still
## genuinely held (direct probe) -- so a non-zero exit for any unrelated reason,
## or a holder that never acquired, cannot false-pass this.
contend_rc=0
bash "${subject}" "${key_one}" -- true >/dev/null 2>&1 || contend_rc=$?
if [ "${contend_rc}" -ne 0 ] && lock_held; then
   ok "second acquirer refused while the lock is held"
else
   notok "second acquirer was not refused while the lock is held" "contend_rc=${contend_rc}"
fi

## --- Assertion 2: re-acquirable after the holder exits -----------------------
## End the locked command ('sleep'); flock then releases the lock and exits (the
## normal command-exit path). Signalling the command, not flock, leaves no orphan.
if [ -n "${sleep_pid}" ]; then kill "${sleep_pid}" 2>/dev/null || true; fi
for _ in $(seq 1 200); do
   proc_dead "${holder_pid}" && break
   sleep 0.05
done
wait "${holder_pid}" 2>/dev/null || true
holder_pid=""
sleep_pid=""

reacq_rc=0
bash "${subject}" "${key_one}" -- true >/dev/null 2>&1 || reacq_rc=$?
if [ "${reacq_rc}" -eq 0 ]; then
   ok "lock re-acquirable after the holder exits"
else
   notok "lock not re-acquirable after the holder exits"
fi

## --- Assertion 3: flock --close -- a detached grandchild must not pin the lock
## The locked command spawns a background grandchild that outlives it, then exits.
## With flock --close the grandchild never inherits the lock fd, so the lock frees
## the moment the command exits; without --close the grandchild pins it.
pidfile="${work}/gchild.pid"
bash "${subject}" "${key_two}" -- bash -c "sleep 3600 & printf '%s' \"\${!}\" > '${pidfile}'; exit 0"
gchild_pid="$(cat -- "${pidfile}" 2>/dev/null || true)"

if [ -z "${gchild_pid}" ] || proc_dead "${gchild_pid}"; then
   ## The grandchild must be alive, or the canary proves nothing.
   notok "detached grandchild not alive after command exit -- canary vacuous" "pid='${gchild_pid}'"
else
   free_rc=0
   bash "${subject}" "${key_two}" -- true >/dev/null 2>&1 || free_rc=$?
   if [ "${free_rc}" -eq 0 ]; then
      ok "lock free after command exit though detached grandchild (pid ${gchild_pid}) lives -- flock --close verified"
   else
      proc_diag "detached-grandchild" "${gchild_pid}"
      notok "detached grandchild pinned the lock -- flock --close missing or ineffective"
   fi
fi

printf '%s\n' ""
printf '%s\n' "===== lockfile.sh: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
