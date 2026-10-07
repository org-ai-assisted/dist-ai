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
##   1. a FREE lock is acquired and the command runs;
##   2. a second acquirer is REFUSED while the lock is held (confirmed by a DIRECT
##      flock probe, not by message text) -- the no-double-start guarantee;
##   3. after the holder exits the lock is re-acquirable;
##   4. flock --close: a backgrounded grandchild that OUTLIVES the locked command
##      (the real dist-installer-cli case: a detached VirtualBox GUI) does NOT pin
##      the lock. Without --close the grandchild inherits the lock fd and this
##      FAILS -- the canary that keeps --close load-bearing.
##   5. SOURCED self-lock under strict mode (errexit/errtrace + an ERR trap) refuses
##      a held lock CLEANLY: exit 75 (EX_TEMPFAIL), NO ERR-trap abort, body not run.
##      This is the systemcheck regression -- a bare pre-check 'flock' fired the
##      sourcing script's ERR trap (a spurious error dialog), so the lock was
##      disabled. FAILS on the old code (ERR trap fires, exit != 75).
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

## Subject: the shipped lockfile.sh. HELPER_SCRIPTS_REPO (empty when testing the
## installed package) prefixes the path -- empty -> '/usr/libexec/...', a checkout
## -> '<repo>/usr/libexec/...'.
hs_root="${HELPER_SCRIPTS_REPO:-}"
subject="${hs_root}/usr/libexec/helper-scripts/lockfile.sh"
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
gchild_pid=""
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   ## End every process we started; each guard tolerates an already-gone target so
   ## errexit cannot abort the trap before the work dir is removed. The holder holds
   ## the lock fd directly (no child), so SIGKILL releases it with nothing orphaned.
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

## --- Assertion 1: lockfile.sh acquires a free lock and runs the command -------
## This also creates the flocker-temp-folder and the key_one lock file that the
## holder below opens directly.
if bash "${subject}" "${key_one}" -- true >/dev/null 2>&1; then
   ok "free lock acquired and command ran"
else
   notok "lockfile.sh failed to acquire a free lock"
fi

## --- Assertion 2: a second acquirer is refused while the lock is held ---------
## The holder holds the lock DIRECTLY on its own fd, then execs 'sleep' so it keeps
## that fd open with no child -- SIGKILL releases the lock immediately and orphans
## nothing. The fd is opened INSIDE the subshell, so neither this shell nor the
## acquirers under test inherit it.
## style-ok: allow-exec -- the holder execs 'sleep' so the lock-holder is a single
## killable PID holding the fd, leaving no orphaned child to pin the lock.
( exec {hf}>"${lockfile_one}"; flock --exclusive --nonblock "${hf}" || exit 1; exec sleep 3600 ) &
holder_pid="$!"
## Drop it from the job table so bash does not print an async "Killed" notice when
## we SIGKILL it below; liveness is polled via proc_dead (/proc), not wait.
disown "${holder_pid}" 2>/dev/null || true

for _ in $(seq 1 200); do
   lock_held && break
   sleep 0.05
done

contend_rc=0
bash "${subject}" "${key_one}" -- true >/dev/null 2>&1 || contend_rc=$?
## Exit MUST be 75 (EX_TEMPFAIL -- the conventional 'resource busy, retry later'
## code), not merely non-zero, so a regression to flock's generic default (1) or a
## dropped --conflict-exit-code is caught.
if [ "${contend_rc}" -eq 75 ] && lock_held; then
   ok "second acquirer refused while the lock is held (exit 75 EX_TEMPFAIL)"
else
   notok "second acquirer not refused with exit 75 while the lock is held" "contend_rc=${contend_rc}"
fi

## --- Assertion 3: re-acquirable after the holder exits ------------------------
if [ -n "${holder_pid}" ]; then kill -s KILL -- "${holder_pid}" 2>/dev/null || true; fi
for _ in $(seq 1 200); do
   proc_dead "${holder_pid}" && break
   sleep 0.05
done
holder_pid=""

reacq_rc=0
bash "${subject}" "${key_one}" -- true >/dev/null 2>&1 || reacq_rc=$?
if [ "${reacq_rc}" -eq 0 ]; then
   ok "lock re-acquirable after the holder exits"
else
   notok "lock not re-acquirable after the holder exits"
fi

## --- Assertion 4: flock --close -- a detached grandchild must not pin the lock
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

## --- Assertion 5: SOURCED self-lock under strict mode refuses cleanly ----------
## The systemcheck regression. A script that SOURCES lockfile.sh under
## errexit/errtrace with an ERR trap must, when the lock is held, exit 75 via the
## authoritative exec'd flock -- NOT abort through its ERR trap. The old bare
## pre-check 'flock' failed under errexit and fired the trap (a spurious error
## dialog), which is why the lock was disabled in systemcheck.
key_src="guardkeysource"
lockfile_src="${XDG_RUNTIME_DIR}/flocker-temp-folder/${key_src}"

## Hold the key_src lock directly (same fd-holder pattern as assertion 2); the '>'
## redirect creates the lock file, so no prior lockfile.sh run is needed.
( exec {hf}>"${lockfile_src}"; flock --exclusive --nonblock "${hf}" || exit 1; exec sleep 3600 ) &
holder_pid="$!"
disown "${holder_pid}" 2>/dev/null || true
for _ in $(seq 1 200); do
   if [ -e "${lockfile_src}" ] && ! flock --exclusive --nonblock "${lockfile_src}" true 2>/dev/null; then
      break
   fi
   sleep 0.05
done

## Contender: a strict-mode script that SOURCES the real lockfile.sh with
## LOCK_NAME=key_src (locking the held key). Its ERR trap prints a marker and exits
## 42; a clean refusal instead exits 75 with neither the trap marker nor the
## post-source body ('PROCEEDED') having run.
src_caller="${work}/selflock_caller.sh"
cat > "${src_caller}" <<EOF
#!/bin/bash
set -o errexit -o nounset -o pipefail -o errtrace
shopt -s inherit_errexit
trap 'printf "ERRTRAP\n" >&2; exit 42' ERR
export LOCK_NAME='${key_src}'
source '${subject}'
printf 'PROCEEDED\n'
EOF
chmod +x -- "${src_caller}"

src_out="${work}/selflock.out"
src_rc=0
"${src_caller}" >"${src_out}" 2>&1 || src_rc=$?

if [ "${src_rc}" -eq 75 ] \
   && ! grep --quiet 'ERRTRAP' -- "${src_out}" \
   && ! grep --quiet 'PROCEEDED' -- "${src_out}"; then
   ok "sourced self-lock under strict mode refused cleanly (exit 75, no ERR-trap abort)"
else
   notok "sourced self-lock mishandled a held lock -- bug #1 regression" \
      "src_rc=${src_rc} out=[$(tr '\n' '|' < "${src_out}" 2>/dev/null || true)]"
fi

if [ -n "${holder_pid}" ]; then kill -s KILL -- "${holder_pid}" 2>/dev/null || true; fi
holder_pid=""

printf '%s\n' ""
printf '%s\n' "===== lockfile.sh: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
