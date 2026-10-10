#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: the TTL self-release backstop and stale-holder reaping + registry format.
##   - a command exceeding --ttl is killed via timeout(1) (exit 124), releasing the lock,
##     so a wedged holder cannot hold the mutex forever (without the timeout wrap it would
##     run to completion and this FAILS);
##   - a holder registry file records the session identity + pid + ttl + cmd (so another
##     session can investigate a holder);
##   - a stale holder (dead pid, OR expired TTL even with a live pid) is reaped.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
# shellcheck source=./lib.bash
source "${test_dir}/lib.bash"

tmp="$(mktemp --directory --tmpdir dm-vm-lock-ttlreap.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${tmp}"; }
trap cleanup EXIT

## --- TTL self-release ------------------------------------------------------------------
d1="${tmp}/d1"; mkdir -- "${d1}"; printf '%s' "" > "${d1}/vm.lock"
export DM_VM_LOCK_DIR="${d1}"
start=${SECONDS}
rc=0; "${TOOL}" acquire --class leak --ttl 1 --wait 5 -- sleep 10 2>/dev/null || rc=$?
dur=$(( SECONDS - start ))
if [ "${rc}" -eq 124 ] && [ "${dur}" -lt 5 ]; then r=0; else r=1; fi
check 'TTL kills a wedged holder (exit 124, well before the command would finish)' "${r}"
rc=0; "${TOOL}" acquire --class leak --nonblock -- true || rc=$?
check 'the lock is free after a TTL kill' "${rc}"

## --- registry format -------------------------------------------------------------------
d2="${tmp}/d2"; mkdir -- "${d2}"; printf '%s' "" > "${d2}/vm.lock"
export DM_VM_LOCK_DIR="${d2}"
CLAUDE_RC_SESSION_NAME=devX CLAUDE_CODE_SESSION_ID=uuid-X \
   "${TOOL}" acquire --class work --ttl 30 --wait 5 -- sh -c 'sleep 3' &
bgpid=$!
rc=0; wait_for_holder "${d2}" work || rc=$?
check 'a holder registry file is created' "${rc}"
line="$(cat -- "${d2}"/holder.work.* 2>/dev/null || true)"
for kv in 'class=work' 'session=devX' 'session_id=uuid-X' 'ttl=30' 'cmd=sh -c sleep 3'; do
   case "${line}" in *"${kv}"*) r=0 ;; *) r=1 ;; esac
   check "registry records ${kv}" "${r}"
done
case "${line}" in *pid=*) r=0 ;; *) r=1 ;; esac
check 'registry records pid' "${r}"
case "${line}" in *ttl_deadline_epoch=*) r=0 ;; *) r=1 ;; esac
check 'registry records ttl_deadline_epoch (for investigation + reaping)' "${r}"
wait "${bgpid}" 2>/dev/null || true

## --- field-injection resistance --------------------------------------------------------
## An untrusted session name carrying a ' pid=NNN' token must not forge the pid field: the
## reader (vm_lock_kv) matches leftmost, so an unsanitized session would hijack the pid lookup
## and mis-reap the LIVE holder. The written session= must be sanitized AND vm_lock_kv must
## read back the REAL wrapper pid, not the injected one.
d4="${tmp}/d4"; mkdir -- "${d4}"; printf '%s' "" > "${d4}/vm.lock"
export DM_VM_LOCK_DIR="${d4}"
CLAUDE_RC_SESSION_NAME='foo pid=123' CLAUDE_CODE_SESSION_ID='id bar=1' \
   "${TOOL}" acquire --class work --ttl 30 --wait 5 -- sh -c 'sleep 3' &
bgpid=$!
rc=0; wait_for_holder "${d4}" work || rc=$?
check 'injection: a holder registry file is created' "${rc}"
line="$(cat -- "${d4}"/holder.work.* 2>/dev/null || true)"
case "${line}" in *'session=foo pid=123'*) r=1 ;; *'session=foo_pid_123'*) r=0 ;; *) r=1 ;; esac
check 'injection: session value is sanitized (no forged field boundary)' "${r}"
## Source the real tool (its BASH_SOURCE/$0 guard keeps main from running) to use vm_lock_kv,
## the exact reader vm_lock_reap relies on -- never a reimplementation that could drift.
read_pid="$(
   # shellcheck source=../../bin/dm-vm-lock
   source "${TOOL}"
   vm_lock_kv "${line}" pid
)"
if [ "${read_pid}" = "${bgpid}" ]; then r=0; else r=1; fi
check 'injection: vm_lock_kv reads the real pid, not the injected 123' "${r}"
wait "${bgpid}" 2>/dev/null || true

## --- reaping ---------------------------------------------------------------------------
d3="${tmp}/d3"; mkdir -- "${d3}"; printf '%s' "" > "${d3}/vm.lock"
export DM_VM_LOCK_DIR="${d3}"
printf '%s\n' "class=work session=g session_id=g user=g pid=999999 acquired=2020-01-01T00:00:00Z ttl=60 ttl_deadline_epoch=9999999999 cmd=ghost" \
   > "${d3}/holder.work.999999"
"${TOOL}" status >/dev/null 2>&1 || true
if [ -e "${d3}/holder.work.999999" ]; then r=1; else r=0; fi
check 'status reaps a dead-pid holder' "${r}"

## A LIVE pid with a future deadline must NOT be reaped (the who-holds-it record must survive).
printf '%s\n' "class=leak session=g session_id=g user=g pid=${$} acquired=2020-01-01T00:00:00Z ttl=999999 ttl_deadline_epoch=9999999999 cmd=live" \
   > "${d3}/holder.leak.$$"
"${TOOL}" status >/dev/null 2>&1 || true
if [ -e "${d3}/holder.leak.$$" ]; then r=0; else r=1; fi
check 'status keeps a live-pid, non-expired holder (no over-reaping)' "${r}"
safe-rm --force -- "${d3}/holder.leak.$$"

printf '%s\n' "class=work session=g session_id=g user=g pid=${$} acquired=2020-01-01T00:00:00Z ttl=1 ttl_deadline_epoch=1 cmd=old" \
   > "${d3}/holder.work.$$"
"${TOOL}" status >/dev/null 2>&1 || true
if [ -e "${d3}/holder.work.$$" ]; then r=1; else r=0; fi
check 'status reaps an expired-TTL holder (even with a live pid)' "${r}"

vmlock_done
