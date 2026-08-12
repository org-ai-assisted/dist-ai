#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## msgcollector's escalate_type_file writes a passive-popup type (info<warning<
## error) without downgrading. Concurrent same-identifier writers are expected,
## so the read-modify-write must be serialized -- otherwise two writers both read
## the old value and the last to write downgrades severity (error -> info),
## violating the no-downgrade contract. This drives the REAL function from the
## msgcollector checkout: the sequential no-downgrade property, and -- the
## regression this guards -- that a concurrent writer is BLOCKED by the lock
## (an unlocked read-modify-write writes straight through and fails here).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""

if [ -n "${MSGCOLLECTOR_REPO}" ]; then
   subject="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector/msgcollector"
else
   subject='/usr/libexec/msgcollector/msgcollector'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: msgcollector not found at '${subject}'" >&2
   printf '%s\n' "set MSGCOLLECTOR_REPO to a msgcollector checkout, or install the package" >&2
   exit 77
fi
## flock (util-linux) is a hard msgcollector dependency (msgdispatcher requires
## it too), so it is required, not skipped.

## Extract the REAL function from the current script text (no drift), then run it.
fn="$(sed -n '/^escalate_type_file() {/,/^}/p' -- "${subject}")"
if [ -z "${fn}" ]; then
   printf '%s\n' "SKIP: escalate_type_file not found in ${subject}" >&2
   exit 77
fi
## escalate_type_file references onlyecho only in the passive path, not here;
## default it so nounset does not abort the extracted function.
onlyecho=""
eval "${fn}"

work_dir="$(mktemp --directory -- "${TMP}/msgcollector-escalate-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT
type_file="${work_dir}/id_passivepopupqueuextype"

pass_count=0
fail_count=0
pass() { printf '%s\n' "PASS: $1"; pass_count=$(( pass_count + 1 )); }
fail() { printf '%s\n' "FAIL: $1" >&2; fail_count=$(( fail_count + 1 )); }

## 1. Sequential no-downgrade: a later info must not overwrite an error.
escalate_type_file "${type_file}" error
escalate_type_file "${type_file}" info
if [ "$(cat -- "${type_file}")" = error ]; then
   pass "sequential: error is not downgraded by a later info"
else
   fail "sequential: error was downgraded to '$(cat -- "${type_file}")'"
fi

## 2. The lock. A SEPARATE process holds the type-file lock and SIGNALS once it
## has actually acquired it (no fixed-delay guessing), then a writer must BLOCK
## (write nothing) until the lock frees. flock runs its -c command only after
## acquiring, so the touch proves the lock is held. All waits are bounded polls
## on real state, not sleeps that assume timing.
safe-rm --force -- "${type_file}" "${type_file}.lock"
ready_file="${work_dir}/holder_ready"
flock --exclusive "${type_file}.lock" -c "touch -- '${ready_file}'; sleep 30" &
holder_pid=$!

waited=0
while [ ! -e "${ready_file}" ] && [ "${waited}" -lt 100 ]; do
   sleep 0.1
   waited=$(( waited + 1 ))
done
if [ ! -e "${ready_file}" ]; then
   fail "lock holder never acquired the lock (setup failure)"
fi

escalate_type_file "${type_file}" error &
writer_pid=$!
## A correctly-locked writer never writes while the lock is held; an unlocked
## one writes almost immediately. Poll to a deadline instead of guessing a sleep.
wrote_while_locked=no
polled=0
while [ "${polled}" -lt 20 ]; do
   if [ -s "${type_file}" ]; then
      wrote_while_locked=yes
      break
   fi
   sleep 0.1
   polled=$(( polled + 1 ))
done
if [ "${wrote_while_locked}" = yes ]; then
   fail "a writer wrote the type file while the lock was held -- read-modify-write is unserialized (the downgrade race)"
else
   pass "a concurrent writer is blocked by the held type lock (nothing written while locked)"
fi

kill -- "${holder_pid}" 2>/dev/null || true   ## release the lock
wait "${writer_pid}" 2>/dev/null || true
if [ "$(cat -- "${type_file}" 2>/dev/null)" = error ]; then
   pass "the writer wrote error once the lock was released"
else
   fail "the writer did not write error after the lock released"
fi

printf '%s\n' ""
## No per-test skips: the suite exits 77 at setup if a dependency is missing.
printf '%s\n' "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
