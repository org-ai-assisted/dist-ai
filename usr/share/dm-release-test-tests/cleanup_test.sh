#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for rt_eph_cleanup. Canary: a VBoxSVC owned by the ephemeral
## account lingers after the VM stops and blocks userdel (observed leaking the
## account in a live run), so cleanup MUST kill the account's processes BEFORE
## userdel. Stubs image-test-gc / pkill / userdel as order-recording stand-ins
## and asserts the kill precedes the userdel.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not found at ${subject}" >&2; exit 1; }
# shellcheck source=../../bin/dm-release-test
source "${subject}"

failures=0
work="$(mktemp --directory --tmpdir dm-release-test-cleanup.XXXXXX)"

cleanup_test_cleanup() {
   [ -n "${work}" ] || return 0
   safe-rm --recursive --force -- "${work}"
}
trap cleanup_test_cleanup EXIT

## Every seam that keeps the subject off REAL state is set before the first subject call:
## run as root, an unset seam would reclaim a real kept run's marker and staged ISO dir.
export ISO_DIR="${work}/iso"
export DM_RELEASE_TEST_LOCK_DIR="${work}/lock"
export DM_RELEASE_TEST_STATE_DIR="${work}/state"
mkdir --parents -- "${ISO_DIR}"

stubbin="${work}/bin"
mkdir --parents -- "${stubbin}"
order="${work}/order.log"
busctl_log="${work}/busctl.log"

## getent stub: the eph account resolves to a fake home under ${work}; anything else is
## passed to the real getent.
eph_home="${work}/home"
mkdir --parents -- "${eph_home}"
real_getent='/usr/bin/getent'
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "if [ \"\${1:-}\" = passwd ] && [ \"\${2:-}\" = 'eph-inst-kicksecure-18-2-3-5' ]; then"
   printf '%s\n' "   printf '%s\\n' 'eph-inst-kicksecure-18-2-3-5:x:5005:5005::${eph_home}:/bin/bash'"
   printf '%s\n' '   exit 0'
   printf '%s\n' 'fi'
   printf '%s\n' "if [ \"\$#\" = 1 ] && [ \"\${1:-}\" = passwd ]; then"
   printf '%s\n' "   printf '%s\\n' 'eph-inst-kicksecure-18-2-3-5:x:5005:5005::${eph_home}:/bin/bash' 'eph-inst-whonix-18-2-3-5:x:5006:5006::/nonexistent:/bin/bash' 'eph-inst-kicksecure-built:x:5007:5007::/nonexistent:/bin/bash' 'persist-inst-kicksecure:x:5008:5008::/nonexistent:/bin/bash'"
   printf '%s\n' '   exit 0'
   printf '%s\n' 'fi'
   printf '%s\n' "'${real_getent}' \"\$@\""
} > "${stubbin}/getent"
chmod 0770 -- "${stubbin}/getent"

for tool in image-test-gc pkill userdel; do
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' "printf '%s %s\\n' '${tool}' \"\$*\" >> '${order}'"
      printf '%s\n' 'exit 0'
   } > "${stubbin}/${tool}"
done
chmod 0770 -- "${stubbin}/image-test-gc" "${stubbin}/pkill" "${stubbin}/userdel"

## pgrep stub: the account's processes are STUB_PGREP_PIDS (none when empty). busctl stub:
## records the call, fails when STUB_BUSCTL_FAIL=1.
cat > "${stubbin}/pgrep" <<'EOF'
#!/bin/bash
[ -n "${STUB_PGREP_PIDS:-}" ] || exit 1
tr ' ' '\n' <<< "${STUB_PGREP_PIDS}"
EOF
cat > "${stubbin}/busctl" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> '${busctl_log}'
[ "\${STUB_BUSCTL_FAIL:-0}" != 1 ] || exit 1
exit 0
EOF
chmod 0770 -- "${stubbin}/pgrep" "${stubbin}/busctl"

## Globals rt_eph_cleanup reads (exported so shellcheck sees them used).
export PATH="${stubbin}:${PATH}"
export IMAGE_TEST_GC="${stubbin}/image-test-gc"
export EPH_CLEANUP_SETTLE=0
export NFT_FLEET_TOOL="definitely-not-on-path-${RANDOM}"
export eph_account='eph-inst-kicksecure-18-2-3-5'

rt_eph_cleanup >/dev/null 2>&1

check() {
   local label cond
   label="$1"
   cond="$2"
   if [ "${cond}" = 'true' ]; then
      printf '%s\n' "ok: ${label}"
   else
      printf '%s\n' "FAIL: ${label}" >&2
      failures=$((failures + 1))
   fi
}

pkill_line="$(grep -n '^pkill ' -- "${order}" | head -n 1 | cut -d: -f1)"
userdel_line="$(grep -n '^userdel ' -- "${order}" | head -n 1 | cut -d: -f1)"

check "image-test-gc was invoked" "$(grep --quiet '^image-test-gc ' -- "${order}" && printf '%s' "true" || printf '%s' "false")"
check "pkill killed the account by uid" "$(grep --quiet -- 'pkill .*--uid eph-inst-kicksecure-18-2-3-5' "${order}" && printf '%s' "true" || printf '%s' "false")"
check "userdel was invoked" "$([ -n "${userdel_line}" ] && printf '%s' "true" || printf '%s' "false")"
## Canary: a reverted fix (userdel with no prior pkill) leaves pkill_line empty or after userdel.
check "pkill ran BEFORE userdel" "$([ -n "${pkill_line}" ] && [ -n "${userdel_line}" ] && [ "${pkill_line}" -lt "${userdel_line}" ] && printf '%s' "true" || printf '%s' "false")"

## ---- keep-on-failure + reclaim ------------------------------------------------------
rt_kept_marker 'eph-inst-kicksecure-18-2-3-5'
marker="${rt_marker}"
check "keep: marker lives in the persistent state dir, not the /run lock dir" \
   "$([ "${marker}" = "${DM_RELEASE_TEST_STATE_DIR}/kept-eph-inst-kicksecure-18-2-3-5.staged" ] && printf '%s' "true" || printf '%s' "false")"

## Sets $? for the next command, as main's exit status does for the EXIT trap.
rc_is() {
   return "$1"
}

## (a) FAILED run, keep on (default): nothing torn down, staged ISO kept, marker written.
true >| "${order}"
rt_staged_dir="$(mktemp --directory -- "${ISO_DIR}/.built-XXXXXX")"
export DM_RELEASE_TEST_KEEP_FAILED=1
rc_is 5 || STUB_PGREP_PIDS='4242' rt_eph_cleanup >/dev/null 2>&1
check "keep: failed run tears nothing down" "$([ ! -s "${order}" ] && printf '%s' "true" || printf '%s' "false")"
check "keep: staged ISO dir kept (VM still has it attached)" "$([ -d "${rt_staged_dir}" ] && printf '%s' "true" || printf '%s' "false")"
check "keep: marker records the staged dir" "$([ "$(cat -- "${marker}" 2>/dev/null)" = "${rt_staged_dir}" ] && printf '%s' "true" || printf '%s' "false")"
## Root must never write into the account-controlled home (symlink / FIFO attack).
check "keep: nothing written into the account home" "$([ -z "$(ls -A -- "${eph_home}")" ] && printf '%s' "true" || printf '%s' "false")"
kept_dir="${rt_staged_dir}"

## (b) FAILED run, keep off: torn down as before.
true >| "${order}"
rt_staged_dir=""
export DM_RELEASE_TEST_KEEP_FAILED=0
rc_is 5 || rt_eph_cleanup >/dev/null 2>&1
check "no-keep: failed run invokes image-test-gc" "$(grep --quiet '^image-test-gc ' -- "${order}" && printf '%s' "true" || printf '%s' "false")"
check "no-keep: failed run invokes userdel" "$(grep --quiet '^userdel ' -- "${order}" && printf '%s' "true" || printf '%s' "false")"

## (c) reclaim of the kept account removes exactly the marked staged dir.
printf '%s\n' "${kept_dir}" > "${marker}"
rt_eph_reclaim 'eph-inst-kicksecure-18-2-3-5' >/dev/null 2>&1
check "reclaim: removes the kept staged ISO dir" "$([ ! -e "${kept_dir}" ] && printf '%s' "true" || printf '%s' "false")"

## (d) defense in depth: a marker path outside ISO_DIR/.built-*, or one escaping it
## with '..', is never removed.
victim="${work}/victim"
mkdir --parents -- "${victim}"
printf '%s\n' "${victim}" > "${marker}"
rt_eph_reclaim 'eph-inst-kicksecure-18-2-3-5' >/dev/null 2>&1
check "reclaim: ignores a marker outside ISO_DIR/.built-*" "$([ -d "${victim}" ] && printf '%s' "true" || printf '%s' "false")"
## .built-x must EXIST, else the path walk fails and the escape is never attempted.
mkdir --parents -- "${ISO_DIR}/.built-x"
printf '%s\n' "${ISO_DIR}/.built-x/../../victim" > "${marker}"
rt_eph_reclaim 'eph-inst-kicksecure-18-2-3-5' >/dev/null 2>&1
check "reclaim: ignores a '..' escape from ISO_DIR/.built-*" "$([ -d "${victim}" ] && printf '%s' "true" || printf '%s' "false")"

## (e) sweep: an UNLOCKED leftover eph-inst-* account is reclaimed; a LOCKED one (a live
## run holds its lock) and a persist-* account are never touched; the current account is
## left to the caller.
true >| "${order}"
rt_lock_dir
lockdir="${rt_lockdir}"
exec {held_fd}>"${lockdir}/dm-release-test-eph-inst-kicksecure-built.lock"
flock --nonblock "${held_fd}"
rt_sweep_eph_leftovers 'eph-inst-kicksecure-18-2-3-5' >/dev/null 2>&1
exec {held_fd}>&-
check "sweep: unlocked leftover reclaimed" "$(grep --quiet -- '^userdel .*eph-inst-whonix-18-2-3-5' "${order}" && printf '%s' "true" || printf '%s' "false")"
check "sweep: locked (live) account untouched" "$(grep --quiet -- 'eph-inst-kicksecure-built' "${order}" && printf '%s' "false" || printf '%s' "true")"
check "sweep: current account untouched" "$(grep --quiet -- 'eph-inst-kicksecure-18-2-3-5' "${order}" && printf '%s' "false" || printf '%s' "true")"
check "sweep: persist account untouched" "$(grep --quiet -- 'persist-inst' "${order}" && printf '%s' "false" || printf '%s' "true")"

## (f) an unusable state/lock dir ABORTS the run (SETUP rc 2). A die inside "$(...)" was
## masked: the marker path collapsed to '/kept-ACCOUNT.staged' and the keep "succeeded".
printf '%s\n' 'not a dir' > "${work}/afile"
export DM_RELEASE_TEST_KEEP_FAILED=1
bad_rc=0
(
   # shellcheck disable=SC2030  # scoped to this subshell on purpose
   export DM_RELEASE_TEST_STATE_DIR="${work}/afile/state" DM_RELEASE_TEST_LOCK_DIR="${work}/afile/lock"
   rt_staged_dir="${ISO_DIR}/.built-bad"
   rc_is 5 || rt_eph_cleanup
) >/dev/null 2>&1 || bad_rc=$?
check "unusable state dir aborts with the SETUP rc (no masked die)" "$([ "${bad_rc}" = 2 ] && printf '%s' "true" || printf '%s' "false")"
rel_rc=0
(
   # shellcheck disable=SC2030,SC2031  # scoped to this subshell on purpose
   export DM_RELEASE_TEST_LOCK_DIR='relative/lock'
   rt_lock_dir
) >/dev/null 2>&1 || rel_rc=$?
check "a relative lock dir is refused" "$([ "${rel_rc}" = 2 ] && printf '%s' "true" || printf '%s' "false")"

## (g) a run starting while a sweep briefly holds its account's lock WAITS for it (bounded),
## instead of dying 'another run holds the lock'.
wait_lock="${lockdir}/dm-release-test-eph-inst-wait.lock"
held_flag="${work}/held"
## Hold the lock for $1 seconds in the background; return once it is actually held.
hold_wait_lock() {
   safe-rm --force -- "${held_flag}"
   # shellcheck disable=SC2016  # positional args of the inner sh
   flock -o "${wait_lock}" sh -c 'touch -- "$1" && sleep "$2"' sh "${held_flag}" "$1" &
   sweep_holder=$!
   while [ ! -e "${held_flag}" ]; do
      sleep 0.1
   done
}
hold_wait_lock 3
wait_rc=0
( DM_RELEASE_TEST_LOCK_WAIT=30 rt_lock_account 'eph-inst-wait' ) >/dev/null 2>&1 || wait_rc=$?
check "lock: waits out a briefly held lock (rc=${wait_rc})" "$([ "${wait_rc}" = 0 ] && printf '%s' "true" || printf '%s' "false")"
wait "${sweep_holder}" || true
hold_wait_lock 600
wait_rc=0
( DM_RELEASE_TEST_LOCK_WAIT=1 rt_lock_account 'eph-inst-wait' ) >"${work}/wait.out" 2>&1 || wait_rc=$?
check "lock: the wait is bounded, dies with the SETUP rc (rc=${wait_rc}: $(tr '\n' ' ' < "${work}/wait.out"))" "$([ "${wait_rc}" = 2 ] && printf '%s' "true" || printf '%s' "false")"
## flock -o: the lock lives only in the flock process, so killing it releases the lock.
kill -- "${sweep_holder}" 2>/dev/null || true
wait "${sweep_holder}" || true

## (h) a kept VM leaves this run's cgroup: its processes move into their own scope. A VM
## that cannot be detached is NOT kept: the run is torn down, never reported as kept.
keep_out="${work}/keep.out"
rt_staged_dir=""
true >| "${busctl_log}"
rc_is 5 || STUB_PGREP_PIDS='4242 4243' rt_eph_cleanup 2>"${keep_out}" >/dev/null
check "keep: VM processes moved into their own scope" \
   "$(grep --quiet -- 'StartTransientUnit .*dm-release-test-kept-eph-inst-kicksecure-18-2-3-5-.*\.scope fail 1 PIDs au 2 4242 4243 0' "${busctl_log}" && printf '%s' "true" || printf '%s' "false")"
true >| "${order}"
rt_staged_dir="$(mktemp --directory -- "${ISO_DIR}/.built-XXXXXX")"
detach_fail_dir="${rt_staged_dir}"
safe-rm --force -- "${marker}"
rc_is 5 || STUB_PGREP_PIDS='4242' STUB_BUSCTL_FAIL=1 rt_eph_cleanup 2>"${keep_out}" >/dev/null
check "keep: a failed detach is reported loudly" \
   "$(grep --quiet -- 'dies as soon as' "${keep_out}" && printf '%s' "true" || printf '%s' "false")"
check "keep: a failed detach never claims the run was kept" \
   "$(grep --quiet -- 'kept FAILED run' "${keep_out}" && printf '%s' "false" || printf '%s' "true")"
check "keep: a failed detach tears the run down" \
   "$(grep --quiet -- '^userdel .*eph-inst-kicksecure-18-2-3-5' "${order}" && [ ! -e "${detach_fail_dir}" ] && [ ! -e "${marker}" ] && printf '%s' "true" || printf '%s' "false")"
rc_is 5 || rt_eph_cleanup 2>"${keep_out}" >/dev/null
check "keep: no VM process to keep -> not reported as kept" \
   "$(grep --quiet -- 'kept FAILED run' "${keep_out}" && printf '%s' "false" || printf '%s' "true")"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "" "${failures} cleanup assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' "" "all cleanup assertions passed"
