#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Contract test for helper-scripts try-wait-for-system-ready.
##
## The novel logic is the wait LOOP, which must:
##  - return 0 as soon as 'leaprun system-ready-check' reports 'running' or
##    'degraded';
##  - be bounded by ELAPSED WALL-CLOCK, not by an iteration count: the probe can
##    return instantly on failure (missing binary / rejected comm socket), so an
##    iteration cap plus a per-iteration light_sleep would collapse the wait to
##    ~(iterations)s and give up long before the intended ~180s ceiling -- the
##    exact bug this helper exists to avoid. Case B is the canary: it fails on an
##    iteration-count loop, which ignores the seconds cap and runs its fixed count.
##  - still return 0 (best-effort) when the system never reports ready, so the
##    consumer falls through to its own gate.
##
## Drives the REAL script by SOURCING it (the was_executed guard suppresses its
## main, so sourcing only defines the pure function), then exercises
## try_wait_for_system_ready with the readiness oracle ('leaprun', an external
## privileged action that needs a live system) stubbed as a shell function. The
## stub is inherited by the subject's '$(leaprun ...)' command-substitution
## subshell, so it logs each call to a FILE (a counter variable would not survive
## the subshell). No root, no systemd, no privleap.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/try-wait-for-system-ready"
else
   subject='/usr/libexec/helper-scripts/try-wait-for-system-ready'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}' (set HELPER_SCRIPTS_REPO)." >&2
   exit 1
fi

## The subject resolves check_runtime.bsh / strings.bsh / light_sleep.bsh through
## HELPER_SCRIPTS_PATH; empty -> the installed /usr/libexec, same as production.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"

pass_count=0
fail_count=0
pass() { pass_count=$((pass_count + 1)); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$((fail_count + 1)); printf '%s\n' "FAIL: $*" >&2; }

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

probe_log="${work_dir}/leaprun-calls"

## Sourcing defines the pure function without running main: was_executed sees
## BASH_SOURCE[0] (the subject) != $0 (this test), so main is skipped.
# shellcheck disable=SC1090
source "${subject}"

if ! declare -F try_wait_for_system_ready >/dev/null; then
   printf '%s\n' "FATAL: sourcing the subject did not define try_wait_for_system_ready" >&2
   exit 1
fi

## Readiness oracle stub. 'leaprun' is the real privileged action in production
## (needs a live system); here it is a shell function, inherited by the subject's
## '$(leaprun ...)' subshell, that appends one line per call to probe_log (so the
## re-probe count survives the subshell) and prints the fake verdict passed via
## leaprun_fake_result ('' + non-zero models the fast-fail / unusable case).
leaprun_fake_result=''
# shellcheck disable=SC2329  # invoked across the 'source' boundary (dynamic scope)
leaprun() {
   printf '%s\n' 'call' >>"${probe_log}"
   if [ -z "${leaprun_fake_result}" ]; then
      return 1
   fi
   printf '%s\n' "${leaprun_fake_result}"
}

## 'running' on the first probe -> returns 0 after exactly one probe, no wait.
true >"${probe_log}"
leaprun_fake_result='running'
rc=0
try_wait_for_system_ready || rc="$?"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '1' ]; then
   pass "'running' immediately -> exit 0 after 1 probe"
else
   fail "'running' immediately -> rc=${rc}, probes=${probe_calls} (want 0, 1)"
fi

## 'degraded' is also accepted (is-system-running reports it on a booted system
## with a failed unit) -> returns 0 after exactly one probe.
true >"${probe_log}"
leaprun_fake_result='degraded'
rc=0
try_wait_for_system_ready || rc="$?"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '1' ]; then
   pass "'degraded' immediately -> exit 0 after 1 probe"
else
   fail "'degraded' accepted -> rc=${rc}, probes=${probe_calls} (want 0, 1)"
fi

## CANARY: probe never reports ready and fails FAST (empty + non-zero), with the
## REAL light_sleep (1s floor) running. A correct WALL-CLOCK cap waits ~max_seconds
## and re-probes repeatedly; an iteration-count loop would ignore max_seconds and
## either collapse to ~0s or run its own fixed count. Assert the elapsed time
## tracks the seconds cap and that it re-probed more than once.
true >"${probe_log}"
leaprun_fake_result=''
rc=0
t0="$(date +%s)"
system_ready_wait_max_seconds=3 try_wait_for_system_ready || rc="$?"
t1="$(date +%s)"
elapsed=$(( t1 - t0 ))
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] \
   && [ "${elapsed}" -ge 2 ] \
   && [ "${elapsed}" -le 10 ] \
   && [ "${probe_calls}" -ge 2 ]; then
   pass "never ready -> exit 0, waited ~cap (${elapsed}s for cap=3), re-probed ${probe_calls}x"
else
   fail "wall-clock cap -> rc=${rc}, elapsed=${elapsed}s (want 2..10), probes=${probe_calls} (want >=2)"
fi

## Errexit contract: the standalone main() calls this under 'set -o errexit', so a
## never-ready run must RETURN (0), not abort on an internal command. errexit is
## IGNORED inside an if-condition / '&&'-'||' list, so an in-process check would
## assert nothing -- run it in a real child 'bash' where errexit is set at top
## level and the function runs as a plain command. Use the REAL light_sleep (a
## stub returning 0 could hide a subject that misuses it).
errexit_probe="${work_dir}/errexit-probe.bash"
cat >"${errexit_probe}" <<'PROBE'
#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C
source "${SUBJECT}"
## Never-ready oracle (the real leaprun needs a live system).
leaprun() { return 1; }
system_ready_wait_max_seconds=1 try_wait_for_system_ready
PROBE
rc=0
SUBJECT="${subject}" HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
   bash "${errexit_probe}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" = '0' ]; then
   pass "never-ready run returns cleanly under errexit (child process, does not abort)"
else
   fail "aborted under errexit (rc=${rc})"
fi

printf '%s\n' ""
printf '%s\n' "===== try_wait_for_system_ready: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
