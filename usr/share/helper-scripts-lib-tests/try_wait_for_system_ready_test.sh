#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Contract test for helper-scripts try-wait-for-system-ready.
##
## The subject re-probes 'leaprun system-ready-check' and must:
##  - return 0 as soon as a whole output LINE is 'running' or 'degraded' --
##    matching the STDOUT state regardless of leaprun's exit code (real
##    'systemctl is-system-running' exits non-zero for 'degraded'), and
##    tolerating a stderr warning line that system-ready-check merges into the
##    output ahead of the state;
##  - re-probe every iteration, so a system that becomes ready on a later probe
##    is still detected;
##  - NOT accept any other state ('starting', 'offline', ...) or empty output;
##  - be bounded by ELAPSED WALL-CLOCK, not an iteration count: with a slow
##    probe an iteration-count loop runs iterations*probe, far past the cap --
##    Case "wall-clock" is the canary that fails such a loop;
##  - bound each probe with 'timeout', so a hung leaprun cannot block past the
##    cap -- Case "probe-timeout" is the canary for that;
##  - still return 0 (best-effort) when never ready, so the consumer's own gate
##    stays authoritative.
##
## Drives the REAL script by SOURCING it (the was_executed guard suppresses its
## main). 'leaprun' is the real privileged action in production; here it is a
## stub EXECUTABLE on PATH (not a shell function -- the subject runs it through
## 'timeout', which execs via PATH and would miss a function), driven by
## LEAPRUN_FAKE_* env. No root, no systemd, no privleap.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   repo="${HELPER_SCRIPTS_REPO}"
else
   repo="/"
fi
subject="${repo%/}/usr/libexec/helper-scripts/try-wait-for-system-ready"
libdir="${repo%/}/usr/libexec/helper-scripts"

## Absent subject / libs -> SKIP (a source-tree or partial run whose wired
## helper-scripts predates this helper); once helper-scripts ships it, the lane
## runs for real.
if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: subject not readable at '${subject}' (set HELPER_SCRIPTS_REPO)" >&2
   exit 77  ## style-ok: allow-skip: try-wait-for-system-ready absent (source-tree / helper-scripts not installed)
fi
for lib in check_runtime.bsh strings.bsh light_sleep.bsh; do
   if [ ! -r "${libdir}/${lib}" ]; then
      printf '%s\n' "SKIP: helper-scripts lib '${lib}' not readable under '${libdir}'" >&2
      exit 77  ## style-ok: allow-skip: helper-scripts lib absent (source-tree / helper-scripts not installed)
   fi
done

## The subject resolves its libs through HELPER_SCRIPTS_PATH; empty -> the
## installed /usr/libexec, same as production.
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
export LEAPRUN_PROBE_LOG="${probe_log}"
timeout_arg_log="${work_dir}/timeout-args"
export TIMEOUT_ARG_LOG="${timeout_arg_log}"

## Stub 'leaprun' executable, modelling 'leaprun system-ready-check':
##  - logs one line per call (count survives across the timeout/exec boundary);
##  - optionally delays (a slow / hung probe);
##  - once LEAPRUN_READY_ON_CALL (>0) calls have happened, reports 'running';
##  - prints LEAPRUN_FAKE_RESULT to stdout (empty -> nothing);
##  - exits 0 ONLY for 'running', non-zero otherwise -- as real
##    'systemctl is-system-running' does (exit 0 only when fully running).
leaprun_stub="${work_dir}/leaprun"
cat >"${leaprun_stub}" <<'STUB'
#!/bin/bash
## The subject MUST invoke exactly the 'system-ready-check' action; any other
## args mean a wrong call -> fail loud so the test catches it.
if [ "$*" != 'system-ready-check' ]; then
   printf '%s\n' "leaprun-stub: unexpected args: $*" >&2
   exit 99
fi
printf '%s\n' 'call' >>"${LEAPRUN_PROBE_LOG}"
if [ "${LEAPRUN_FAKE_DELAY:-0}" -gt 0 ]; then
   sleep "${LEAPRUN_FAKE_DELAY}"
fi
out="${LEAPRUN_FAKE_RESULT:-}"
calls="$(wc -l <"${LEAPRUN_PROBE_LOG}")"
if [ "${LEAPRUN_READY_ON_CALL:-0}" -gt 0 ] \
   && [ "${calls}" -ge "${LEAPRUN_READY_ON_CALL}" ]; then
   out='running'
fi
if [ -n "${out}" ]; then
   printf '%s\n' "${out}"
fi
[ "${out}" = 'running' ]
STUB
chmod 0755 "${leaprun_stub}"

## Stub 'timeout' wrapper: records the DURATION arg, then execs the REAL timeout.
## The subject calls 'timeout --kill-after=3 <probe_this> leaprun ...', so the first
## non-option token is the per-probe timeout. Lets the test assert the CONFIGURED
## system_ready_probe_timeout is actually passed (not merely a wall-clock band). The
## real path is resolved before work_dir is prepended to PATH, so exec never recurses.
real_timeout="$(type -P timeout)"
timeout_stub="${work_dir}/timeout"
cat >"${timeout_stub}" <<STUB
#!/bin/bash
dur=''
for arg in "\$@"; do
   case "\${arg}" in
      -*) ;;
      *) dur="\${arg}"; break ;;
   esac
done
printf '%s\n' "\${dur}" >>"\${TIMEOUT_ARG_LOG}"
exec "${real_timeout}" "\$@"
STUB
chmod 0755 "${timeout_stub}"
export PATH="${work_dir}:${PATH}"

## Reset per-case stub state to known defaults.
reset_stub() {
   true >"${probe_log}"
   true >"${timeout_arg_log}"
   export LEAPRUN_FAKE_RESULT=''
   export LEAPRUN_FAKE_DELAY='0'
   export LEAPRUN_READY_ON_CALL='0'
   unset system_ready_wait_max_seconds system_ready_probe_timeout 2>/dev/null || true
}

## Sourcing defines the pure function without running main.
# shellcheck disable=SC1090
source "${subject}"
if ! declare -F try_wait_for_system_ready >/dev/null; then
   printf '%s\n' "FATAL: sourcing the subject did not define try_wait_for_system_ready" >&2
   exit 1
fi

## 'running' (exit 0) -> return 0 after one probe, no wait.
reset_stub
export LEAPRUN_FAKE_RESULT='running'
rc=0
system_ready_wait_max_seconds=5 try_wait_for_system_ready || rc="$?"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '1' ]; then
   pass "'running' -> exit 0 after 1 probe"
else
   fail "'running' -> rc=${rc}, probes=${probe_calls} (want 0, 1)"
fi

## 'degraded' prints 'degraded' and exits NON-ZERO (as real is-system-running
## does) -> still accepted via the stdout line after one probe. Regression: a
## subject gating on leaprun's exit code would miss it and wait out the cap.
reset_stub
export LEAPRUN_FAKE_RESULT='degraded'
rc=0
system_ready_wait_max_seconds=5 try_wait_for_system_ready || rc="$?"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '1' ]; then
   pass "'degraded' (exit!=0) -> exit 0 after 1 probe"
else
   fail "'degraded' accepted -> rc=${rc}, probes=${probe_calls} (want 0, 1)"
fi

## system-ready-check merges systemctl's stderr into stdout, so a warning line
## can precede the state -> whole-line match still detects 'running'.
reset_stub
export LEAPRUN_FAKE_RESULT='Failed to acquire match for StartupFinished
running'
rc=0
system_ready_wait_max_seconds=5 try_wait_for_system_ready || rc="$?"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '1' ]; then
   pass "stderr-warning line + 'running' -> exit 0 after 1 probe"
else
   fail "multi-line result -> rc=${rc}, probes=${probe_calls} (want 0, 1)"
fi

## Becomes ready on the 3rd probe -> returns 0 after exactly 3 probes, proving
## it re-evaluates every iteration (not a cached first verdict).
reset_stub
export LEAPRUN_READY_ON_CALL='3'
rc=0
system_ready_wait_max_seconds=10 try_wait_for_system_ready || rc="$?"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '3' ]; then
   pass "ready on 3rd probe -> exit 0 after exactly 3 probes"
else
   fail "re-probe -> rc=${rc}, probes=${probe_calls} (want 0, 3)"
fi

## A non-ready, non-empty state ('starting', exit!=0) is NOT accepted: the loop
## keeps probing to the cap. Regression: a subject treating any non-empty output
## as ready returns after 1 probe.
reset_stub
export LEAPRUN_FAKE_RESULT='starting'
rc=0
system_ready_wait_max_seconds=2 try_wait_for_system_ready || rc="$?"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" -ge 2 ]; then
   pass "'starting' not accepted -> kept probing to cap (${probe_calls} probes)"
else
   fail "'starting' -> rc=${rc}, probes=${probe_calls} (want 0, >=2)"
fi

## A state that merely CONTAINS 'running' as a substring ('not-running') is NOT
## ready: the match is whole-line. Regression: a subject using an unanchored
## 'grep -E running|degraded' accepts it and returns after 1 probe.
reset_stub
export LEAPRUN_FAKE_RESULT='not-running'
rc=0
system_ready_wait_max_seconds=2 try_wait_for_system_ready || rc="$?"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" -ge 2 ]; then
   pass "'not-running' (substring) not accepted -> kept probing (${probe_calls} probes)"
else
   fail "'not-running' -> rc=${rc}, probes=${probe_calls} (want 0, >=2)"
fi

## CANARY (wall-clock): never ready, each probe SLOW (3s), cap 3s. A monotonic
## wall-clock cap runs ~1 probe and stops at ~4s; a loop that treats the cap as
## an iteration count runs cap probes = cap*3s (>=9s even with no sleep) -> over
## the upper bound. The old fixed count runs far longer still.
reset_stub
export LEAPRUN_FAKE_DELAY='3'
rc=0
t0="$(date +%s)"
system_ready_wait_max_seconds=3 try_wait_for_system_ready || rc="$?"
t1="$(date +%s)"
elapsed=$(( t1 - t0 ))
if [ "${rc}" = '0' ] && [ "${elapsed}" -ge 2 ] && [ "${elapsed}" -le 7 ]; then
   pass "wall-clock cap honoured -> exit 0 in ${elapsed}s (slow probe, cap=3)"
else
   fail "wall-clock cap -> rc=${rc}, elapsed=${elapsed}s (want 2..7)"
fi

## CANARY (probe-timeout): a probe that hangs (5s) with probe_timeout=1 and cap
## 1s must be bounded by the CONFIGURED timeout -> total ~2s (1s probe + 1s
## sleep). Regressions caught: an unbounded probe (~6s) and one that ignores the
## configured value and hardcodes a larger timeout (~4s) both exceed the bound.
reset_stub
export LEAPRUN_FAKE_DELAY='5'
rc=0
t0="$(date +%s)"
system_ready_wait_max_seconds=1 system_ready_probe_timeout=1 \
   try_wait_for_system_ready || rc="$?"
t1="$(date +%s)"
elapsed=$(( t1 - t0 ))
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" -ge 1 ] && [ "${elapsed}" -ge 1 ] && [ "${elapsed}" -le 3 ]; then
   pass "hung probe bounded by configured timeout -> exit 0 in ${elapsed}s (${probe_calls} probes)"
else
   fail "probe-timeout -> rc=${rc}, elapsed=${elapsed}s, probes=${probe_calls} (want 0, >=1, 1..3)"
fi

## Configured per-probe timeout is passed through verbatim. With max_seconds >
## probe_timeout the remaining-budget clamp (probe_this=min(probe_timeout,remaining))
## does not apply, so the recorded 'timeout' DURATION must equal the configured 2 --
## 'running' exits after one probe. Regression: a subject ignoring
## system_ready_probe_timeout (hardcoded literal) records a different value.
reset_stub
export LEAPRUN_FAKE_RESULT='running'
rc=0
system_ready_wait_max_seconds=5 system_ready_probe_timeout=2 \
   try_wait_for_system_ready || rc="$?"
recorded_timeout="$(head -n1 "${timeout_arg_log}")"
probe_calls="$(wc -l <"${probe_log}")"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '1' ] && [ "${recorded_timeout}" = '2' ]; then
   pass "configured probe timeout passed through -> 'timeout ${recorded_timeout}' (1 probe)"
else
   fail "configured timeout -> rc=${rc}, probes=${probe_calls}, timeout-arg='${recorded_timeout}' (want 0, 1, 2)"
fi

## Errexit contract: main() calls this under 'set -o errexit', so a never-ready
## run must RETURN 0, not abort on an internal command. errexit is ignored
## inside an if-condition / '&&'-'||' list, so assert it in a real child 'bash'
## where the function runs as a plain command at top level.
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
system_ready_wait_max_seconds=1 try_wait_for_system_ready
PROBE
reset_stub
rc=0
SUBJECT="${subject}" HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" PATH="${PATH}" \
   LEAPRUN_PROBE_LOG="${probe_log}" LEAPRUN_FAKE_RESULT='' \
   bash "${errexit_probe}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" = '0' ]; then
   pass "never-ready run returns cleanly under errexit (child process)"
else
   fail "aborted under errexit (rc=${rc})"
fi

printf '%s\n' ""
printf '%s\n' "===== try_wait_for_system_ready: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
