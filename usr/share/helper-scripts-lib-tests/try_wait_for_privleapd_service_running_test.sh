#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Contract test for helper-scripts try-wait-for-privleapd-service-running.
##
## By DESIGN this is a BEST-EFFORT wait: it blocks until privleapd.service is
## either active OR determinably never-going-to-start (failed), then exits 0 in
## every case ("No 'exit 1' by design"). The caller handles privleapd's absence;
## the real consumer (try-wait-for-privleap-socket-ready) invokes it as
## '... || true'. This asserts that contract on the active, failed, and timeout
## paths alike.
##
## Drives the REAL script with 'systemctl' and 'sleep' stubbed on PATH (so the
## 120-iteration timeout path is instant). No root, no systemd, no privleapd.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/try-wait-for-privleapd-service-running"
else
   subject='/usr/libexec/helper-scripts/try-wait-for-privleapd-service-running'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}' (set HELPER_SCRIPTS_REPO)." >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$((pass_count + 1)); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$((fail_count + 1)); printf '%s\n' "FAIL: $*" >&2; }

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT
stub_bin="${work_dir}/bin"
mkdir --parents -- "${stub_bin}"
args_log="${work_dir}/systemctl.args"

## sleep stub: no-op, so the 120-iteration timeout path is instant.
cat > "${stub_bin}/sleep" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod 0755 -- "${stub_bin}/sleep"

## systemctl stub: logs its args (so a test can confirm WHICH unit was queried)
## and prints the LoadState/ActiveState given by the TEST_PRIVLEAPD_* env,
## mimicking 'systemctl show ... --property LoadState --property ActiveState'.
cat > "${stub_bin}/systemctl" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${SYSTEMCTL_ARGS_LOG:-/dev/null}"
printf 'LoadState=%s\n' "${TEST_PRIVLEAPD_LOADSTATE:-loaded}"
printf 'ActiveState=%s\n' "${TEST_PRIVLEAPD_STATE:-activating}"
STUB
chmod 0755 -- "${stub_bin}/systemctl"

## Drives the REAL subject with 'systemctl'/'sleep' stubbed and the args log
## captured, returning 'rc calls' so a case can assert BOTH the exit status and
## the systemctl call count. 'sleep' is a no-op, so the count (not wall time)
## distinguishes an immediate break from the full bounded wait.
run_with_state() {
   local state="$1" rc=0 calls
   ## Truncate-or-CREATE: a buggy subject that returns before any systemctl poll
   ## leaves no log, and 'wc -l < absent' under errexit would abort the whole
   ## script (silent, no FAIL line) instead of reporting a clean 0-poll failure.
   true >| "${args_log}"
   TEST_PRIVLEAPD_STATE="${state}" SYSTEMCTL_ARGS_LOG="${args_log}" \
      PATH="${stub_bin}:${PATH}" bash "${subject}" >/dev/null 2>&1 || rc="$?"
   calls="$(wc -l < "${args_log}")"
   printf '%s %s' "${rc}" "${calls}"
}

## active -> success (0), breaking on the first poll
result="$( run_with_state active )"
rc="${result%% *}"
calls="${result##* }"
if [ "${rc}" = '0' ] && [ "${calls}" -eq 1 ]; then
   pass "active -> exit 0 (${calls} systemctl call(s))"
else
   fail "active -> rc=${rc}, ${calls} call(s); expected 0 and immediate break"
fi

## failed -> exit 0 (best-effort contract; the caller handles privleapd's
## absence), breaking on the first poll
result="$( run_with_state failed )"
rc="${result%% *}"
calls="${result##* }"
if [ "${rc}" = '0' ] && [ "${calls}" -eq 1 ]; then
   pass "failed -> exit 0 (best-effort contract, ${calls} systemctl call(s))"
else
   fail "failed -> rc=${rc}, ${calls} call(s); expected 0 and immediate break"
fi

## Never terminal -> exit 0 (best-effort) only AFTER the full bounded wait.
## Asserting rc=0 alone is vacuous: a subject that polled once and returned 0
## would pass too. Pin the systemctl call count to the full 120-iteration loop
## bound, which proves it actually timed out instead of returning early.
result="$( run_with_state activating )"
rc="${result%% *}"
calls="${result##* }"
if [ "${rc}" = '0' ] && [ "${calls}" -eq 120 ]; then
   pass "timeout -> exit 0 after the full ${calls}-poll bounded wait"
else
   fail "timeout -> rc=${rc}, ${calls} poll(s); expected 0 after 120 polls"
fi

## Confirms the subject queries privleapd.service (not a copied unit name) and
## that an unrunnable unit (LoadState=not-found) breaks on the first poll instead
## of waiting out the whole loop. 'sleep' is stubbed, so the systemctl CALL COUNT
## (not wall time) distinguishes an immediate break from a 120-iteration loop.
true >| "${args_log}"
rc=0
TEST_PRIVLEAPD_LOADSTATE='not-found' TEST_PRIVLEAPD_STATE='inactive' \
   SYSTEMCTL_ARGS_LOG="${args_log}" PATH="${stub_bin}:${PATH}" bash "${subject}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" = '0' ]; then
   pass "LoadState=not-found -> exit 0"
else
   fail "LoadState=not-found -> exit ${rc}, expected 0"
fi
if grep --quiet -- 'privleapd.service' "${args_log}"; then
   pass "queries privleapd.service"
else
   fail "did not query privleapd.service (args: $(cat -- "${args_log}"))"
fi
calls="$(wc -l < "${args_log}")"
if [ "${calls}" -eq 1 ]; then
   pass "LoadState=not-found breaks immediately (${calls} systemctl call(s))"
else
   fail "LoadState=not-found looped (${calls} systemctl calls), expected immediate break"
fi

## bad-setting (an unparsable unit that will not start) is also terminal.
true >| "${args_log}"
rc=0
TEST_PRIVLEAPD_LOADSTATE='bad-setting' TEST_PRIVLEAPD_STATE='inactive' \
   SYSTEMCTL_ARGS_LOG="${args_log}" PATH="${stub_bin}:${PATH}" bash "${subject}" >/dev/null 2>&1 || rc="$?"
calls="$(wc -l < "${args_log}")"
if [ "${rc}" = '0' ] && [ "${calls}" -eq 1 ]; then
   pass "LoadState=bad-setting breaks immediately (${calls} systemctl call(s))"
else
   fail "LoadState=bad-setting -> rc=${rc}, ${calls} call(s); expected 0 and immediate break"
fi

printf '%s\n' ""
printf '%s\n' "===== try_wait_for_privleapd_service_running: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
