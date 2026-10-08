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

## sleep stub: no-op, so the 120-iteration timeout path is instant.
cat > "${stub_bin}/sleep" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod 0755 -- "${stub_bin}/sleep"

## systemctl stub: prints the ActiveState given by TEST_PRIVLEAPD_STATE,
## mimicking 'systemctl show ... --property ActiveState'.
cat > "${stub_bin}/systemctl" <<'STUB'
#!/bin/bash
printf 'ActiveState=%s\n' "${TEST_PRIVLEAPD_STATE:-activating}"
STUB
chmod 0755 -- "${stub_bin}/systemctl"

run_with_state() {
   local state="$1" rc=0
   TEST_PRIVLEAPD_STATE="${state}" PATH="${stub_bin}:${PATH}" bash "${subject}" >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

## active -> success (0)
rc="$( run_with_state active )"
if [ "${rc}" = '0' ]; then
   pass "active -> exit 0"
else
   fail "active -> exit ${rc}, expected 0"
fi

## failed -> exit 0 (best-effort contract; the caller handles privleapd's absence)
rc="$( run_with_state failed )"
if [ "${rc}" = '0' ]; then
   pass "failed -> exit 0 (best-effort contract)"
else
   fail "failed -> exit ${rc}, expected 0 (best-effort contract)"
fi

## never terminal (timeout) -> exit 0 (best-effort contract)
rc="$( run_with_state activating )"
if [ "${rc}" = '0' ]; then
   pass "timeout -> exit 0 (best-effort contract)"
else
   fail "timeout -> exit ${rc}, expected 0 (best-effort contract)"
fi

printf '%s\n' ""
printf '%s\n' "===== try_wait_for_privleapd_service_running: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
