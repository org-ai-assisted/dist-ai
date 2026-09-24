#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Contract test for helper-scripts try-wait-for-tor-service-running.
##
## By DESIGN this is a BEST-EFFORT wait: it blocks until Tor is either active OR
## determinably never-going-to-start, then exits 0 in every case. The shipped
## script documents this itself ("No 'exit 1' by design ... ALWAYS exits 0 ... A
## caller MUST NOT gate on the exit code ... Do not add 'exit 1' on the
## failed/timeout paths"). Handling Tor's absence is the CALLER's responsibility,
## and the real callers do not gate on the exit code: qubes.UpdatesProxy.anondist
## runs 'try-wait-... || true', and the uwt dnf-3.anondist path invokes it as a
## bare statement. This asserts that contract: exit 0 on the active, failed, and
## timeout paths alike. Restoring a fail-closed exit non-zero would diverge the
## test from the shipped script, which explicitly prohibits it.
##
## Drives the REAL script with 'systemctl' and 'sleep' stubbed on PATH (so the
## timeout path is instant). No root, no systemd, no Tor.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/try-wait-for-tor-service-running"
else
   subject='/usr/libexec/helper-scripts/try-wait-for-tor-service-running'
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

## systemctl stub: prints the ActiveState given by TEST_TOR_STATE, mimicking
## 'systemctl show ... --property ActiveState'.
cat > "${stub_bin}/systemctl" <<'STUB'
#!/bin/bash
printf 'ActiveState=%s\n' "${TEST_TOR_STATE:-activating}"
STUB
chmod 0755 -- "${stub_bin}/systemctl"

run_with_state() {
   local state="$1" rc=0
   TEST_TOR_STATE="${state}" PATH="${stub_bin}:${PATH}" bash "${subject}" >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

## active -> success (0)
rc="$( run_with_state active )"
# shellcheck disable=SC2015  # pass returns 0, so fail runs only on the test's failure
[ "${rc}" = "0" ] && pass "active -> exit 0" || fail "active -> exit ${rc}, expected 0"

## failed -> exit 0 (best-effort contract; the caller handles Tor's absence)
rc="$( run_with_state failed )"
# shellcheck disable=SC2015  # pass returns 0, so fail runs only on the test's failure
[ "${rc}" = "0" ] && pass "failed -> exit 0 (best-effort contract)" \
   || fail "failed -> exit ${rc}, expected 0 (best-effort contract)"

## never terminal (timeout) -> exit 0 (best-effort contract)
rc="$( run_with_state activating )"
# shellcheck disable=SC2015  # pass returns 0, so fail runs only on the test's failure
[ "${rc}" = "0" ] && pass "timeout -> exit 0 (best-effort contract)" \
   || fail "timeout -> exit ${rc}, expected 0 (best-effort contract)"

printf '%s\n' ""
printf '%s\n' "===== try_wait_for_tor: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
