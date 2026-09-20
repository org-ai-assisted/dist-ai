#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for helper-scripts try-wait-for-tor-service-running.
##
## THE BUG: the script had no 'exit' anywhere, so its status was whatever the
## last command returned -- 'break' (0) on BOTH the active AND the failed branch,
## and the loop tail (0) on timeout. It could NEVER report failure: a caller
## gating on it ('if try-wait-...; then') proceeded as if Tor was up even when
## tor@default.service had failed or never came up. Fix: exit 0 only on active;
## non-zero on failed and on timeout (fail closed -- anonymity-relevant).
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
[ "${rc}" = "0" ] && pass "active -> exit 0" || fail "active -> exit ${rc}, expected 0"

## failed -> non-zero (fail closed)
rc="$( run_with_state failed )"
[ "${rc}" != "0" ] && pass "failed -> non-zero exit (${rc}); a gate must not proceed" \
   || fail "failed -> exit 0 (fail-open: a gate would proceed with Tor down)"

## never terminal (timeout) -> non-zero (fail closed)
rc="$( run_with_state activating )"
[ "${rc}" != "0" ] && pass "timeout -> non-zero exit (${rc})" \
   || fail "timeout -> exit 0 (fail-open)"

printf '%s\n' ""
printf '%s\n' "===== try_wait_for_tor: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
