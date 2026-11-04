#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression suite for onion-tester-run's Tor control-port PREFLIGHT. Without a
## reachable control port the probe's time-sanity check cannot run and EVERY URL
## falls back to REACHABLE-but-INVALID -- a bogus "0 ONLINE" that reads as "all
## onions dead". The preflight must refuse to emit that verdict:
##   A. CI + control DOWN           -> exit 4, probe NEVER runs (no false verdict).
##   B. local + self-heal FIXES it  -> probe runs, exit 0 (safe path by default).
##   C. local + self-heal does NOT  -> exit 4, probe NEVER runs.
##   D. control UP from the start   -> probe runs, exit 0 (no self-heal).
##   E. local + non-default port    -> refuse self-heal BEFORE restart: exit 4,
##                                     configure-tor never invoked, probe NEVER runs.
## All mocked: no Tor, no network, seconds. Canary: pre-preflight onion-tester-run
## runs the probe regardless, so A/C would emit a verdict (exit 0/1), not exit 4; and
## pre-guard code would invoke configure-tor in E and probe, not exit 4.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

payload_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
runner="${ONION_TESTER_RUN_BIN:-${payload_dir}/../../bin/onion-tester-run}"
work_dir=""
passed=0
failed=0

# shellcheck disable=SC2317  ## reached via the EXIT trap
cleanup() { [ -n "${work_dir}" ] && safe-rm --recursive --force -- "${work_dir}"; }

pass() { passed=$(( passed + 1 )); printf '%s\n' "PASS: $1"; }
fail() { failed=$(( failed + 1 )); printf '%s\n' "FAIL: $1" >&2; }

[ -f "${runner}" ] || { printf '%s\n' "FAIL: onion-tester-run not found at ${runner}" >&2; exit 1; }

work_dir="$(mktemp --directory)"
trap cleanup EXIT

## control-check command: "up" iff the state flag exists (configure-tor mock
## creates it to simulate a healed Tor). Invoked by onion-tester-run with no args.
cat > "${work_dir}/control-check" <<'EOF'
#!/bin/bash
[ -f "${CONTROL_STATE}/up" ]
EOF

## probe mock: records that it ran (so a test can assert it did NOT), prints a
## verdict line, exits 0. If it runs in case A/C the preflight failed to refuse.
cat > "${work_dir}/mock-probe" <<'EOF'
#!/bin/bash
: > "${PROBE_RAN}"
printf 'pool 0 url http://example.onion: ONLINE\n'
exit 0
EOF

## configure-tor mock that HEALS: creates the control flag, exit 0.
cat > "${work_dir}/mock-configure-heal" <<'EOF'
#!/bin/bash
: > "${CONTROL_STATE}/up"
EOF

## configure-tor mock that does NOT heal (exit 0 but leaves the port down).
cat > "${work_dir}/mock-configure-noheal" <<'EOF'
#!/bin/bash
exit 0
EOF

## configure-tor mock that RECORDS it ran AND heals. For the non-default-port refuse
## case: if the guard works it is NEVER invoked (flag stays absent); on the pre-guard
## code it runs (flag present) -- that flag IS the canary for the regression.
cat > "${work_dir}/mock-configure-record" <<'EOF'
#!/bin/bash
: > "${CONFIGURE_RAN}"
: > "${CONTROL_STATE}/up"
EOF

## wait-bootstrap mock: no-op success.
cat > "${work_dir}/mock-wait" <<'EOF'
#!/bin/bash
exit 0
EOF

chmod +x "${work_dir}/control-check" "${work_dir}/mock-probe" \
   "${work_dir}/mock-configure-heal" "${work_dir}/mock-configure-noheal" \
   "${work_dir}/mock-configure-record" "${work_dir}/mock-wait"

## Run onion-tester-run with the preflight wired to mocks. $1=configure-tor mock.
## Returns the runner rc; sets globals out/ran for assertions.
out=""
ran=""
configured=""
state="${work_dir}/state"
configure_ran="${work_dir}/configure-ran"
run_case() { ## run_case <configure-mock> ; env (CI / control-up / CTRL_PORT) set by caller
   safe-rm --recursive --force -- "${state}"
   mkdir --parents -- "${state}"
   [ "${PRESET_UP:-0}" = 1 ] && touch -- "${state}/up"
   local probe_ran="${work_dir}/probe-ran"
   safe-rm --force -- "${probe_ran}" "${configure_ran}"
   local rc=0
   out="$(
      CONTROL_STATE="${state}" PROBE_RAN="${probe_ran}" \
      CONFIGURE_RAN="${configure_ran}" \
      ONION_TESTER_CONTROL_PORT="${CTRL_PORT:-9051}" \
      ALLOW_LOCAL="${ALLOW_LOCAL:-true}" CI="${CI:-}" \
      ONION_TESTER_BIN="${work_dir}/mock-probe" \
      ONION_TESTER_CONTROL_CHECK="${work_dir}/control-check" \
      ONION_TESTER_CONFIGURE_TOR_BIN="$1" \
      ONION_TESTER_WAIT_BOOTSTRAP_BIN="${work_dir}/mock-wait" \
      ONION_TESTER_WARMUP_MAX=0 \
      ONION_TESTER_ATTEMPTS=1 \
      ONION_TESTER_DEADLINE=600 \
      "${runner}" 2>&1
   )" && rc=0 || rc=$?
   [ -f "${probe_ran}" ] && ran=1 || ran=0
   [ -f "${configure_ran}" ] && configured=1 || configured=0
   return "${rc}"
}

# A. CI + control DOWN -> exit 4, probe never runs.
rc=0
CI=true ALLOW_LOCAL='' PRESET_UP=0 run_case "${work_dir}/mock-configure-heal" || rc=$?
if [ "${rc}" = 4 ] && [ "${ran}" = 0 ]; then
   pass 'CI + control down: exits 4 and never probes (no bogus verdict)'
else
   fail "CI + control down: rc=${rc} ran=${ran} (want rc=4, ran=0); out: ${out}"
fi

# B. local + self-heal FIXES the port -> probe runs, exit 0.
rc=0
CI='' ALLOW_LOCAL=true PRESET_UP=0 run_case "${work_dir}/mock-configure-heal" || rc=$?
if [ "${rc}" = 0 ] && [ "${ran}" = 1 ]; then
   pass 'local + self-heal fixes it: probe runs, exit 0'
else
   fail "local self-heal success: rc=${rc} ran=${ran} (want rc=0, ran=1); out: ${out}"
fi

# C. local + self-heal does NOT fix the port -> exit 4, probe never runs.
rc=0
CI='' ALLOW_LOCAL=true PRESET_UP=0 run_case "${work_dir}/mock-configure-noheal" || rc=$?
if [ "${rc}" = 4 ] && [ "${ran}" = 0 ]; then
   pass 'local + self-heal fails: exits 4 and never probes'
else
   fail "local self-heal failure: rc=${rc} ran=${ran} (want rc=4, ran=0); out: ${out}"
fi

# D. control UP from the start -> probe runs, exit 0, no self-heal needed.
rc=0
CI='' ALLOW_LOCAL=true PRESET_UP=1 run_case "${work_dir}/mock-configure-noheal" || rc=$?
if [ "${rc}" = 0 ] && [ "${ran}" = 1 ]; then
   pass 'control up: probe runs, exit 0'
else
   fail "control up: rc=${rc} ran=${ran} (want rc=0, ran=1); out: ${out}"
fi

# E. local + control DOWN + non-default port -> refuse BEFORE the self-heal:
#    configure-tor (which hardcodes 9051 and cannot heal a custom port) is NEVER
#    invoked, exit 4, probe never runs. Canary: the pre-guard code invokes
#    configure-tor (configured=1), heals the mock's up-flag, and exits 0 probing.
rc=0
CI='' ALLOW_LOCAL=true PRESET_UP=0 CTRL_PORT=9151 \
   run_case "${work_dir}/mock-configure-record" || rc=$?
if [ "${rc}" = 4 ] && [ "${configured}" = 0 ] && [ "${ran}" = 0 ]; then
   pass 'non-default control port: refuses self-heal (no restart), exits 4, never probes'
else
   fail "non-default port refuse: rc=${rc} configured=${configured} ran=${ran} (want rc=4, configured=0, ran=0); out: ${out}"
fi

printf '%s\n' "" "===== onion-tester control preflight: ${passed} pass, ${failed} fail ====="
[ "${failed}" -eq 0 ]
