#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression suite for onion-tester-configure-tor's torrc idempotency + its
## concurrency lock. The REAL script is driven OFFLINE via its overridable bases
## (ONION_TESTER_TORRC / _PRIV_CMD / _TOR_RESTART_BIN / _CONFIGURE_LOCK) -- no sudo,
## no systemd, no tor -- so it runs in the dist-ai container in seconds.
##   1. empty torrc            -> appends the block, ControlPort present once, restarts.
##   2. ControlPort present     -> skips the append (no duplicate), still restarts.
##   3. marker kept, ControlPort DROPPED -> RE-heals (ControlPort back). Canary: the
##      marker-keyed old code skipped, leaving the port missing -> runner exit 4.
##   4. two concurrent runs vs an empty torrc -> exactly ONE ControlPort. Canary:
##      without the flock the grep/append TOCTOU double-appends -> two.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

payload_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject="${ONION_TESTER_CONFIGURE_TOR_BIN:-${payload_dir}/../../bin/onion-tester-configure-tor}"
work_dir=""
passed=0
failed=0

# shellcheck disable=SC2317  ## reached via the EXIT trap
cleanup() { [ -n "${work_dir}" ] && safe-rm --recursive --force -- "${work_dir}"; }

pass() { passed=$(( passed + 1 )); printf '%s\n' "PASS: $1"; }
fail() { failed=$(( failed + 1 )); printf '%s\n' "FAIL: $1" >&2; }

[ -f "${subject}" ] || { printf '%s\n' "FAIL: onion-tester-configure-tor not found at ${subject}" >&2; exit 1; }

work_dir="$(mktemp --directory)"
trap cleanup EXIT

torrc="${work_dir}/torrc"
lock="${work_dir}/lock"
restart_log="${work_dir}/restart-log"

## restart mock: records each (re)start so a case can assert tor was restarted,
## without a real systemctl.
cat > "${work_dir}/mock-restart" <<EOF
#!/bin/bash
printf 'restart\n' >> "${restart_log}"
EOF
## priv wrapper that SLOWS the torrc ops (grep, tee) to widen the check->append
## window, so case 4 deterministically exposes a missing lock. execs the real
## command otherwise (no sudo).
cat > "${work_dir}/slow-priv" <<'EOF'
#!/bin/bash
sleep 0.4
exec "$@"
EOF
chmod +x "${work_dir}/mock-restart" "${work_dir}/slow-priv"

## Run the REAL configure-tor offline. $1 (optional) = priv command (default: none).
run_configure() {
   ALLOW_LOCAL=true \
   ONION_TESTER_TORRC="${torrc}" \
   ONION_TESTER_PRIV_CMD="${1-}" \
   ONION_TESTER_TOR_RESTART_BIN="${work_dir}/mock-restart" \
   ONION_TESTER_CONFIGURE_LOCK="${lock}" \
   "${subject}"
}

## Count non-commented `ControlPort 9051` directives in the torrc.
control_port_count() {
   grep --count --extended-regexp -- \
      '^[[:space:]]*ControlPort[[:space:]]+9051([[:space:]]|$)' "${torrc}" 2>/dev/null || true
}

restarted() { if [ -s "${restart_log}" ]; then printf '%s' y; else printf '%s' n; fi; }

# 1. empty torrc -> appends, ControlPort present once, restart recorded.
## torrc absent after safe-rm; configure-tor's grep tolerates that and tee creates it.
safe-rm --force -- "${torrc}" "${restart_log}"
rc=0
out="$(run_configure 2>&1)" || rc=$?
if [ "${rc}" = 0 ] && [ "$(control_port_count)" = 1 ] && [ "$(restarted)" = y ]; then
   pass 'empty torrc: appends ControlPort once and restarts'
else
   fail "empty torrc: rc=${rc} count=$(control_port_count) restart=$(restarted); out: ${out}"
fi

# 2. ControlPort already present -> skip append (still exactly one), still restarts.
safe-rm --force -- "${restart_log}"
rc=0
out="$(run_configure 2>&1)" || rc=$?
saw_already=0
case "${out}" in *'already has'*) saw_already=1 ;; esac
if [ "${rc}" = 0 ] && [ "$(control_port_count)" = 1 ] && [ "${saw_already}" = 1 ] && [ "$(restarted)" = y ]; then
   pass 're-run with ControlPort present: no duplicate, still restarts'
else
   fail "idempotent re-run: rc=${rc} count=$(control_port_count) restart=$(restarted); out: ${out}"
fi

# 3. marker kept but ControlPort DROPPED -> must RE-heal (Finding 1).
safe-rm --force -- "${torrc}" "${restart_log}"
printf '%s\n' '## Added by local-onion-tester.yml' 'CookieAuthentication 1' > "${torrc}"
rc=0
out="$(run_configure 2>&1)" || rc=$?
if [ "${rc}" = 0 ] && [ "$(control_port_count)" -ge 1 ]; then
   pass 'marker kept, ControlPort dropped: re-heals (ControlPort restored)'
else
   fail "re-heal on dropped ControlPort: rc=${rc} count=$(control_port_count); out: ${out}"
fi

# 4. two concurrent runs vs an empty torrc -> exactly one ControlPort (Finding 2).
safe-rm --force -- "${torrc}" "${restart_log}" "${lock}"
rc_a=0
rc_b=0
run_configure "${work_dir}/slow-priv" > /dev/null 2>&1 &
pid_a=$!
run_configure "${work_dir}/slow-priv" > /dev/null 2>&1 &
pid_b=$!
wait "${pid_a}" || rc_a=$?
wait "${pid_b}" || rc_b=$?
if [ "$(control_port_count)" = 1 ] && [ "${rc_a}" = 0 ] && [ "${rc_b}" = 0 ]; then
   pass 'concurrent runs: flock serializes -> exactly one ControlPort'
else
   fail "concurrent double-append guard: count=$(control_port_count) rc_a=${rc_a} rc_b=${rc_b} (want count=1)"
fi

printf '%s\n' "" "===== onion-tester configure-tor: ${passed} pass, ${failed} fail ====="
[ "${failed}" -eq 0 ]
