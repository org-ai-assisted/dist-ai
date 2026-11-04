#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression suite for onion-tester-configure-tor's torrc idempotency, its
## never-duplicate-ControlPort rule, and its concurrency lock. The REAL script is
## driven OFFLINE via its overridable bases (ONION_TESTER_TORRC / _PRIV_CMD /
## _TOR_RESTART_BIN / _CONFIGURE_LOCK) -- no sudo, no systemd, no tor -- so it runs
## in the dist-ai container in seconds.
##   1. empty torrc                 -> appends the full block (ControlPort + cookie), restarts.
##   2. fully configured            -> skips the append (no change), still restarts.
##   3. ControlPort present, cookie MISSING -> adds cookie WITHOUT a 2nd ControlPort.
##      (A duplicate ControlPort parses but fails tor's runtime bind, so the port
##      would be down after the restart.) Canary: ControlPort-only-keyed code skips
##      and leaves cookie auth missing -> stem auth fails.
##   4. marker kept, ControlPort DROPPED -> re-adds exactly one ControlPort. Canary:
##      marker-keyed code skips, leaving the port missing -> runner exit 4.
##   5. two concurrent runs vs an empty torrc -> exactly ONE ControlPort. Canary:
##      without the flock both add ControlPort -> two -> tor fails to bind.

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
lock_dir="${work_dir}/lockdir"
mkdir --parents -- "${lock_dir}"
restart_log="${work_dir}/restart-log"

## restart mock: records each (re)start so a case can assert tor was restarted,
## without a real systemctl.
cat > "${work_dir}/mock-restart" <<EOF
#!/bin/bash
printf '%s\n' restart >> "${restart_log}"
EOF
## priv wrapper that SLOWS the torrc ops (grep, tee) to widen the check->append
## window, so case 5 deterministically exposes a missing lock. execs the real
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
   ONION_TESTER_CONFIGURE_LOCK_DIR="${lock_dir}" \
   "${subject}"
}

## Count non-commented `ControlPort 9051` directives in the torrc.
control_port_count() {
   grep --count --extended-regexp -- \
      '^[[:space:]]*ControlPort[[:space:]]+9051([[:space:]]|$)' "${torrc}" 2>/dev/null || true
}

cookie_present() {
   if grep --quiet --extended-regexp -- \
      '^[[:space:]]*CookieAuthentication[[:space:]]+1([[:space:]]|$)' "${torrc}" 2>/dev/null; then
      printf '%s' y
   else
      printf '%s' n
   fi
}

restarted() { if [ -s "${restart_log}" ]; then printf '%s' y; else printf '%s' n; fi; }

# 1. empty/absent torrc -> appends full block (ControlPort once + cookie), restarts.
## torrc absent after safe-rm; configure-tor's grep tolerates that and tee creates it.
safe-rm --force -- "${torrc}" "${restart_log}"
rc=0
out="$(run_configure 2>&1)" || rc=$?
if [ "${rc}" = 0 ] && [ "$(control_port_count)" = 1 ] && [ "$(cookie_present)" = y ] && [ "$(restarted)" = y ]; then
   pass 'empty torrc: appends ControlPort + cookie once, restarts'
else
   fail "empty torrc: rc=${rc} cp=$(control_port_count) cookie=$(cookie_present) restart=$(restarted); out: ${out}"
fi

# 2. fully configured -> skip (no change), still restarts.
safe-rm --force -- "${restart_log}"
rc=0
out="$(run_configure 2>&1)" || rc=$?
saw_skip=0
case "${out}" in *'not appending again'*) saw_skip=1 ;; esac
if [ "${rc}" = 0 ] && [ "$(control_port_count)" = 1 ] && [ "$(cookie_present)" = y ] \
   && [ "${saw_skip}" = 1 ] && [ "$(restarted)" = y ]; then
   pass 're-run fully configured: no change, still restarts'
else
   fail "idempotent re-run: rc=${rc} cp=$(control_port_count) cookie=$(cookie_present) skip=${saw_skip}; out: ${out}"
fi

# 3. ControlPort present but cookie MISSING -> add cookie, NO duplicate ControlPort.
safe-rm --force -- "${torrc}" "${restart_log}"
printf '%s\n' 'ControlPort 9051' > "${torrc}"
rc=0
out="$(run_configure 2>&1)" || rc=$?
if [ "${rc}" = 0 ] && [ "$(control_port_count)" = 1 ] && [ "$(cookie_present)" = y ] && [ "$(restarted)" = y ]; then
   pass 'ControlPort present, cookie missing: adds cookie without a 2nd ControlPort'
else
   fail "cookie-heal: rc=${rc} cp=$(control_port_count) cookie=$(cookie_present); out: ${out}"
fi

# 4. marker kept but ControlPort DROPPED -> re-adds exactly one ControlPort.
safe-rm --force -- "${torrc}" "${restart_log}"
printf '%s\n' '## Added by local-onion-tester.yml' 'CookieAuthentication 1' \
   'CookieAuthFileGroupReadable 1' > "${torrc}"
rc=0
out="$(run_configure 2>&1)" || rc=$?
if [ "${rc}" = 0 ] && [ "$(control_port_count)" = 1 ] && [ "$(cookie_present)" = y ]; then
   pass 'marker kept, ControlPort dropped: re-adds exactly one ControlPort'
else
   fail "controlport-heal: rc=${rc} cp=$(control_port_count) cookie=$(cookie_present); out: ${out}"
fi

# 5. two concurrent runs vs an empty torrc -> exactly one ControlPort (flock).
safe-rm --force -- "${torrc}" "${restart_log}"
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
