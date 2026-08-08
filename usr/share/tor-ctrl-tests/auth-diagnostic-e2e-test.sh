#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## login() must REACH its diagnostics, and authenticate when it can.
##
## The failure this guards against is silent: login() derives the offered auth
## methods through greps inside command substitutions, and a no-match grep is the
## NORMAL case for a method tor does not offer. Under 'set -o errexit -o pipefail'
## an unguarded one aborts the script, so the "Authentication method not detected"
## block -- which exists precisely for that case -- became unreachable and the
## user got a bare non-zero with no explanation.
##
## Exit status alone cannot see this: a deliberate error_msg and an errexit abort
## both exit 1. Every case therefore asserts the MESSAGE, not just the status.
##
## Starts its OWN tor on a private DataDirectory and ControlPort with
## DisableNetwork -- never a system tor, never the network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

work_dir=""
tor_pid=""

cleanup() {
   trap "" EXIT
   [ -z "${tor_pid}" ] || kill "${tor_pid}" 2>/dev/null || true
   [ -z "${work_dir}" ] || safe-rm --recursive --force -- "${work_dir}"
   return 0
}

trap cleanup EXIT

[ -v TOR_CTRL_REPO ] || TOR_CTRL_REPO=""
if [ -n "${TOR_CTRL_REPO}" ]; then
   bin_dir="${TOR_CTRL_REPO}/usr/bin"
else
   bin_dir="/usr/bin"
fi

if [ ! -x "${bin_dir}/tor-ctrl" ]; then
   printf '%s\n' "SKIP: tor-ctrl not found at '${bin_dir}/tor-ctrl'" >&2
   exit 77
fi

PATH="${bin_dir}:${PATH}"
export PATH

for dependency in tor nc socat; do
   if ! type -P "${dependency}" >/dev/null; then
      printf '%s\n' "FAIL: required program '${dependency}' is not installed" >&2
      exit 1
   fi
done

failures=0
checks=0

check() {
   local label="${1}"
   local expected="${2}"
   local actual="${3}"
   checks=$(( checks + 1 ))
   if [ "${expected}" = "${actual}" ]; then
      printf '%s\n' "PASS  ${label} (${actual})"
   else
      failures=$(( failures + 1 ))
      printf '%s\n' "FAIL  ${label}: expected '${expected}', got '${actual}'"
   fi
}

last_output=""
last_status=0

## Set in THIS shell: a command substitution would discard the captured output.
run_tor_ctrl() {
   last_status=0
   last_output="$( env --unset=TOR_CONTROL_HOST --unset=TOR_CONTROL_PORT \
      "${bin_dir}/tor-ctrl" "$@" 2>&1 )" || last_status=$?
}

expect_text() {
   local label="${1}"
   local want_text="${2}"
   if printf '%s' "${last_output}" | grep -qF -- "${want_text}"; then
      check "${label}" "found" "found"
   else
      check "${label}" "found" "missing: ${last_output:0:70}"
   fi
}

start_tor() {
   local auth_line="${1}"
   work_dir="$(mktemp --directory)"
   mkdir --parents -- "${work_dir}/data"
   chmod 0700 -- "${work_dir}/data"

   cat > "${work_dir}/torrc" <<EOF
DataDirectory ${work_dir}/data
ControlPort auto
ControlPortWriteToFile ${work_dir}/control.port
${auth_line}
SocksPort 0
DisableNetwork 1
Log notice file ${work_dir}/tor.log
EOF

   tor --quiet -f "${work_dir}/torrc" &
   tor_pid=$!

   local waited=0
   until [ -s "${work_dir}/control.port" ]; do
      sleep 1
      waited=$(( waited + 1 ))
      if [ "${waited}" -ge 60 ]; then
         printf '%s\n' "FAIL: tor did not open its control port within 60s" >&2
         cat -- "${work_dir}/tor.log" >&2 || true
         exit 1
      fi
   done
   control_port="$(sed 's/.*://' -- "${work_dir}/control.port" | tr -d '\r\n')"
}

stop_tor() {
   [ -z "${tor_pid}" ] || kill "${tor_pid}" 2>/dev/null || true
   tor_pid=""
   [ -z "${work_dir}" ] || safe-rm --recursive --force -- "${work_dir}"
   work_dir=""
}

## 1. HASHEDPASSWORD offered and supplied -- the success path.
control_password="tor-ctrl-auth-test-${$}"
start_tor "HashedControlPassword $(tor --hash-password "${control_password}" | tail -n 1)"
run_tor_ctrl -s "${control_port}" -p "${control_password}" -c "GETINFO version"
check "password auth: exit status" "0" "${last_status}"
expect_text "password auth: controller answered" "250-version="

## 2. HASHEDPASSWORD offered, NO password given. login() must reach its
##    diagnostic and name the reason.
##
##    NOT the errexit regression case, despite looking like one: tor does answer
##    with an 'AUTH METHODS=' line here, so the grep that extracts it MATCHES and
##    nothing aborts. Verified by running this case against the unguarded code --
##    it passes there too. Case 5 is the one that catches it. Keeping this case
##    anyway: it pins the branch that decides WHICH method is usable, and the
##    wording the user is told to act on.
run_tor_ctrl -s "${control_port}" -c "GETINFO version"
check "no password supplied: exit status" "1" "${last_status}"
expect_text "no password supplied: says the method was not detected" \
   "Authentication method not detected"
expect_text "no password supplied: names HASHEDPASSWORD as the reason" \
   "HASHEDPASSWORD is enabled but no password provided"

## 3. Wrong password: tor rejects the AUTHENTICATE, and the failure must surface.
run_tor_ctrl -s "${control_port}" -p "definitely-not-the-password" -c "GETINFO version"
check "wrong password: exit status is non-zero" "nonzero" \
   "$( [ "${last_status}" -ne 0 ] && printf 'nonzero' || printf '0' )"
expect_text "wrong password: tor's rejection is shown" "515"

stop_tor

## 4. NULL auth (no method configured at all) -- the other side of the branch:
##    login() must SUCCEED without any credential.
start_tor "## no authentication configured"
run_tor_ctrl -s "${control_port}" -c "GETINFO version"
check "null auth: exit status" "0" "${last_status}"
expect_text "null auth: controller answered" "250-version="
stop_tor

## 5. THE regression case. A socket that accepts but is not a tor controller
##    returns no 'AUTH METHODS=' line at all, so the grep that extracts it
##    matches nothing. That is the state login() is written to report -- and
##    with the grep unguarded it is instead an errexit abort, exiting 1 with the
##    diagnostics never printed. Measured on the unguarded code: exit 1 and zero
##    occurrences of "Authentication method not detected".
##
##    A live tor cannot produce this, which is why it needs a stand-in listener.
listener_port=19801
socat "TCP-LISTEN:${listener_port},fork,reuseaddr,bind=127.0.0.1" /dev/null &
listener_pid=$!
sleep 1

run_tor_ctrl -s "${listener_port}" -c "GETINFO version"
check "non-controller socket: exit status" "1" "${last_status}"
expect_text "non-controller socket: says the method was not detected" \
   "Authentication method not detected"
expect_text "non-controller socket: names the socket as the problem" \
   "does not seems to be tor's controller socket"

kill "${listener_pid}" 2>/dev/null || true

printf '%s\n' "" "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
