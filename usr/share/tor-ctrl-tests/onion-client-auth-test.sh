#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Does 'tor-ctrl-onion -n' actually make tor PERSIST the client credential?
##
## '-n' is the documented permanent flag: the credential belongs in the
## filesystem rather than only in tor's memory. ONION_CLIENT_AUTH_ADD answers
## 250 OK whether or not 'Flags=Permanent' was sent, so the exit status cannot
## tell a working flag from a flag that does nothing.
##
## The discriminator is the ClientOnionAuthDir: tor writes '<onion>.auth_private'
## there for a PERMANENT credential and nothing at all for an ephemeral one.
## Both directions are asserted, so a build that persists everything fails as
## loudly as one that persists nothing.
##
## Starts its OWN tor on a private DataDirectory, ControlPort and
## ClientOnionAuthDir, with DisableNetwork -- it never touches a system tor, a
## production onion, or the network.

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

## Subject resolution, following the dist-ai convention:
##   TOR_CTRL_REPO=/path/to/tor-ctrl -> that checkout
##   unset                           -> the installed package
[ -v TOR_CTRL_REPO ] || TOR_CTRL_REPO=""
if [ -n "${TOR_CTRL_REPO}" ]; then
   tor_ctrl_bin_dir="${TOR_CTRL_REPO}/usr/bin"
else
   tor_ctrl_bin_dir="/usr/bin"
fi

onion_tool="${tor_ctrl_bin_dir}/tor-ctrl-onion"

## BOTH halves of the subject, not just the one invoked directly. tor-ctrl-onion
## shells out to 'tor-ctrl' through PATH, so a checkout missing its companion
## would still resolve to the INSTALLED /usr/bin/tor-ctrl below -- silently
## pairing new tor-ctrl-onion with an old tor-ctrl and reporting whatever that
## mismatch produces as a result about the checkout.
for subject in "${onion_tool}" "${tor_ctrl_bin_dir}/tor-ctrl"; do
   if [ ! -x "${subject}" ]; then
      printf '%s\n' "SKIP: subject not found at '${subject}'" >&2
      printf '%s\n' "set TOR_CTRL_REPO to a complete tor-ctrl checkout, or install the package" >&2
      exit 77
   fi
done

## tor-ctrl-onion shells out to 'tor-ctrl' from PATH, and the INSTALLED copy can
## lag the checkout under test -- it did during development, missing the CR strip
## that makes '^HASHEDPASSWORD$' match, so the suite exercised old code and
## reported a failure the tree did not have. Put the subject's own directory
## first so both halves come from the same tree.
PATH="${tor_ctrl_bin_dir}:${PATH}"
export PATH

## Dependencies, not subjects: a missing one is a bug to fix in the consumer's
## declared packages, not something to skip past.
for dependency in tor nc python3; do
   if ! type -P "${dependency}" >/dev/null; then
      printf '%s\n' "FAIL: required program '${dependency}' is not installed" >&2
      exit 1
   fi
done

if ! python3 -c 'from cryptography.hazmat.primitives.asymmetric import ed25519' 2>/dev/null; then
   printf '%s\n' "FAIL: python3 'cryptography' is required to build a valid v3 onion address" >&2
   exit 1
fi

payload_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"

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

## Delegates to onion-address-generate.py, which documents the v3 address format.
## Generated per call rather than hardcoded, so this never names a real service.
make_onion() {
   python3 -- "${payload_dir}/onion-address-generate.py"
}

make_privkey() {
   python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
}

work_dir="$(mktemp --directory)"
mkdir --parents -- "${work_dir}/data" "${work_dir}/auth"
chmod 0700 -- "${work_dir}/data" "${work_dir}/auth"

## Password auth, not cookie: tor-ctrl refuses any CookieAuthFile outside the
## canonical /run/tor/control.authcookie, which a private test tor cannot use.
control_password="tor-ctrl-onion-test-${$}"
hashed_password="$(tor --hash-password "${control_password}" | tail -n 1)"

## An ephemeral high port, so a concurrent run or a local service does not
## collide with a fixed one. Tor reports the port it actually opened.
control_port=0

cat > "${work_dir}/torrc" <<EOF
DataDirectory ${work_dir}/data
ControlPort auto
ControlPortWriteToFile ${work_dir}/control.port
HashedControlPassword ${hashed_password}
ClientOnionAuthDir ${work_dir}/auth
SocksPort 0
DisableNetwork 1
Log notice file ${work_dir}/tor.log
EOF

tor --quiet -f "${work_dir}/torrc" &
tor_pid=$!

## Wait for the port file rather than sleeping a guessed interval.
waited=0
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

count_auth_files() {
   find "${work_dir}/auth" -name '*.auth_private' -type f | wc -l
}

## TOR_CONTROL_HOST / TOR_CONTROL_PORT are UNSET for the subject, not merely
## overridden by '-s'. tor-ctrl treats them as a FALLBACK: if the socket given on
## the command line does not answer, it tries the environment pair next. Inherited
## from the caller, a hiccup on this private tor would silently redirect the
## authorization command at whatever controller those variables name -- a real
## one, on a machine where this suite must touch nothing but its own tor.
add_client_auth() {
   local onion="${1}"
   local key="${2}"
   shift 2
   env --unset=TOR_CONTROL_HOST --unset=TOR_CONTROL_PORT \
      "${onion_tool}" -s "${control_port}" -p "${control_password}" \
      -U "x25519:${key}" -o "${onion}" "$@"
}

printf '%s\n' "--- ephemeral (no -n): tor must NOT write a credential file ---"
onion_ephemeral="$(make_onion)"
add_status=0
add_client_auth "${onion_ephemeral}" "$(make_privkey)" >"${work_dir}/ephemeral.log" 2>&1 || add_status=$?
check "ephemeral ONION_CLIENT_AUTH_ADD succeeds" "0" "${add_status}"
[ "${add_status}" -eq 0 ] || cat -- "${work_dir}/ephemeral.log" >&2
check "ephemeral leaves ClientOnionAuthDir empty" "0" "$(count_auth_files)"

printf '%s\n' "--- permanent (-n): tor MUST write a credential file ---"
onion_permanent="$(make_onion)"
add_status=0
add_client_auth "${onion_permanent}" "$(make_privkey)" -n >"${work_dir}/permanent.log" 2>&1 || add_status=$?
check "permanent ONION_CLIENT_AUTH_ADD succeeds" "0" "${add_status}"
[ "${add_status}" -eq 0 ] || cat -- "${work_dir}/permanent.log" >&2
check "permanent writes one credential file" "1" "$(count_auth_files)"

if [ "$(count_auth_files)" = "1" ]; then
   written="$(find "${work_dir}/auth" -name '*.auth_private' -type f -print -quit)"
   check "credential is named after the onion" "${onion_permanent}.auth_private" "$(basename -- "${written}")"
   check "credential records the x25519 key type" "1" "$(grep -c 'x25519' -- "${written}" || true)"
fi

printf '%s\n' "" "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
