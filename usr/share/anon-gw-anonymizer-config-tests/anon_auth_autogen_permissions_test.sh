#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for anon-auth-autogen's private-key file modes.
##
## WHAT IS UNDER TEST: onion client authorization private key material. The
## script creates it through 'openssl' and 'tee', both of which honour the
## inherited umask, so an operator with a permissive umask got world-readable
## private keys. secure_private_file() sets 0600 on each file it creates, and
## secure_existing_private_files() tightens keys left behind by earlier runs --
## a key already deployed stops being exposed without waiting for
## regeneration.
##
## That is a security fix, and it had no standing test: it was verified once by
## executing the extracted functions by hand. This suite runs the REAL script
## end to end instead, under a deliberately permissive umask, and asserts the
## modes of the files it actually produced.
##
## The script is fully parameterised by environment, so nothing here patches
## it: every path is redirected into a temp tree, 'tor_user_sudo' is emptied,
## and the tools it shells out to that need a machine (tor, systemctl, id,
## groups, chown, basez, qubesdb-read) are stubbed on PATH. openssl runs for
## real -- the key material is the subject.
##
## Set ANON_GW_ANONYMIZER_CONFIG_REPO to test a checkout; otherwise the
## installed /usr/bin/anon-auth-autogen is used. Exits 77 (SKIP) when neither
## resolves. No root, no network, no tor.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: /usr/libexec/helper-scripts/has.sh is not installed; the subject sources it" >&2
   exit 1
fi
## Installed path: this repo is outside the dm source tree, so helper-scripts
## is not a relative sibling here.
# shellcheck source=./has.sh
# shellcheck disable=SC1091
source /usr/libexec/helper-scripts/has.sh

## openssl is the subject's key generator, not a convenience: without it there
## is no private key to check the mode of, and every assertion below would be
## vacuous.
if ! has openssl ; then
   printf '%s\n' "FATAL: openssl not on PATH; this suite cannot generate the key material it checks" >&2
   exit 1
fi
if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## Resolve the subject: an explicit checkout, then a sibling checkout next to
## this suite, then the installed path.
subject="${ANON_AUTH_AUTOGEN_BIN:-}"
if [ -z "${subject}" ] && [ -n "${ANON_GW_ANONYMIZER_CONFIG_REPO:-}" ]; then
   subject="${ANON_GW_ANONYMIZER_CONFIG_REPO}/usr/bin/anon-auth-autogen"
fi
if [ -z "${subject}" ] && [ -x "${script_dir}/../../bin/anon-auth-autogen" ]; then
   subject="${script_dir}/../../bin/anon-auth-autogen"
fi
if [ -z "${subject}" ]; then
   subject='/usr/bin/anon-auth-autogen'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: no anon-auth-autogen to test (looked at '${subject}'); set ANON_GW_ANONYMIZER_CONFIG_REPO" >&2
   exit 77
fi

test_dir="$(mktemp --directory -- "${TMP}/anon-auth-autogen-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}

if [ ! -v ANON_KEEP_TEST_DIR ]; then
   trap test_cleanup_handler EXIT
fi

stub_dir="${test_dir}/stub"
mkdir --parents -- "${stub_dir}"

make_stub() {
   local name body

   name="$1"
   body="$2"
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' "${body}"
   } >"${stub_dir}/${name}"
   chmod 0755 -- "${stub_dir}/${name}"
}

## Root is asserted by the subject before it does anything else.
make_stub id 'if [ "${1:-}" = "-u" ]; then printf "%s\n" "0"; exit 0; fi
exit 0'
make_stub groups 'exit 0'
## chown to debian-tor cannot work unprivileged, and is not what is under test.
make_stub chown 'exit 0'
make_stub systemctl 'exit 0'
make_stub sleep 'exit 0'
## Deterministic stand-ins for the base32/base64 conversion. The subject pipes
## key bytes through these; what they emit does not matter to a mode check, but
## it must be stable and non-empty or the pipeline fails and no file is made.
make_stub basez 'cat >/dev/null
printf "%s\n" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
## Not a Qubes machine: the subject falls back to a fixed IP when this is
## absent, and 'has' must therefore NOT find it.
safe-rm --force -- "${stub_dir}/qubesdb-read"

fail=0

## Every path the subject writes to, redirected into the temp tree.
hs_dir="${test_dir}/tor/hidden_service"
autogen_root="${test_dir}/tor_autogen"
autogen_hs="${autogen_root}/hidden_service"
torconf_dir="${test_dir}/torrc.d"
mkdir --parents -- "${hs_dir}" "${torconf_dir}" "${test_dir}/home"
printf '%s\n' 'exampleonionaddressexampleonionaddressexampleonionaddr.onion' \
   >"${hs_dir}/hostname"

run_subject() {
   local client_id rc

   client_id="$1"
   rc=0
   ## umask 0022 deliberately: it is the permissive default that made the
   ## created files world-readable, so running under it is what gives the
   ## assertions below something to prove.
   ( umask 0022
     env --ignore-environment \
        PATH="${stub_dir}:/usr/bin:/bin" \
        HOME="${test_dir}/home" \
        tor_user_sudo='' \
        tor_user="$(id --user --name)" \
        tor_group="$(id --group --name)" \
        client="${client_id}" \
        hsname='hidden_service' \
        hsdir="${hs_dir}" \
        onion_url_file="${hs_dir}/hostname" \
        authorized_clients_folder="${hs_dir}/authorized_clients" \
        tor_autogen_root_folder="${autogen_root}" \
        tor_autogen_hs_folder="${autogen_hs}" \
        torconfdir="${torconf_dir}" \
        torconffile="${torconf_dir}/43_hidden_service_hs_autogen.conf" \
        unittool="${stub_dir}/systemctl" \
        unitruntestcmd='true' \
        sleep_seconds_after_reload=0 \
        home_folder_auth_private_file="${test_dir}/home/${client_id}.auth_private" \
        bash "${subject}" ) >"${test_dir}/run-${client_id}.log" 2>&1 || rc=$?
   printf '%s' "${rc}"
}

expect_mode() {
   local path expected actual label

   path="$1"
   expected="$2"
   label="$3"
   if [ ! -e "${path}" ]; then
      printf '%s\n' "FAIL: ${label}: '${path}' was not created"
      fail=1
      return 0
   fi
   actual="$(stat --format='%a' -- "${path}")"
   if [ ! "${actual}" = "${expected}" ]; then
      printf '%s\n' "FAIL: ${label}: '${path}' is mode ${actual}, expected ${expected}"
      fail=1
      return 0
   fi
   printf '%s\n' "PASS: ${label}: mode ${actual}"
}

## --- 1. a fresh run creates private key material readable only by its owner.
run_rc="$(run_subject 1)"
if [ ! "${run_rc}" = "0" ]; then
   printf '%s\n' "FAIL: the subject exited ${run_rc} on a fresh run"
   tail -20 -- "${test_dir}/run-1.log" | sed 's/^/  /'
   fail=1
fi

expect_mode "${autogen_hs}/1_private_key.pem"   '600' 'private key (PEM)'
expect_mode "${autogen_hs}/1_private_key.base32" '600' 'private key (base32)'
expect_mode "${autogen_hs}/1.auth_private"      '600' 'auth_private'

## The PUBLIC half must NOT be tightened: doing so would be a different bug,
## and asserting only the private files would not notice a blanket chmod.
if [ -e "${autogen_hs}/1_public_key.pem" ]; then
   public_mode="$(stat --format='%a' -- "${autogen_hs}/1_public_key.pem")"
   if [ "${public_mode}" = "600" ]; then
      printf '%s\n' "FAIL: the public key was tightened to 600 as well"
      fail=1
   else
      printf '%s\n' "PASS: the public key is left at ${public_mode}"
   fi
else
   printf '%s\n' "FAIL: the public key was not created; the run did not get that far"
   fail=1
fi

## --- 2. a key left world-readable by an EARLIER run is tightened on the next
## run, which is the whole point of secure_existing_private_files.
legacy_private="${autogen_hs}/9_private_key.pem"
legacy_base32="${autogen_hs}/9_private_key.base32"
legacy_auth="${autogen_hs}/9.auth_private"
printf '%s\n' 'legacy key material' >"${legacy_private}"
printf '%s\n' 'legacy key material' >"${legacy_base32}"
printf '%s\n' 'legacy key material' >"${legacy_auth}"
chmod 0644 -- "${legacy_private}" "${legacy_base32}" "${legacy_auth}"

run_rc="$(run_subject 2)"
if [ ! "${run_rc}" = "0" ]; then
   printf '%s\n' "FAIL: the subject exited ${run_rc} on the second run"
   tail -20 -- "${test_dir}/run-2.log" | sed 's/^/  /'
   fail=1
fi

expect_mode "${legacy_private}" '600' 'pre-existing private key (PEM) tightened'
expect_mode "${legacy_base32}"  '600' 'pre-existing private key (base32) tightened'
expect_mode "${legacy_auth}"    '600' 'pre-existing auth_private tightened'

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
