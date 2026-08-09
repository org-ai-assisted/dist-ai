#!/bin/bash

## Copyright (C) 2025 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## anon-server-to-client-install: the MODE of the files it writes, not just its
## exit code.
##
## THE BUG: the installer used 'cp', which PRESERVES the source mode, so a
## world-readable .auth_private file stayed world-readable once deployed -- a
## private onion client-auth key, exit code 0, no diagnostic. The fix tightens
## both the newly installed key and any key an EARLIER run already left
## exposed, so both are asserted here.
##
## Runs under 'bwrap --unshare-user --uid 0': the installer chowns to
## the Tor user, which needs uid 0. A user namespace supplies that without real
## root, so this lane needs no privilege and cannot touch anything outside its
## temp dir. The earlier per-package copy of this test simply refused to run as
## non-root, which in practice meant it did not run.
##
## Targets the INSTALLED installer; ANON_GW_ANONYMIZER_CONFIG_REPO points it at
## a checkout instead. The per-package copy resolved it relative to its own
## file, so it validated the checkout it sat in and stayed green against a
## stale install.
##
## No root, no network, no tor.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v ANON_GW_ANONYMIZER_CONFIG_REPO ] || ANON_GW_ANONYMIZER_CONFIG_REPO=""
[ -v AUTH_PRIVATE_MODE_TEST_INNER ] || AUTH_PRIVATE_MODE_TEST_INNER=""

if [ -n "${ANON_GW_ANONYMIZER_CONFIG_REPO}" ]; then
   installer="${ANON_GW_ANONYMIZER_CONFIG_REPO}/usr/bin/anon-server-to-client-install"
else
   installer='/usr/bin/anon-server-to-client-install'
fi

if [ ! -x "${installer}" ]; then
   printf '%s\n' "SKIP: anon-server-to-client-install not found at '${installer}'" >&2
   printf '%s\n' "set ANON_GW_ANONYMIZER_CONFIG_REPO to a checkout, or install the package" >&2
   exit 77
fi

## Re-run once inside a user namespace where this process is uid 0. The
## sentinel is what stops it from doing so again, which would loop forever.
if [ -z "${AUTH_PRIVATE_MODE_TEST_INNER}" ]; then
   ## Run as a CHILD and forward its exit code rather than 'exec'-ing, so this
   ## shell's own EXIT trap and diagnostics stay in place.
   inner_rc=0
   bwrap --dev-bind / / --unshare-user --uid 0 --gid 0 \
      -- env AUTH_PRIVATE_MODE_TEST_INNER=1 bash "$0" "$@" || inner_rc=$?
   exit "${inner_rc}"
fi

if [ ! "$(id -u)" = 0 ]; then
   printf '%s\n' "FATAL: not uid 0 inside the user namespace; the chown would fail" >&2
   printf '%s\n' "and every mode assertion would then be about a file the installer never wrote" >&2
   exit 1
fi

test_root="$(mktemp --directory -- "${TMP}/auth-private-mode-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${test_root}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

check_mode() {
   local label expected path actual

   label="$1"
   expected="$2"
   path="$3"

   if [ ! -e "${path}" ]; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${label}: '${path}' does not exist"
      return 0
   fi
   actual="$(stat --format=%a -- "${path}")"
   if [ "${actual}" = "${expected}" ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${label}: mode ${actual}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${label}: mode ${actual}, expected ${expected}"
   fi
}

run_installer() {
   local sourcefile

   sourcefile="$1"

   ## 'tor_user=root': debian-tor need not exist on the test host, and the
   ## assertion is about the mode, not about which user owns the file.
   ## The unit commands are stubbed so no Tor has to be running.
   sourcefile="${sourcefile}" \
   tor_user="root" \
   tor_group="root" \
   tor_dir="${test_root}/var-lib-tor" \
   torconfdir="${test_root}/torrc.d" \
   torconffile="${test_root}/torrc.d/60_client_onion_auth_dir.conf" \
   unitcmd="true" \
   unitruntestcmd="true" \
   user_name="nobody" \
      "${installer}" >/dev/null
}

mkdir --parents -- "${test_root}/var-lib-tor" "${test_root}/torrc.d"

## Case 1: a world-readable sourcefile must NOT stay world-readable once
## installed. 'cp' preserves the source mode, which is how the key leaked.
printf '%s\n' 'descriptor:x25519:AAAA' >"${test_root}/1.auth_private"
chmod 0644 -- "${test_root}/1.auth_private"
run_installer "${test_root}/1.auth_private"
check_mode 'newly installed key' '600' "${test_root}/var-lib-tor/authdir/1.auth_private"

## Case 2: a key left world-readable by an EARLIER run gets tightened on the
## next run. A code-only fix would leave already deployed keys exposed.
printf '%s\n' 'descriptor:x25519:BBBB' >"${test_root}/var-lib-tor/authdir/9.auth_private"
chmod 0644 -- "${test_root}/var-lib-tor/authdir/9.auth_private"
run_installer "${test_root}/1.auth_private"
check_mode 'pre-existing key from an earlier run' '600' "${test_root}/var-lib-tor/authdir/9.auth_private"

## A run that installed NOTHING would report two 'does not exist' failures
## rather than a false pass, but say so explicitly: a mode assertion against a
## file the installer never wrote is the vacuous shape to guard.
if [ ! -d "${test_root}/var-lib-tor/authdir" ]; then
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: the installer created no authdir at all -- nothing was tested"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
