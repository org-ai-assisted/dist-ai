#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for #814: a RELATIVE --ova-gw/--ova-ws must be canonicalized to an ABSOLUTE path at
## parse time. A relative path passes the root-side readability precheck (relative to root's CWD)
## but then fails in VBoxManage run as the drop account (a different CWD) AFTER the import already
## deleted the existing VM. parse_args now realpath -m's each value. Drives the REAL parse_args
## (sourced define-only). Canary: the pre-fix parser left the value relative.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not found at ${subject}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${subject}"

work="$(mktemp --directory --tmpdir dm-release-test-ova.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass=0
fail=0
check() {
   if [ "$2" = "true" ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1 (got '${3:-}')"; fi
}

## realpath -m resolves relative to CWD and does NOT require existence (so a missing file is still
## reported by the dedicated readability check, not here). cd into the temp dir and pass a path
## relative to it.
cd -- "${work}"
parse_args whonix cli --source built --ova-gw sub/gw.ova --ova-ws deeper/ws.ova \
   --lane inst --version 18.2.3.0-g1 --provision

## ova_gw/ova_ws are set by the sourced parse_args above (shellcheck cannot see that).
# shellcheck disable=SC2154
case "${ova_gw}" in
   /*)
      check "--ova-gw canonicalized to an absolute path" true
      ;;
   *)
      check "--ova-gw canonicalized to an absolute path" false "${ova_gw}"
      ;;
esac
case "${ova_gw}" in
   */sub/gw.ova)
      check "--ova-gw preserves the given basename/subpath" true
      ;;
   *)
      check "--ova-gw preserves the given basename/subpath" false "${ova_gw}"
      ;;
esac
# shellcheck disable=SC2154
case "${ova_ws}" in
   /*)
      check "--ova-ws canonicalized to an absolute path" true
      ;;
   *)
      check "--ova-ws canonicalized to an absolute path" false "${ova_ws}"
      ;;
esac
case "${ova_ws}" in
   */deeper/ws.ova)
      check "--ova-ws preserves the given basename/subpath" true
      ;;
   *)
      check "--ova-ws preserves the given basename/subpath" false "${ova_ws}"
      ;;
esac

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
