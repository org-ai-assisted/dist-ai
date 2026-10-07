#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The --iso built-origin lane: test a LOCALLY-BUILT ISO instead of downloading.
## A git-describe build version (18.2.3.0-222-g<sha>) is NOT a release token, so it
## must NOT flow through rt_version_token / the eph account-name ceiling -- a built run
## uses a FIXED eph-run-GUEST-built account and records origin=built. Canary: on the old
## (download-only) code `--iso` is an unknown option and the helpers do not exist.

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
[ -r "${subject}" ] || { printf 'FATAL: dm-release-test not found at %s\n' "${subject}" >&2; exit 1; }

failures=0
ok()  { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }

## --- pure helpers (source the guarded main) ---
# shellcheck disable=SC1090
source "${subject}"

iso_name='Kicksecure-LXQt-18.2.3.0-222-g0355db7f4fe1b4a73573d6d61aa50833369a8f26.Intel_AMD64.iso'
got="$(rt_build_version_from_iso "/home/admin/derivative-binary/x/${iso_name}")"
if [ "${got}" = '18.2.3.0-222-g0355db7f4fe1b4a73573d6d61aa50833369a8f26' ]; then
   ok 'rt_build_version_from_iso derives the git-describe label'
else
   bad "rt_build_version_from_iso: got '${got}'"
fi

## path-safe labels accepted; traversal / separators / bad charset / overlong rejected.
for good in '18.2.3.0-222-g0355db7f' '18.2.1.9' '1.0+build-1'; do
   if rt_build_version_ok "${good}"; then
      ok "rt_build_version_ok accepts '${good}'"
   else
      bad "rt_build_version_ok rejected a safe label '${good}'"
   fi
done
for evil in '../etc' 'a/b' 'a..b' 'has space' "$(printf 'x%065d' 0)"; do
   if rt_build_version_ok "${evil}"; then
      bad "rt_build_version_ok accepted an unsafe label '${evil}'"
   else
      ok 'rt_build_version_ok rejects an unsafe label'
   fi
done

## --- the lane wiring (run the real script, --dry-run so no VM/root) ---
d="$(mktemp --directory)"
iso="${d}/${iso_name}"
touch -- "${iso}"
cleanup() { safe-rm --recursive --force -- "${d}"; }
trap cleanup EXIT

plan="$("${subject}" kicksecure lxqt --iso "${iso}" --firmware efi --checks --dry-run 2>&1)"
if grep --quiet 'origin=built' <<<"${plan}"; then ok '--iso plan records origin=built'; else bad "no origin=built in plan: ${plan}"; fi
if grep --quiet 'account=eph-run-kicksecure-built' <<<"${plan}"; then ok '--iso uses the fixed eph-run-kicksecure-built account'; else bad "wrong account in plan: ${plan}"; fi
if grep --quiet 'resolved=18.2.3.0-222-g0355db7f4fe1b4a73573d6d61aa50833369a8f26' <<<"${plan}"; then ok '--iso derives the version label into the plan'; else bad "no derived version in plan: ${plan}"; fi

## --iso is kicksecure-only (whonix tests an imported pair, not an ISO install).
if "${subject}" whonix lxqt --iso "${iso}" --dry-run >/dev/null 2>&1; then
   bad '--iso wrongly accepted for whonix'
else
   ok '--iso rejected for whonix (kicksecure-only)'
fi

## --version overrides the derived label but keeps origin=built.
over_plan="$("${subject}" kicksecure lxqt --iso "${iso}" --version 18.2.3.0 --dry-run 2>&1)"
if grep --quiet 'origin=built' <<<"${over_plan}"; then
   ok '--version overrides the derived label but keeps origin=built'
else
   bad "--version broke origin=built: ${over_plan}"
fi

if [ "${failures}" -ne 0 ]; then
   printf '\n%s built-iso-lane assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall built-iso-lane assertions passed\n'
