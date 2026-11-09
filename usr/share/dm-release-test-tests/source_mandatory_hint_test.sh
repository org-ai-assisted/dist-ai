#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## --source is MANDATORY. A STALE local vbox-image-test/-default (predating mandatory --source)
## emits lanes with NO --source, and this (freshly deployed) dm-release-test then fails at
## rt_resolve_origin. The stale orchestrator cannot detect its own staleness, so the server-side
## error is the ONE place to catch it -- it must name the remediation (rebuild + dpkg -i the
## dist-ai .deb LOCALLY). Drives the REAL dm-release-test with a missing --source (it reaches the
## die after pure validation only -- no root, no network) and asserts the exit code + the hint.
## [CANARY: pre-fix the die text lacked the stale-local-install remediation.]

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
   if [ -x "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -x "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not executable at ${subject}" >&2; exit 1; }

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: ${1}"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${1}"; fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## A bare guest+interface with NO --source reaches the rt_resolve_origin die (SETUP_RC=2).
rc=0
err="$("${subject}" kicksecure lxqt </dev/null 2>&1)" || rc=$?
got=0; [ "${rc}" -eq 2 ] || got=1
check 'missing --source exits SETUP_RC (2)' "${got}"
got=0; has '--source is mandatory' "${err}" || got=1
check 'error still states --source is mandatory' "${got}"
got=0; has 'your LOCAL dist-ai is likely STALE' "${err}" || got=1
check 'error hints a STALE local dist-ai install' "${got}"
got=0; has "dpkg -i" "${err}" || got=1
check 'error gives the dpkg -i remediation' "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
