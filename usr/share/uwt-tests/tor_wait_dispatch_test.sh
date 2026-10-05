#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dnf-3.anondist tor-wait dispatch: which command waits for the Tor service.
##
## The shipped wrapper picks, in order:
##   1. root (id -u = 0)                -> helper directly, NEVER leaprun
##   2. non-root + leaprun can run it   -> leaprun try-wait-for-tor-service-running
##   3. non-root + leaprun --check fail -> helper directly (fallback)
##   4. non-root + leaprun absent       -> helper directly (fallback)
##
## Drives the REAL dnf-3.anondist by SOURCING it (it is source-able: pure
## functions + a was_executed-guarded main) and calling wait_for_tor_service via
## uwt_dispatch_probe.sh. The direct-helper seam is overridden in the probe; id
## and leaprun are PATH stubs. check_runtime.bsh (for was_executed) resolves via
## HELPER_SCRIPTS_PATH. No real helper, uwtwrapper, leaprun or Tor is touched.
##
## A missing subject / check_runtime.bsh is a REQUIRED-dependency environment
## bug -> exit 1 (FATAL), never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${tool_dir}/uwt_dispatch_probe.sh"

[ -v UWT_REPO ] || UWT_REPO=""
if [ -n "${UWT_REPO}" ]; then
   subject="${UWT_REPO}/usr/bin/dnf-3.anondist"
else
   subject='/usr/bin/dnf-3.anondist'
fi

## check_runtime.bsh (defines was_executed): HELPER_SCRIPTS_PATH points at a
## helper-scripts checkout (set by dist-ai-tests-all's wire); unset -> installed
## /usr/libexec. The subject sources it on load, so it must resolve.
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
check_runtime="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/check_runtime.bsh"

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set UWT_REPO to a uwt checkout, or install uwt" >&2
   exit 1
fi
if [ ! -r "${check_runtime}" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable at '${check_runtime}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -x "${probe}" ]; then
   printf '%s\n' "FATAL: test support probe missing or not executable: '${probe}'" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

## Write a minimal, dependency-free stub (printf + exit only, no coreutils) so
## the probe can run under a stub-ONLY PATH -- which is how 'leaprun absent'
## stays reliable (a leaprun installed on the host cannot leak onto PATH).
write_stub() {
   local file="$1" stdout_line="$2" exit_code="$3"
   {
      printf '%s\n' '#!/bin/bash'
      if [ -n "${stdout_line}" ]; then
         printf "printf '%%s\\\\n' %q\\n" "${stdout_line}"
      fi
      printf 'exit %s\n' "${exit_code}"
   } > "${file}"
   chmod 0755 -- "${file}"
}

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Run the probe under a fresh stub-only PATH. Args: $1 id's 'id -u' output
## (uid), $2 leaprun mode ('ok' present+exit0, 'fail' present+exit1, 'absent'
## not on PATH). Echoes the probe's single RAN:* line.
run_case() {
   local uid="$1" leaprun_mode="$2" bin out
   bin="$(mktemp --directory --tmpdir="${test_dir}")"
   write_stub "${bin}/id" "${uid}" 0
   ## 'absent' writes no leaprun stub -> not on the stub-only PATH.
   if [ "${leaprun_mode}" = 'ok' ]; then
      write_stub "${bin}/leaprun" 'RAN:leaprun' 0
   elif [ "${leaprun_mode}" = 'fail' ]; then
      write_stub "${bin}/leaprun" '' 1
   fi
   ## stdout is the assertion; a probe crash yields empty -> the check fails
   ## loud. '|| true' keeps this test's errexit from aborting on it.
   out="$(SUBJECT="${subject}" HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
      PATH="${bin}" "${probe}")" || true
   printf '%s' "${out}"
}

check "root (uid 0), leaprun available -> direct, never leaprun" \
   "$(run_case 0 ok)" "RAN:direct"
check "non-root, leaprun --check ok -> leaprun" \
   "$(run_case 1000 ok)" "RAN:leaprun"
check "non-root, leaprun --check fails -> direct (fallback)" \
   "$(run_case 1000 fail)" "RAN:direct"
check "non-root, leaprun absent -> direct (fallback)" \
   "$(run_case 1000 absent)" "RAN:direct"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
