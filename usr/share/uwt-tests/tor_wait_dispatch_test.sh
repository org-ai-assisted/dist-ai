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
   ## '|| true': a cleanup failure must not clobber the script's real exit code.
   safe-rm -r -f -- "${test_dir}" || true
}
trap cleanup_handler EXIT

## Write a minimal, dependency-free stub (printf + exit only, no coreutils) that
## RECORDS its argv to <record> then emits <stdout_line> and exits <exit_code>.
## No coreutils so the probe runs under a stub-ONLY PATH (how 'leaprun absent'
## stays reliable: a host leaprun cannot leak onto PATH); the recording lets the
## test assert HOW the subject invoked id / leaprun, not just which branch ran.
write_stub() {
   local file="$1" record="$2" stdout_line="$3" exit_code="$4"
   {
      printf '%s\n' '#!/bin/bash'
      printf 'printf %s "$*" >> %q\n' "'%s\\n'" "${record}"
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

## Run the probe under a fresh stub-only PATH and populate the case_* globals:
## case_out (probe stdout), case_rc (probe exit status), case_id_args and
## case_leaprun_args (recorded argv, '' when the command was never invoked).
## $1 uid for 'id -u', $2 leaprun mode ('ok' present+exit0, 'fail' present+exit1,
## 'absent' not on PATH).
case_out=''
case_rc=0
case_id_args=''
case_leaprun_args=''
run_case() {
   local uid="$1" leaprun_mode="$2" bin id_rec leaprun_rec
   bin="$(mktemp --directory --tmpdir="${test_dir}")"
   id_rec="${bin}/id.args"
   leaprun_rec="${bin}/leaprun.args"
   write_stub "${bin}/id" "${id_rec}" "${uid}" 0
   ## 'absent' writes no leaprun stub -> not on the stub-only PATH.
   if [ "${leaprun_mode}" = 'ok' ]; then
      write_stub "${bin}/leaprun" "${leaprun_rec}" 'RAN:leaprun' 0
   elif [ "${leaprun_mode}" = 'fail' ]; then
      write_stub "${bin}/leaprun" "${leaprun_rec}" '' 1
   fi
   ## '|| case_rc=$?' captures the probe's exit instead of letting errexit abort,
   ## so a dispatch that prints the right marker then FAILS is still caught.
   case_rc=0
   case_out="$(SUBJECT="${subject}" HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
      PATH="${bin}" "${probe}")" || case_rc=$?
   case_id_args=''
   if [ -f "${id_rec}" ]; then
      case_id_args="$(cat -- "${id_rec}")"
   fi
   case_leaprun_args=''
   if [ -f "${leaprun_rec}" ]; then
      case_leaprun_args="$(cat -- "${leaprun_rec}")"
   fi
}

## root: direct, never leaprun; and the subject must query uid via 'id -u'.
run_case 0 ok
check "root: dispatch -> direct"           "${case_out}" "RAN:direct"
check "root: probe exits 0"                "${case_rc}"  "0"
check "root: subject queried 'id -u'"      "${case_id_args}" "-u"
check "root: leaprun never invoked"        "${case_leaprun_args}" ""

## non-root + leaprun can run it: leaprun, invoked with the CORRECT action name
## (the real call is the last recorded invocation, after the '--check' probe).
run_case 1000 ok
check "non-root, leaprun ok: dispatch -> leaprun" "${case_out}" "RAN:leaprun"
check "non-root, leaprun ok: probe exits 0"       "${case_rc}"  "0"
check "non-root, leaprun ok: real call action is try-wait-for-tor-service-running" \
   "${case_leaprun_args##*$'\n'}" "try-wait-for-tor-service-running"

## non-root + leaprun --check fails: fall back to direct.
run_case 1000 fail
check "non-root, leaprun --check fails: dispatch -> direct" "${case_out}" "RAN:direct"
check "non-root, leaprun --check fails: probe exits 0"      "${case_rc}"  "0"

## non-root + leaprun absent: fall back to direct, leaprun never invoked.
run_case 1000 absent
check "non-root, leaprun absent: dispatch -> direct"   "${case_out}" "RAN:direct"
check "non-root, leaprun absent: probe exits 0"        "${case_rc}"  "0"
check "non-root, leaprun absent: leaprun never invoked" "${case_leaprun_args}" ""

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
