#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## apparmor-info: UNIT coverage of the source-able post-processing function
## apparmor_info_filter, which the clean-boot lane only exercises end-to-end.
##
##  (1) Source-ability: sourcing the real apparmor-info does NOT auto-run (the
##      was_executed guard) and does NOT leak strict-mode into the sourcing
##      shell, and the reusable function is defined and pure. Probed by the
##      committed non-strict apparmor_info_filter_source_probe.sh -- no inline
##      shell program here.
##  (2) The function in isolation: it redacts (pid=/fsuid= stripped), deduplicates
##      (records identical after redaction collapse to one; genuinely distinct
##      ones are kept), isolates the keyword (a DENIED filter never emits an
##      ALLOWED-only record and vice-versa), survives a NUL in the stream
##      (--text, so grep does not switch to binary mode and drop the match), and
##      returns 0 on no match -- the clean-boot case that must not abort under
##      errexit. The exit CODE is main()'s job, not the function's: the function
##      returns 0 even when it emits records, which this pins directly.
##
## Drives the REAL function by SOURCING the real script (sourceable skill), never
## a copy. No root, no journalctl, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${tool_dir}/apparmor_info_filter_source_probe.sh"

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/sbin/apparmor-info"
   libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
else
   subject='/usr/sbin/apparmor-info'
   libdir='/usr/libexec/helper-scripts'
fi

## The subject + its check_runtime.bsh are REQUIRED dependencies: absent means
## helper-scripts is not installed or HELPER_SCRIPTS_REPO is unset -- an
## environment bug, so FATAL (exit 1), never a skip (R-220). The test's own
## support script missing is likewise a FAIL.
if [ ! -x "${subject}" ]; then
   printf '%s\n' "FATAL: subject not executable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -r "${libdir}/check_runtime.bsh" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable under '${libdir}'" >&2
   exit 1
fi
if [ ! -x "${probe}" ]; then
   printf '%s\n' "FATAL: test support script missing next to '${tool_dir}'" >&2
   exit 1
fi

## The subject resolves check_runtime.bsh via HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"

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

contains() {
   case "$1" in
      *"$2"*)
         printf '%s' yes
         ;;
      *)
         printf '%s' no
         ;;
   esac
}

## Count the lines of $1 that contain the fixed string $2 (grep -c exits 1 on zero).
count_lines_with() {
   printf '%s\n' "$1" | { grep -F -c -- "$2" || true; }
}

## --- (1) source-ability: no auto-run, no strict leak, pure + defined ---
src_out=""
src_rc=0
src_out="$(SUBJECT="${subject}" "${probe}" source 2>/dev/null)" || src_rc=$?
check "sourcing does not enable errexit (no strict leak)" "${src_rc}" "0"
check "sourcing does not auto-run" "${src_out}" ""

call_rc=0
SUBJECT="${subject}" "${probe}" call >/dev/null 2>&1 || call_rc=$?
check "calling apparmor_info_filter stays pure and defined" "${call_rc}" "0"

## --- (2) the function in isolation: source the real script and call it ---
# shellcheck disable=SC1090,SC1091
source "${subject}"
if ! declare -F apparmor_info_filter >/dev/null ; then
   printf '%s\n' "FATAL: apparmor_info_filter not defined after sourcing subject" >&2
   exit 1
fi

## The pid=/comm=/fsuid= fields are what the subject's sed redaction strips. The
## distinctive post-redaction substring ('name=... comm=...' adjacency) exists
## ONLY after 's/pid=.* comm/comm/' ran, so asserting it pins that sed executed.
denied_line='type=AVC msg=audit(1.0:4): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/shadow" pid=123 comm="foo" fsuid=0'
allowed_line='type=AVC msg=audit(1.0:5): apparmor="ALLOWED" operation="open" profile="/usr/bin/bar" name="/srv/example" pid=124 comm="bar" fsuid=0'
denied_redacted='name="/etc/shadow" comm="foo"'
allowed_redacted='name="/srv/example" comm="bar"'

## Drive the real function with stdin from the caller; capture output and rc.
LAST_OUT=""
LAST_RC=0
run_filter() {
   ## $1 = keyword; stdin = the raw journal text.
   LAST_RC=0
   LAST_OUT="$(apparmor_info_filter "$1")" || LAST_RC=$?
}

## no match (a clean boot) -> empty output. NOTE: the clean-boot REGRESSION (the
## function must not ABORT under the caller's errexit when grep finds nothing) is
## owned by apparmor_info_clean_boot_test.sh, which runs the subject as a
## SUBPROCESS. A sourcing test cannot observe a function's errexit-abort:
## capturing the call's status (a '|| rc=$?', a subshell, an 'if') necessarily
## disables errexit for the whole call, so the abort never happens here. These
## assert the pure OUTPUT contract only.
## Byte-exact (wc -c, not a captured string -- command substitution strips a
## stray trailing newline, so a subject emitting "\n" would read as empty).
nomatch_bytes="$(printf '%s\n' 'type=SYSCALL msg=audit(1.0:2): nothing to see here' | apparmor_info_filter DENIED | wc -c | tr -d ' ')"
check "no match -> 0 bytes output" "${nomatch_bytes}" "0"

empty_bytes="$(apparmor_info_filter DENIED </dev/null | wc -c | tr -d ' ')"
check "empty stdin -> 0 bytes output" "${empty_bytes}" "0"

## a DENIED record -> redacted record emitted, pid=/fsuid= stripped, AND return 0
## (the function does not own the exit code; main() derives it from the output).
run_filter DENIED <<< "${denied_line}"
check "DENIED -> returns 0 (exit code is main's job)" "${LAST_RC}" "0"
check "DENIED -> redacted record emitted (sed ran)" "$(contains "${LAST_OUT}" "${denied_redacted}")" "yes"
check "DENIED -> pid= stripped" "$(contains "${LAST_OUT}" 'pid=')" "no"
check "DENIED -> fsuid= stripped" "$(contains "${LAST_OUT}" 'fsuid=')" "no"

## keyword isolation: a DENIED filter over BOTH records must emit only the DENIED
## one -- never the ALLOWED token -- and the ALLOWED filter the mirror image.
run_filter DENIED <<< "$(printf '%s\n' "${denied_line}" "${allowed_line}")"
check "DENIED filter -> emits DENIED record" "$(contains "${LAST_OUT}" "${denied_redacted}")" "yes"
check "DENIED filter -> drops ALLOWED record (keyword isolation)" "$(contains "${LAST_OUT}" 'ALLOWED')" "no"
run_filter ALLOWED <<< "$(printf '%s\n' "${denied_line}" "${allowed_line}")"
check "ALLOWED filter -> emits ALLOWED record" "$(contains "${LAST_OUT}" "${allowed_redacted}")" "yes"
check "ALLOWED filter -> drops DENIED record (keyword isolation)" "$(contains "${LAST_OUT}" 'DENIED')" "no"

## dedup: two DENIED records differing ONLY in the sed-stripped pid collapse to
## one line -- pins that BOTH sed (redaction) and awk (dedup) ran.
dup_a='type=AVC msg=audit(1.0:9): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/shadow" pid=111 comm="foo" fsuid=0'
dup_b='type=AVC msg=audit(1.0:9): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/shadow" pid=222 comm="foo" fsuid=0'
run_filter DENIED <<< "$(printf '%s\n' "${dup_a}" "${dup_b}")"
check "duplicate DENIED (differ only by pid) -> deduped to one line" "$(count_lines_with "${LAST_OUT}" "${denied_redacted}")" "1"

## distinct denials are NOT over-deduped: two records differing in a field sed
## does NOT strip (the path) both survive.
other_line='type=AVC msg=audit(1.0:7): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/passwd" pid=333 comm="foo" fsuid=0'
run_filter DENIED <<< "$(printf '%s\n' "${denied_line}" "${other_line}")"
check "distinct DENIED records -> both kept (shadow)" "$(contains "${LAST_OUT}" 'name="/etc/shadow"')" "yes"
check "distinct DENIED records -> both kept (passwd)" "$(contains "${LAST_OUT}" 'name="/etc/passwd"')" "yes"

## a NUL byte elsewhere in the stream must not make grep's binary heuristic drop
## the (ASCII) denial. A NUL cannot live in a shell string, so feed it as a real
## stream via a pipe into the function. 'printf %s\0' is the R-030-allowed way to
## emit one.
nul_rc=0
nul_out="$( { printf '%s\n' "${denied_line}"; printf '%s\0' 'type=AVC embedded'; printf '%s\n' 'tail'; } \
   | apparmor_info_filter DENIED )" || nul_rc=$?
check "NUL in stream -> return 0" "${nul_rc}" "0"
check "NUL in stream -> DENIED record not dropped (--text)" "$(contains "${nul_out}" "${denied_redacted}")" "yes"

## a NUL byte INSIDE a matching record must be PRESERVED, not silently dropped:
## two DENIED records differing ONLY by a NUL must stay DISTINCT (2 lines), not
## collapse to one. A buffered '$(grep ...)' filter drops the NUL (bash strips
## NULs from a command substitution) so 'sha<NUL>dow' becomes 'shadow', the two
## records become identical, awk dedups, and a denial DISAPPEARS. A streaming
## grep|sed|awk filter never puts the record in a variable, so the NUL survives.
## Fed as a real stream (a NUL cannot live in a shell string); the NUL is built
## from R-030-allowed printf forms and the output LINE COUNT is NUL-free to
## capture safely.
nul_shadow='apparmor="DENIED" name="/etc/shadow" pid=1 comm="x" fsuid=1'
nul_merge_lines="$( {
   printf '%s\n' "${nul_shadow}"
   printf '%s' 'apparmor="DENIED" name="/etc/sha'
   printf '%s\0' ''
   printf '%s\n' 'dow" pid=2 comm="x" fsuid=1'
} | apparmor_info_filter DENIED | wc -l | tr -d ' ')"
check "NUL inside a record -> distinct records kept, not merged" "${nul_merge_lines}" "2"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
