#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## apparmor-info: a clean AppArmor boot has no DENIED/ALLOWED audit records, so the
## two 'journalctl ... | grep ...' pipelines match nothing and grep exits 1. Under
## errexit+pipefail+inherit_errexit that must NOT abort the script.
##
## REGRESSION: old code aborted at the first pipeline with exit 1 and no output.
## systemcheck's log-checker then surfaced that as a bogus "could not read the systemd
## journal", so 'systemcheck --cli --ci' check 8 FAILED on every clean installed-system
## run (verified bios+efi, builds 1974/1981). The fix wraps each grep in a brace group
## '{ grep "..." || true; }'.
##
## The assertions pin the FULL correct behaviour so a wrong "fix" cannot pass:
##   - clean/empty journal -> exit 0, byte-exact empty output (the regression).
##   - a genuine journalctl read failure (non-zero exit) must STILL propagate, not be
##     swallowed -- rules out a broad '"$(...)" || true' that masks the whole pipeline.
##   - a DENIED/ALLOWED record is reported AND redacted (pid=/fsuid= stripped), which
##     only holds if sed/awk still run -- rules out a naive 'grep "..." || true' whose
##     precedence is '(journalctl|grep) || (true|sed|awk)', skipping redaction on a match.
##
## Drives the REAL script. The only seams stubbed are journalctl (a privileged audit
## read) and the root guard, both via committed support scripts on PATH; grep, sed and
## awk are the real pipeline under test. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
journalctl_stub="${tool_dir}/apparmor_info_journalctl_stub.sh"
id_stub="${tool_dir}/apparmor_info_id_stub.sh"

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/sbin/apparmor-info"
else
   subject='/usr/sbin/apparmor-info'
fi

## The subject is a REQUIRED dependency: absent it means helper-scripts is not
## installed or HELPER_SCRIPTS_REPO is unset -- an environment bug, so FATAL (exit 1),
## never a skip (R-220). The test's own support scripts missing is likewise a FAIL.
if [ ! -x "${subject}" ]; then
   printf '%s\n' "FATAL: subject not executable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -x "${journalctl_stub}" ] || [ ! -x "${id_stub}" ]; then
   printf '%s\n' "FATAL: test support scripts missing next to '${tool_dir}'" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup_handler EXIT

## Stubs go on PATH under their real names; grep/sed/awk still resolve to the real
## tools from the inherited PATH.
bindir="${test_dir}/bin"
mkdir --parents -- "${bindir}"
ln -s -- "${journalctl_stub}" "${bindir}/journalctl"
ln -s -- "${id_stub}" "${bindir}/id"
stub_path="${bindir}:${PATH}"

fixtures_dir="${test_dir}/fixtures"
mkdir --parents -- "${fixtures_dir}"

## A clean boot still logs non-AppArmor-denial audit records (SYSCALL, profile-load
## STATUS, ...); the parser must match none of them.
clean_fixture="${fixtures_dir}/clean.txt"
{
   printf '%s\n' 'type=SYSCALL msg=audit(1.0:2): arch=c000003e syscall=59 success=yes exit=0'
   printf '%s\n' 'type=AVC msg=audit(1.0:3): apparmor="STATUS" operation="profile_load" name="/usr/bin/foo"'
} >"${clean_fixture}"

## An empty journal (no audit records at all).
empty_fixture="${fixtures_dir}/empty.txt"
touch -- "${empty_fixture}"

## The pid=/comm=/fsuid= fields are what the subject's sed redaction strips.
denied_line='type=AVC msg=audit(1.0:4): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/shadow" pid=123 comm="foo" fsuid=0'
allowed_line='type=AVC msg=audit(1.0:5): apparmor="ALLOWED" operation="open" profile="/usr/bin/bar" name="/srv/example" pid=124 comm="bar" fsuid=0'

denied_fixture="${fixtures_dir}/denied.txt"
printf '%s\n' "${denied_line}" >"${denied_fixture}"
allowed_fixture="${fixtures_dir}/allowed.txt"
printf '%s\n' "${allowed_line}" >"${allowed_fixture}"
both_fixture="${fixtures_dir}/both.txt"
{ printf '%s\n' "${denied_line}"; printf '%s\n' "${allowed_line}"; } >"${both_fixture}"

out_file="${test_dir}/subject.out"
LAST_RC=0
LAST_OUT=""
LAST_BYTES=0
run_subject() {
   ## $1 = fixture file; $2 = journalctl exit code (default 0).
   local fixture rc
   fixture="$1"
   rc="${2:-0}"
   LAST_RC=0
   APPARMOR_INFO_STUB_FIXTURE="${fixture}" APPARMOR_INFO_STUB_RC="${rc}" \
      PATH="${stub_path}" "${subject}" --boot >"${out_file}" 2>/dev/null || LAST_RC=$?
   ## Byte-exact: command substitution would strip trailing newlines, so a lone '\n'
   ## would read as empty. Count bytes from the file instead.
   LAST_BYTES="$(wc -c <"${out_file}" | tr -d ' ')"
   LAST_OUT="$(cat -- "${out_file}")"
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

nonzero() {
   if [ "$1" -ne 0 ]; then
      printf '%s' nonzero
   else
      printf '%s' zero
   fi
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

## (1) clean boot: no DENIED/ALLOWED -> exit 0, byte-exact empty. The regression.
run_subject "${clean_fixture}"
check "clean boot -> exit 0" "${LAST_RC}" "0"
check "clean boot -> empty output (0 bytes)" "${LAST_BYTES}" "0"

## (2) empty journal -> exit 0, byte-exact empty. Same abort on old code.
run_subject "${empty_fixture}"
check "empty journal -> exit 0" "${LAST_RC}" "0"
check "empty journal -> empty output (0 bytes)" "${LAST_BYTES}" "0"

## (3) a genuine journalctl read failure must still propagate, not be swallowed.
run_subject "${empty_fixture}" 1
check "journalctl read failure -> non-zero exit (not swallowed)" "$(nonzero "${LAST_RC}")" "nonzero"

## (4) a DENIED record -> exit 1, reported AND redacted (sed/awk ran).
run_subject "${denied_fixture}"
check "DENIED present -> exit 1" "${LAST_RC}" "1"
check "DENIED present -> denial reported" "$(contains "${LAST_OUT}" 'DENIED')" "yes"
check "DENIED present -> pid= redacted" "$(contains "${LAST_OUT}" 'pid=')" "no"
check "DENIED present -> fsuid= redacted" "$(contains "${LAST_OUT}" 'fsuid=')" "no"

## (5) an ALLOWED record -> exit 1, reported AND redacted.
run_subject "${allowed_fixture}"
check "ALLOWED present -> exit 1" "${LAST_RC}" "1"
check "ALLOWED present -> allowance reported" "$(contains "${LAST_OUT}" 'ALLOWED')" "yes"
check "ALLOWED present -> pid= redacted" "$(contains "${LAST_OUT}" 'pid=')" "no"
check "ALLOWED present -> fsuid= redacted" "$(contains "${LAST_OUT}" 'fsuid=')" "no"

## (6) both -> exit 1, both reported and redacted.
run_subject "${both_fixture}"
check "both present -> exit 1" "${LAST_RC}" "1"
check "both present -> DENIED reported" "$(contains "${LAST_OUT}" 'DENIED')" "yes"
check "both present -> ALLOWED reported" "$(contains "${LAST_OUT}" 'ALLOWED')" "yes"
check "both present -> pid= redacted" "$(contains "${LAST_OUT}" 'pid=')" "no"
check "both present -> fsuid= redacted" "$(contains "${LAST_OUT}" 'fsuid=')" "no"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
