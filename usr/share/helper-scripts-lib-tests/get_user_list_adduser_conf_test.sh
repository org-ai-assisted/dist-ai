#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## get-user-list reads FIRST_UID/LAST_UID from /etc/adduser.conf to bound the
## human-user UID range. adduser SHELL-SOURCES that file, so a duplicated key
## means the LAST assignment wins.
##
## THE BUG: the old code grepped ALL matching lines, so a duplicated FIRST_UID
## produced a multi-line value that failed the strict-numeric check and aborted
## the script ("not strictly numeric"). The fix anchors the key and takes the
## last line, matching adduser.
##
## Drives the REAL get-user-list with fixture files injected via the
## GET_USER_LIST_ADDUSER_CONF / GET_USER_LIST_PASSWD overrides (no root, no
## touching the system's /etc). No network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/get-user-list"
else
   subject='/usr/libexec/helper-scripts/get-user-list'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: get-user-list not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/get-user-list-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap test_cleanup_handler EXIT

## A passwd shared by every case: root (special-cased in), bob (uid 1200),
## alice (uid 2500).
passwd_file="${work_dir}/passwd"
printf '%s\n' \
   'root:x:0:0:root:/root:/bin/bash' \
   'bob:x:1200:1200::/home/bob:/bin/bash' \
   'alice:x:2500:2500::/home/alice:/bin/bash' >"${passwd_file}"

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## $1 desc, $2 adduser.conf contents, then runs the subject and captures.
run_case() {
   local conf_file
   conf_file="${work_dir}/adduser.conf"
   printf '%s' "$2" >"${conf_file}"
   run_rc=0
   run_out="$(
      GET_USER_LIST_ADDUSER_CONF="${conf_file}" \
      GET_USER_LIST_PASSWD="${passwd_file}" \
      "${subject}"
   )" || run_rc=$?
}

## Duplicated FIRST_UID/LAST_UID: last wins (FIRST_UID=2000), so bob (1200) is
## below the range and excluded; alice (2500) and root remain.
run_case "duplicate keys" $'FIRST_UID=1000\nFIRST_UID=2000\nLAST_UID=1500\nLAST_UID=59999\n'
if [ "${run_rc}" -eq 0 ]; then
   ok "duplicate keys: exit 0 (old code aborted on the multi-line value)"
else
   notok "duplicate keys: expected exit 0, got ${run_rc}"
fi
if grep --quiet --line-regexp -- 'alice' <<<"${run_out}" \
   && grep --quiet --line-regexp -- 'root' <<<"${run_out}"; then
   ok "duplicate keys: root and alice listed"
else
   notok "duplicate keys: expected root and alice, got: ${run_out//$'\n'/,}"
fi
if grep --quiet --line-regexp -- 'bob' <<<"${run_out}"; then
   notok "duplicate keys: bob listed, so the last FIRST_UID (2000) was not used"
else
   ok "duplicate keys: bob excluded (last FIRST_UID=2000 honored)"
fi

## A single normal key set still works.
run_case "single keys" $'FIRST_UID=1000\nLAST_UID=59999\n'
if [ "${run_rc}" -eq 0 ] \
   && grep --quiet --line-regexp -- 'bob' <<<"${run_out}" \
   && grep --quiet --line-regexp -- 'alice' <<<"${run_out}"; then
   ok "single keys: bob and alice listed (range 1000-59999)"
else
   notok "single keys: rc=${run_rc}, out: ${run_out//$'\n'/,}"
fi

## A non-numeric value must still be rejected.
run_case "non-numeric" $'FIRST_UID=notanumber\nLAST_UID=59999\n'
if [ "${run_rc}" -ne 0 ]; then
   ok "non-numeric FIRST_UID is rejected (exit ${run_rc})"
else
   notok "non-numeric FIRST_UID was accepted"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
