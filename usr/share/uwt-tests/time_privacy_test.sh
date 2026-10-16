#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## time_privacy: the faketime offset generator uwt uses for Time Privacy.
##
## Drives the REAL usr/bin/time_privacy end to end and asserts:
##   - the seconds->minutes->hours carry and the 24h wrap in read_date_file;
##   - the default increment (1) when neither -i nor -r is given;
##   - argument validation (mutually-exclusive -r/-i, is_whole_number on the
##     increment / year / month / day, is_whole_number on -r);
##   - the -r random path runs (exercises the random-between dependency).
##
## The emitted line is "YEAR-MONTH-DAY HOURS:MINUTES:SECONDS"; the clock fields
## are plain arithmetic results (not zero-padded). A fixed -y/-m/-d and a
## pre-seeded per-case TIMEDIR make every expectation deterministic.
##
## Targets the installed package by default; set UWT_REPO to test a checkout
## (then HELPER_SCRIPTS_PATH must point at a helper-scripts checkout so the
## subject can source strings.bsh and reach random-between, and its usr/bin is
## put on PATH for stcat). A missing subject / helper library / stcat is a
## REQUIRED-dependency environment bug -> exit 1 (FATAL), never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v UWT_REPO ] || UWT_REPO=""
if [ -n "${UWT_REPO}" ]; then
   subject="${UWT_REPO}/usr/bin/time_privacy"
else
   subject='/usr/bin/time_privacy'
fi

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
export HELPER_SCRIPTS_PATH
strings_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh"

## stcat lives in helper-scripts usr/bin; the subject calls it as a bare command.
if [ -n "${HELPER_SCRIPTS_PATH}" ]; then
   PATH="${HELPER_SCRIPTS_PATH}/usr/bin:${PATH}"
   export PATH
fi

if [ ! -x "${subject}" ]; then
   printf '%s\n' "FATAL: subject not executable at '${subject}'" >&2
   printf '%s\n' "set UWT_REPO to a uwt checkout, or install uwt" >&2
   exit 1
fi
if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if ! type -P stcat >/dev/null; then
   printf '%s\n' "FATAL: 'stcat' not on PATH (helper-scripts usr/bin)" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   ## '|| true': a cleanup failure must not clobber the script's real exit code.
   safe-rm -r -f -- "${test_dir}" || true
}
trap cleanup_handler EXIT

pass=0
fail=0
check() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Fresh TIMEDIR per case; optionally pre-seed the counter files. $1 case name,
## then NAME=VALUE pairs 'seconds=..' 'minutes=..' 'hours=..'. Echoes the dir.
make_timedir() {
   local name="$1"; shift
   local dir="${test_dir}/${name}" kv k v
   mkdir -p -- "${dir}"
   for kv in "$@"; do
      k="${kv%%=*}"
      v="${kv#*=}"
      printf '%s\n' "${v}" > "${dir}/${k}_file"
   done
   printf '%s\n' "${dir}"
}

## --- carry / wrap / default-increment (fixed date 2013-12-30) ---
td="$(make_timedir default_inc)"
out="$("${subject}" -y 2013 -m 12 -d 30 -f "${td}")"
check "default increment (1), empty TIMEDIR -> 0:0:1" "${out}" "2013-12-30 0:0:1"

td="$(make_timedir sec_carry seconds=59)"
out="$("${subject}" -y 2013 -m 12 -d 30 -i 1 -f "${td}")"
check "seconds 59 + 1 -> minute carry 0:1:0" "${out}" "2013-12-30 0:1:0"

td="$(make_timedir min_carry seconds=59 minutes=59)"
out="$("${subject}" -y 2013 -m 12 -d 30 -i 1 -f "${td}")"
check "minutes 59 + carry -> hour carry 1:0:0" "${out}" "2013-12-30 1:0:0"

td="$(make_timedir hour_wrap seconds=59 minutes=59 hours=23)"
out="$("${subject}" -y 2013 -m 12 -d 30 -i 1 -f "${td}")"
check "hours 23 + carry -> 24h wrap 0:0:0" "${out}" "2013-12-30 0:0:0"

## --- validation (expect exit 1 with the specific message on stdout) ---
check_err() {
   local label="$1"; shift
   local want_msg="$1"; shift
   local td_err out rc=0
   td_err="$(make_timedir "err_$$_${pass}_${fail}")"
   out="$("${subject}" "$@" -f "${td_err}" 2>&1)" || rc=$?
   if [ "${rc}" -ne 0 ] && [ "${out}" = "${want_msg}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (rc='${rc}', out='${out}', want msg '${want_msg}')"
      fail=$((fail + 1))
   fi
}

check_err "-r and -i are mutually exclusive" "You can not combine -r and -i." -r 5 -i 3
check_err "-r non-number rejected" "randomincrement must be a positive number." -r abc
check_err "-i non-number rejected" "increment is not a digit." -i abc
check_err "-y non-number rejected" "year is not a digit." -y abc

## --- -r random path runs (exercises random-between); output is a valid line ---
td="$(make_timedir rand)"
rc=0
out="$("${subject}" -y 2013 -m 12 -d 30 -r 5 -f "${td}")" || rc=$?
if [ "${rc}" -eq 0 ] && [[ "${out}" =~ ^2013-12-30\ 0:0:[1-5]$ ]]; then
   printf '%s\n' "PASS: -r random path produced a valid offset ('${out}')"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: -r random path (rc='${rc}', out='${out}')"
   fail=$((fail + 1))
fi

## --- offset must NOT depend on how long the script runs. SECONDS is bash's
## elapsed-time special variable; used as a plain counter it drifts by the
## runtime. Force >=1s between the SECONDS read and the arithmetic by slowing
## stcat (a latency injector that execs the REAL stcat), and assert the result
## is unchanged. This deterministically distinguishes the fixed code from the
## drift bug (which would yield 0:0:3 here). ---
real_stcat="$(type -P stcat)"
slow_bin="${test_dir}/slow_bin"
mkdir -p -- "${slow_bin}"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'sleep 1'
   printf '%s\n' "exec ${real_stcat@Q} \"\$@\""
} > "${slow_bin}/stcat"
chmod 0755 -- "${slow_bin}/stcat"
td="$(make_timedir slow seconds=0)"
out="$(PATH="${slow_bin}:${PATH}" "${subject}" -y 2013 -m 12 -d 30 -i 1 -f "${td}")"
check "offset independent of runtime (SECONDS not special)" "${out}" "2013-12-30 0:0:1"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
