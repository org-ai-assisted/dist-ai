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

## --- seconds remainder on carry (increment within the 0-60 range) ------------
## The old reset-to-0 dropped the seconds remainder and capped accumulation at
## ~1 minute/call; both cases below read 0:1:0 on that broken code.
td="$(make_timedir sec_remainder seconds=59)"
out="$("${subject}" -y 2013 -m 12 -d 30 -i 7 -f "${td}")"
check "seconds 59 + 7 -> remainder kept 0:1:6" "${out}" "2013-12-30 0:1:6"

td="$(make_timedir sec_remainder_max seconds=55)"
out="$("${subject}" -y 2013 -m 12 -d 30 -i 60 -f "${td}")"
check "seconds 55 + 60 -> remainder kept 0:1:55" "${out}" "2013-12-30 0:1:55"

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
check_err "-m non-number rejected" "month is not a digit." -m abc
check_err "-d non-number rejected" "day is not a digit." -d abc

## The documented 0-60 increment range is enforced (an out-of-range value would
## otherwise overflow bash arithmetic and store a negative/garbage time). The
## 2^63 case is the overflow canary: a bare '-gt 60' wraps it negative and lets
## it through, so the guard must reject it by length.
check_err "-i above 60 rejected" "increment must be between 0 and 60." -i 61
check_err "-i far out of range rejected" "increment must be between 0 and 60." -i 125
check_err "-i 2^63 overflow value rejected" "increment must be between 0 and 60." -i 9223372036854775808
check_err "-r above 60 rejected" "randomincrement must be between 1 and 60." -r 61
## is_whole_number accepts 0, but 'random-between 1 0' crashes; reject it cleanly.
check_err "-r 0 rejected (not a random-between crash)" "randomincrement must be between 1 and 60." -r 0

## -h prints usage and exits 0 (needs no TIMEDIR; must not be treated as error).
help_rc=0
help_out="$("${subject}" -h 2>&1)" || help_rc=$?
if [ "${help_rc}" -eq 0 ] && [[ "${help_out}" == *"Usage:"* ]]; then
   printf '%s\n' "PASS: -h prints usage and exits 0"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: -h usage (rc='${help_rc}', out='${help_out}')"
   fail=$((fail + 1))
fi

## --- file-content sanitization + leading-zero (base-10) arithmetic. ---
## run_tp captures the subject's exit status so a REGRESSED subject that aborts
## (octal arithmetic on a leading-zero counter: "08: value too great for base")
## reports a clean FAIL here instead of killing the whole suite under errexit --
## i.e. these stay honest canaries (RED on broken code) rather than crashing out.
tp_out=""
run_tp() {
   ## A crash (e.g. regressed octal arithmetic) yields the sentinel, so check()
   ## reports a clean FAIL instead of errexit aborting the suite.
   tp_out="$("${subject}" "$@")" || tp_out="__SUBJECT_CRASHED__"
}

## Zero-padded date components (forums.whonix.org/t/23643 Bug #1): 'date +%d' /
## '+%m' yield '05', '09'; passed verbatim to faketime, not used in arithmetic,
## so a leading zero is valid. The hardened is_whole_number rejected them -> the
## DEFAULT date broke on days/months 01-09. A regressed subject exits 1 ("day is
## not a digit."), so run_tp captures that as a clean FAIL (sentinel) here.
td="$(make_timedir zeropad_day)"
run_tp -y 2026 -m 09 -d 05 -i 1 -f "${td}"
check "zero-padded -d 05 -m 09 accepted" "${tp_out}" "2026-09-05 0:0:1"

td="$(make_timedir zeropad_single)"
run_tp -y 2026 -m 01 -d 09 -i 1 -f "${td}"
check "zero-padded -d 09 -m 01 accepted" "${tp_out}" "2026-01-09 0:0:1"

## A non-digit or partial-garbage counter file is treated as 0 (read_date_file's
## sed nodigits guard), never propagated.
td="$(make_timedir garbage_sec seconds=abc)"
run_tp -y 2013 -m 12 -d 30 -i 1 -f "${td}"
check "non-digit seconds file -> treated as 0 (0:0:1)" "${tp_out}" "2013-12-30 0:0:1"

td="$(make_timedir partial_sec seconds=1x2)"
run_tp -y 2013 -m 12 -d 30 -i 1 -f "${td}"
check "partial-garbage seconds file -> reset to 0 (0:0:1)" "${tp_out}" "2013-12-30 0:0:1"

## Leading-zero counter content is a DECIMAL count, not octal. An all-digit value
## bypasses is_whole_number (only the nodigits guard runs), so bash arithmetic
## must be forced to base 10: "08"/"09" would otherwise abort ("value too great
## for base") and "012" would silently become 10. One case per arithmetic site
## (seconds always, minutes/hours on carry).
td="$(make_timedir octal_sec seconds=08)"
run_tp -y 2013 -m 12 -d 30 -i 1 -f "${td}"
check "leading-zero seconds '08' is decimal 8 (0:0:9)" "${tp_out}" "2013-12-30 0:0:9"

td="$(make_timedir octal_sec_12 seconds=012)"
run_tp -y 2013 -m 12 -d 30 -i 1 -f "${td}"
check "leading-zero seconds '012' is decimal 12 (0:0:13)" "${tp_out}" "2013-12-30 0:0:13"

td="$(make_timedir octal_min seconds=59 minutes=09)"
run_tp -y 2013 -m 12 -d 30 -i 1 -f "${td}"
check "leading-zero minutes '09' on carry is decimal 9 (0:10:0)" "${tp_out}" "2013-12-30 0:10:0"

td="$(make_timedir octal_hr seconds=59 minutes=59 hours=08)"
run_tp -y 2013 -m 12 -d 30 -i 1 -f "${td}"
check "leading-zero hours '08' on carry is decimal 8 (9:0:0)" "${tp_out}" "2013-12-30 9:0:0"

## --- auto-provision: a missing TIMEDIR is created and seeded, not an error. ---
auto_dir="${test_dir}/autoprov"
out="$("${subject}" -y 2013 -m 12 -d 30 -i 1 -f "${auto_dir}")"
check "missing TIMEDIR auto-provisioned (0:0:1)" "${out}" "2013-12-30 0:0:1"
if [ -f "${auto_dir}/seconds_file" ] && [ -f "${auto_dir}/minutes_file" ] \
   && [ -f "${auto_dir}/hours_file" ]; then
   printf '%s\n' "PASS: missing TIMEDIR: counter files seeded"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: missing TIMEDIR: counter files not created"
   fail=$((fail + 1))
fi

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

## --- property fuzz: drive the REAL time_privacy over many random inputs (option
## parser + counter-file content) and assert the crash-free / known-rejection /
## in-range-success invariants. Deterministic given the seed; override the
## seed/iteration count via env, and the seed is printed so a finding reproduces.
fuzz_script="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/time_privacy_fuzz.sh"
if [ ! -x "${fuzz_script}" ]; then
   printf '%s\n' "FAIL: time_privacy_fuzz.sh not found/executable at '${fuzz_script}'"
   fail=$((fail + 1))
else
   fuzz_seed="${TIME_PRIVACY_FUZZ_SEED:-1}"
   fuzz_iters="${TIME_PRIVACY_FUZZ_ITERS:-150}"
   fuzz_out="$("${fuzz_script}" "${fuzz_seed}" "${fuzz_iters}" 2>&1)" || true
   fuzz_fails="$(printf '%s\n' "${fuzz_out}" | sed -n 's/^FUZZFAILS=//p')"
   if [ "${fuzz_fails:-missing}" = "0" ]; then
      printf '%s\n' "PASS: property fuzz: ${fuzz_iters} iterations, 0 invariant violations (seed ${fuzz_seed})"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: property fuzz: ${fuzz_fails:-missing} violation(s); reproduce with TIME_PRIVACY_FUZZ_SEED=${fuzz_seed} TIME_PRIVACY_FUZZ_ITERS=${fuzz_iters}"
      printf '%s\n' "${fuzz_out}" >&2
      fail=$((fail + 1))
   fi
fi

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
