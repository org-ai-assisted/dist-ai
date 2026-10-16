#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Property fuzz for the REAL time_privacy (uwt's faketime offset generator).
## Unlike the pure-function fuzzes (curl_prgrs_fuzz.sh, accountctl_fuzz.sh) which
## SOURCE their subject, time_privacy is a standalone script that runs on source,
## so this drives the ACTUAL binary as a subprocess over random inputs -- the
## closest existing analog is fuzz_curl_prgrs_e2e.py. Deterministic given a seed
## (seeded RANDOM, fixed iteration count), so CI reproduces; each run is wrapped
## in a per-run timeout so a hang is a finding, not a stall.
##
## Usage: time_privacy_fuzz.sh SEED ITERATIONS. Prints one 'FUZZFAILS=N' line;
## N>0 also prints each violation. The driver (time_privacy_test.sh) reads
## FUZZFAILS and accounts for it; UWT_REPO / HELPER_SCRIPTS_PATH resolve the
## subject and its siblings exactly as in the driver.
##
## Invariants asserted across random inputs:
##   - never crashes with an unexpected (non-validation) error;
##   - on success it prints exactly ONE line YEAR-MONTH-DAY HOURS:MINUTES:SECONDS
##     with in-range clock fields (hours 0-23, minutes 0-59, seconds 0-59);
##   - a rejected input exits nonzero with a KNOWN validation message;
##   - it never hangs (each run is bounded by a timeout).
##
## SCOPE -- honest. Two input surfaces are fuzzed:
##   (A) the option parser over the DEFINED flags (-y/-m/-d/-i/-r + -h) with
##       values drawn from {valid whole, non-digit garbage, leading-zero digit}
##       and every -i/-r combination. The vestigial '*)' to-be-wrapped-command
##       branch (time_privacy is only ever invoked to PRINT an offset, never to
##       exec a command) is out of scope -- an unresolvable trailing token or an
##       unknown '-x' option errexits with no diagnostic there, a pre-existing
##       quirk flagged separately, not a property of the offset generator.
##   (B) the counter-file content (seconds/minutes/hours) over in-range digits
##       with optional leading zeros, non-digit garbage, and empty -- within the
##       state-file contract (the script writes only in-range values), the domain
##       where correct carry/wrap output is guaranteed.
## The literal sentinel "none" and the empty option VALUE are not generated:
## they collide with the script's internal defaulting (a separate quirk, not the
## property under test).

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

## REQUIRED dependencies: a missing subject / helper library / stcat / timeout is
## an environment bug -> exit 1 (FATAL), never a silent FUZZFAILS=0 green.
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
if ! type -P timeout >/dev/null; then
   printf '%s\n' "FATAL: 'timeout' not on PATH (coreutils)" >&2
   exit 1
fi

RANDOM="${1:?seed required}"
iters="${2:?iteration count required}"
fails=0

base_dir="$(mktemp --directory)"
cleanup_handler() {
   ## '|| true': a cleanup failure must not clobber the real exit code.
   safe-rm -r -f -- "${base_dir}" || true
}
trap cleanup_handler EXIT

note() {
   printf '%s\n' "FUZZ VIOLATION: ${1}"
   fails=$(( fails + 1 ))
}

## Mirror helper-scripts is_whole_number: ^(0|[1-9][0-9]*)$ (no leading zero,
## no sign, no non-digit). The oracle classifies every generated value with it.
is_whole() {
   [[ "${1}" =~ ^(0|[1-9][0-9]*)$ ]]
}

## A per-run fresh TIMEDIR; echoes its path.
fresh_dir() {
   local dir
   dir="$(mktemp --directory --tmpdir="${base_dir}")"
   printf '%s' "${dir}"
}

## Run the subject with a hard per-run timeout. Sets globals run_rc / run_out.
run_subject() {
   run_rc=0
   run_out="$(timeout --kill-after=5 10 "${subject}" "$@" 2>&1)" || run_rc=$?
}

## Non-digit garbage tokens: none is a valid whole number, none is the "none"
## sentinel, none is empty. Each must be REJECTED as an option value and treated
## as 0 as counter-file content.
garbage=( "x" "1a" "a1" "12x" "-3" "+5" "3.0" "!" " 5" "a" )

## A leading-zero digit string for 0..max (e.g. 8 -> "08", 12 -> "012"): a valid
## decimal count that is NOT a whole number per is_whole_number, so it is rejected
## as an option value and is the octal-interpretation target as counter content.
gen_leading_zero() {
   printf '%s' "0$(( RANDOM % ( ${1} + 1 ) ))"
}

## A field value in one of the three classes. $1 = field kind (controls the
## valid range): "r" (1..59, random-between needs >=1), "i" (0..59), "ymd-y"
## (1..3000), "ymd-m" (1..12), "ymd-d" (1..28).
gen_value() {
   local kind="${1}" cls=$(( RANDOM % 3 ))
   case "${cls}" in
      0)
         case "${kind}" in
            r)
               printf '%s' "$(( RANDOM % 59 + 1 ))"
               ;;
            i)
               printf '%s' "$(( RANDOM % 60 ))"
               ;;
            ymd-y)
               printf '%s' "$(( RANDOM % 3000 + 1 ))"
               ;;
            ymd-m)
               printf '%s' "$(( RANDOM % 12 + 1 ))"
               ;;
            ymd-d)
               printf '%s' "$(( RANDOM % 28 + 1 ))"
               ;;
         esac
         ;;
      1)
         printf '%s' "${garbage[$(( RANDOM % ${#garbage[@]} ))]}"
         ;;
      2)
         gen_leading_zero 59
         ;;
   esac
}

## In-range counter-file content: plain digits, leading-zero digits, non-digit
## garbage, or empty. $1 = max (59 for seconds/minutes, 23 for hours).
gen_counter() {
   local max="${1}" cls=$(( RANDOM % 4 ))
   case "${cls}" in
      0)
         printf '%s' "$(( RANDOM % ( max + 1 ) ))"
         ;;
      1)
         printf '%s' "0$(( RANDOM % ( max + 1 ) ))"
         ;;
      2)
         printf '%s' "${garbage[$(( RANDOM % ${#garbage[@]} ))]}"
         ;;
      3)
         printf '%s' ""
         ;;
   esac
}

## The script's kept representation of a counter file: an all-digit string is
## kept verbatim (a decimal count, base 10 -- NOT octal); anything else
## (non-digit, empty) is reset to "0". A field printed WITHOUT a carry reaching
## it keeps this verbatim string (leading zeros and all); a field the carry DOES
## reach is replaced by a normalized integer ($(( 10#value + 1 ))).
counter_keep() {
   if [[ "${1}" =~ ^[0-9]+$ ]]; then
      printf '%s' "${1}"
   else
      printf '%s' 0
   fi
}

## --- mode A: the option parser + validation ladder ---
fuzz_options() {
   local dir yv mv dv iv rv r_present i_present
   dir="$(fresh_dir)"

   ## 1/12 of the time, the bare -h path: usage on stdout, exit 0.
   if [ "$(( RANDOM % 12 ))" -eq 0 ]; then
      run_subject -h
      if [ "${run_rc}" -ne 0 ]; then
         note "option -h: expected exit 0, got rc=${run_rc} out='${run_out}'"
         return
      fi
      if [[ "${run_out}" != *"Usage:"* ]]; then
         note "option -h: usage text missing, out='${run_out}'"
      fi
      return
   fi

   yv="$(gen_value ymd-y)"
   mv="$(gen_value ymd-m)"
   dv="$(gen_value ymd-d)"

   local -a argv=( -y "${yv}" -m "${mv}" -d "${dv}" )
   r_present=0
   i_present=0
   iv=""
   rv=""
   case "$(( RANDOM % 4 ))" in
      0)
         ## neither -i nor -r: the script defaults the increment to 1
         ;;
      1)
         iv="$(gen_value i)"
         argv+=( -i "${iv}" )
         i_present=1
         ;;
      2)
         rv="$(gen_value r)"
         argv+=( -r "${rv}" )
         r_present=1
         ;;
      3)
         iv="$(gen_value i)"
         rv="$(gen_value r)"
         argv+=( -i "${iv}" -r "${rv}" )
         i_present=1
         r_present=1
         ;;
   esac
   argv+=( -f "${dir}" )

   ## Expected outcome via the script's validation precedence. The order is fixed
   ## regardless of argv order: (-r & -i) > bad -r > bad -i > bad year > bad month
   ## > bad day > success.
   local expect_reject="" expect_msg=""
   if [ "${r_present}" -eq 1 ] && [ "${i_present}" -eq 1 ]; then
      expect_reject=1; expect_msg="You can not combine -r and -i."
   elif [ "${r_present}" -eq 1 ] && ! is_whole "${rv}"; then
      expect_reject=1; expect_msg="randomincrement must be a positive number."
   elif [ "${i_present}" -eq 1 ] && ! is_whole "${iv}"; then
      expect_reject=1; expect_msg="increment is not a digit."
   elif ! is_whole "${yv}"; then
      expect_reject=1; expect_msg="year is not a digit."
   elif ! is_whole "${mv}"; then
      expect_reject=1; expect_msg="month is not a digit."
   elif ! is_whole "${dv}"; then
      expect_reject=1; expect_msg="day is not a digit."
   fi

   run_subject "${argv[@]}"

   if [ "${run_rc}" -eq 124 ]; then
      note "option run HUNG (timeout): argv=[${argv[*]}]"
      return
   fi

   if [ -n "${expect_reject}" ]; then
      if [ "${run_rc}" -eq 0 ]; then
         note "option reject expected but succeeded: argv=[${argv[*]}] out='${run_out}'"
      elif [ "${run_out}" != "${expect_msg}" ]; then
         note "option reject wrong message: argv=[${argv[*]}] rc=${run_rc} out='${run_out}' want='${expect_msg}'"
      fi
      return
   fi

   ## Success path: exactly one in-range date line with the given Y-M-D prefix.
   if [ "${run_rc}" -ne 0 ]; then
      note "option success expected but rc=${run_rc}: argv=[${argv[*]}] out='${run_out}'"
      return
   fi
   if [ "$(printf '%s\n' "${run_out}" | wc -l)" -ne 1 ]; then
      note "option success not a single line: argv=[${argv[*]}] out='${run_out}'"
      return
   fi
   local re="^${yv}-${mv}-${dv} ([0-9]+):([0-9]+):([0-9]+)\$"
   if [[ ! "${run_out}" =~ ${re} ]]; then
      note "option success malformed line: argv=[${argv[*]}] out='${run_out}'"
      return
   fi
   local h="${BASH_REMATCH[1]}" m="${BASH_REMATCH[2]}" s="${BASH_REMATCH[3]}"
   if [ "${h}" -gt 23 ] || [ "${m}" -gt 59 ] || [ "${s}" -gt 59 ]; then
      note "option success out-of-range clock: argv=[${argv[*]}] out='${run_out}'"
      return
   fi
   ## Fresh TIMEDIR + increment < 60 means no carry: hours/minutes are 0 and the
   ## seconds equal the effective increment.
   if [ "${h}" != "0" ] || [ "${m}" != "0" ]; then
      note "option success unexpected carry on fresh dir: argv=[${argv[*]}] out='${run_out}'"
      return
   fi
   if [ "${i_present}" -eq 1 ]; then
      if [ "${s}" != "${iv}" ]; then
         note "option -i increment mismatch: argv=[${argv[*]}] seconds=${s} want=${iv}"
      fi
   elif [ "${r_present}" -eq 1 ]; then
      if [ "${s}" -lt 1 ] || [ "${s}" -gt "${rv}" ]; then
         note "option -r increment out of 1..${rv}: argv=[${argv[*]}] seconds=${s}"
      fi
   else
      if [ "${s}" != "1" ]; then
         note "option default increment not 1: argv=[${argv[*]}] seconds=${s}"
      fi
   fi
}

## --- mode B: counter-file content handling + carry/wrap ---
fuzz_counter() {
   local dir sc mc hc inc ks km kh s m h expected
   dir="$(fresh_dir)"
   sc="$(gen_counter 59)"
   mc="$(gen_counter 59)"
   hc="$(gen_counter 23)"
   inc="$(( RANDOM % 6 ))"
   printf '%s\n' "${sc}" > "${dir}/seconds_file"
   printf '%s\n' "${mc}" > "${dir}/minutes_file"
   printf '%s\n' "${hc}" > "${dir}/hours_file"

   ## Oracle: kept representations, then the script's carry/wrap. Seconds always
   ## go through base-10 arithmetic; minutes/hours keep their verbatim string
   ## unless a carry reaches them, in which case they become a normalized int.
   ks="$(counter_keep "${sc}")"
   km="$(counter_keep "${mc}")"
   kh="$(counter_keep "${hc}")"
   s=$(( 10#${ks} + inc ))
   m="${km}"
   h="${kh}"
   if [ "${s}" -ge 60 ]; then
      s=0
      m=$(( 10#${km} + 1 ))
      if [ "${m}" -ge 60 ]; then
         m=0
         h=$(( 10#${kh} + 1 ))
         if [ "${h}" -ge 24 ]; then
            h=0
         fi
      fi
   fi
   expected="2013-12-30 ${h}:${m}:${s}"

   run_subject -y 2013 -m 12 -d 30 -i "${inc}" -f "${dir}"

   if [ "${run_rc}" -eq 124 ]; then
      note "counter run HUNG (timeout): sec='${sc}' min='${mc}' hr='${hc}' inc=${inc}"
      return
   fi
   if [ "${run_rc}" -ne 0 ]; then
      note "counter run crashed rc=${run_rc}: sec='${sc}' min='${mc}' hr='${hc}' inc=${inc} out='${run_out}'"
      return
   fi
   if [ "${run_out}" != "${expected}" ]; then
      note "counter output mismatch: sec='${sc}' min='${mc}' hr='${hc}' inc=${inc} got='${run_out}' want='${expected}'"
   fi
}

i=0
while [ "${i}" -lt "${iters}" ]; do
   i=$(( i + 1 ))
   if [ "$(( RANDOM % 2 ))" -eq 0 ]; then
      fuzz_options
   else
      fuzz_counter
   fi
done

printf '%s\n' "FUZZFAILS=${fails}"
