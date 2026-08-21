#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sources SUBJECT (the real curl-prgrs) and drives its
## pure functions in-process; errexit is undesirable while probing many inputs.
##
## Property fuzz for curl-prgrs' pure functions. Drives the REAL bash functions
## over many random inputs and asserts their invariants. Deterministic given a
## seed, so CI reproduces. Usage: curl_prgrs_fuzz.sh SEED ITERATIONS. Prints one
## 'FUZZFAILS=N' line; N>0 also prints each violation.

# shellcheck disable=SC1090
source "${SUBJECT}"

RANDOM="${1}"
iters="${2}"
fails=0

note() {
   printf '%s\n' "FUZZ VIOLATION: ${1}"
   fails=$(( fails + 1 ))
}

is_whole() {
   [[ "${1}" =~ ^(0|[1-9][0-9]*)$ ]]
}

## Every argument (an output element) must appear, in order, in the input array
## "in_args". An empty output is trivially a subsequence.
subseq() {
   [ "$#" -eq 0 ] && return 0
   local needle idx=0 found
   while IFS= read -r needle; do
      found=1
      while [ "${idx}" -lt "${#in_args[@]}" ]; do
         if [ "${in_args[${idx}]}" = "${needle}" ]; then
            idx=$(( idx + 1 ))
            found=0
            break
         fi
         idx=$(( idx + 1 ))
      done
      [ "${found}" -eq 0 ] || return 1
   done < <(printf '%s\n' "$@")
   return 0
}

i=0
while [ "${i}" -lt "${iters}" ]; do
   i=$(( i + 1 ))

   ## compute_percent: contract inputs (non-negative whole numbers). Result is a
   ## whole number in 0..100. bytes*100 stays in the int64 domain (bytes < ~1e9).
   b=$(( RANDOM * RANDOM ))
   l=$(( RANDOM * RANDOM + 1 ))
   p="$(compute_percent "${b}" "${l}")"
   if ! is_whole "${p}" || [ "${p}" -gt 100 ]; then
      note "compute_percent b=${b} l=${l} -> ${p}"
   fi
   ## length 0 must map to 100, never divide by zero.
   if [ "$(compute_percent "${b}" 0)" != "100" ]; then
      note "compute_percent b=${b} l=0 -> $(compute_percent "${b}" 0)"
   fi

   ## classify_download_size: verdict is always one of the four codes.
   mx=$(( RANDOM * RANDOM + 1 ))
   cl=$(( RANDOM * RANDOM + 1 ))
   min=$(( mx < cl ? mx : cl ))
   sz=$(( RANDOM % (min + 1) ))
   code="$(classify_download_size "${sz}" "${mx}" "${cl}")"
   case "${code}" in
      0 | 81 | 113 | 114)
         ;;
      *)
         note "classify verdict sz=${sz} mx=${mx} cl=${cl} -> ${code}"
         ;;
   esac
   ## sz <= min(mx,cl) and whole -> within bounds -> 0.
   if [ "${code}" != "0" ]; then
      note "classify within-bounds not 0: sz=${sz} mx=${mx} cl=${cl} -> ${code}"
   fi
   ## a non-numeric size must be rejected as 113.
   garbage="g${RANDOM}x"
   gcode="$(classify_download_size "${garbage}" "${mx}" "${cl}")"
   if [ "${gcode}" != "113" ]; then
      note "classify non-numeric size=${garbage} -> ${gcode} (want 113)"
   fi

   ## remove_argument_for_header_request: output is a subsequence of input and
   ## strips each recognized flag together with the value after it.
   declare -a in_args=()
   argc=$(( RANDOM % 7 ))
   j=0
   while [ "${j}" -lt "${argc}" ]; do
      j=$(( j + 1 ))
      case $(( RANDOM % 7 )) in
         0)
            in_args+=("-o")
            ;;
         1)
            in_args+=("--output")
            ;;
         2)
            in_args+=("-C")
            ;;
         3)
            in_args+=("--continue-at")
            ;;
         4)
            in_args+=("url${RANDOM}")
            ;;
         5)
            in_args+=("-sSL")
            ;;
         *)
            in_args+=("-")
            ;;
      esac
   done
   remove_argument_for_header_request "${in_args[@]}"
   if ! subseq "${header_arguments[@]}"; then
      note "remove_argument not a subsequence: in=[${in_args[*]}] out=[${header_arguments[*]}]"
   fi
done

printf '%s\n' "FUZZFAILS=${fails}"
