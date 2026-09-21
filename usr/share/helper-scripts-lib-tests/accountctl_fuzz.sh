#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sources SUBJECT (the real accountctl.sh) and drives its
## pure functions in-process; errexit is undesirable while probing many inputs.

## Property fuzz for accountctl.sh's pure functions. Drives the REAL bash
## functions over many random inputs and asserts their invariants. Deterministic
## given a seed, so CI reproduces. Usage: accountctl_fuzz.sh SEED ITERATIONS.
## Prints one 'FUZZFAILS=N' line; N>0 also prints each violation.
##
## HELPER_SCRIPTS_PATH must be set so SUBJECT resolves its siblings (has.bsh,
## as_root.sh, log_run_die.sh); the driver (accountctl_test.sh) sets it.

# shellcheck disable=SC1090
source "${SUBJECT}"

## The subject MUST define every function fuzzed below. A missing one means a
## stale/wrong accountctl.sh: FATAL, not a silent no-op. Without this, calling an
## absent function returns 127 ("command not found"), which the invariant checks
## read as an ordinary false -- so the fuzz reports FUZZFAILS=0 while testing
## nothing.
for fn in is_name_valid escape_name get_clean_pass get_field group_has_nonroot_member; do
   if ! declare -F "${fn}" >/dev/null 2>&1; then
      printf '%s\n' "FATAL: subject '${SUBJECT}' is missing required function '${fn}'; stale or wrong accountctl.sh." >&2
      exit 1
   fi
done

## Shim the external / root dependencies so the PURE logic runs without root or
## real account state. get_pass injects a fuzzed password; getent serves a small
## fuzzed fixture (numeric key -> GID lookup, matching real getent).
log() { :; }
as_root() { :; }
is_user() { return 0; }
get_pass() { printf '%s' "${FUZZ_PASS}"; }
getent() {
   local db='' key='' a field=1 line matched=''
   for a in "$@"; do
      if [ "${a}" = '--' ]; then
         continue
      fi
      if [ -z "${db}" ]; then
         db="${a}"
      elif [ -z "${key}" ]; then
         key="${a}"
      fi
   done
   local data=''
   case "${db}" in
      passwd)
         data="${FUZZ_PASSWD}"
         ;;
      group)
         data="${FUZZ_GROUP}"
         ;;
      *)
         return 2
         ;;
   esac
   if [ -z "${key}" ]; then
      printf '%s\n' "${data}"
      return 0
   fi
   case "${key}" in
      ''|*[!0-9]*)
         field=1
         ;;
      *)
         field=3
         ;;
   esac
   while IFS= read -r line; do
      [ -n "${line}" ] || continue
      if [ "$(printf '%s' "${line}" | cut -d: -f"${field}")" = "${key}" ]; then
         printf '%s\n' "${line}"
         matched=y
      fi
   done <<< "${data}"
   [ -n "${matched}" ] || return 2
}

RANDOM="${1}"
iters="${2}"
fails=0

note() {
   printf '%s\n' "FUZZ VIOLATION: ${1}"
   fails=$(( fails + 1 ))
}

## Pick a random string: length 0..maxlen, chars drawn from "${alpha}".
rand_str() {
   local alpha="${1}" maxlen="${2}" n out='' i
   n=$(( RANDOM % (maxlen + 1) ))
   for (( i = 0; i < n; i++ )); do
      out+="${alpha:$(( RANDOM % ${#alpha} )):1}"
   done
   printf '%s' "${out}"
}

name_alpha='abcdefghijklmnopqrstuvwxyz0123456789-_.@$ABC!*[]^ /:'
pass_alpha='!*$6aZ:x'
symbols=( '!' '!*' '*' )
fields_known=( pass uid gid comment home shell members admins last-pass-change )
dbs=( passwd shadow group gshadow bogus '' )

i=0
while [ "${i}" -lt "${iters}" ]; do
   i=$(( i + 1 ))

   ## --- is_name_valid: accepted => first char [a-zA-Z_] AND all chars safe ---
   nm="$(rand_str "${name_alpha}" 6)"
   if is_name_valid "${nm}" >/dev/null 2>&1; then
      if [[ "${nm}" != [a-zA-Z_]* ]]; then
         note "is_name_valid accepted '${nm}' not starting [a-zA-Z_]"
      fi
      ## Strip an optional single trailing '$'; every remaining char must be in
      ## the safe class ('-' first in the bracket so it is literal, not a range).
      body="${nm%\$}"
      if [ -n "${body//[-a-zA-Z0-9_.@]/}" ]; then
         note "is_name_valid accepted '${nm}' with an unsafe character"
      fi
   fi

   ## --- escape_name: output equals the reference '.'/'$'-escaping transform ---
   esc="$(escape_name "${nm}")"
   ref="${nm//./\\.}"
   ref="${ref//\$/\\\$}"
   if [ "${esc}" != "${ref}" ]; then
      note "escape_name '${nm}' -> '${esc}', reference '${ref}'"
   fi

   ## --- get_clean_pass: result has no leading marker char and is a suffix ---
   FUZZ_PASS="$(rand_str "${pass_alpha}" 6)"
   sym="${symbols[$(( RANDOM % ${#symbols[@]} ))]}"
   clean="$(get_clean_pass u "${sym}")"
   first="${clean:0:1}"
   if [ -n "${first}" ] && [[ "${sym}" == *"${first}"* ]]; then
      note "get_clean_pass pass='${FUZZ_PASS}' sym='${sym}' -> '${clean}' has a leading marker"
   fi
   if [[ "${FUZZ_PASS}" != *"${clean}" ]]; then
      note "get_clean_pass pass='${FUZZ_PASS}' sym='${sym}' -> '${clean}' is not a suffix"
   fi

   ## --- get_field: known field -> whole-number index; unknown -> error ---
   db="${dbs[$(( RANDOM % ${#dbs[@]} ))]}"
   fld="${fields_known[$(( RANDOM % ${#fields_known[@]} ))]}"
   if idx="$(get_field "${db}" "${fld}" 2>/dev/null)"; then
      if ! [[ "${idx}" =~ ^(0|[1-9][0-9]*)$ ]]; then
         note "get_field '${db}' '${fld}' -> non-whole index '${idx}'"
      fi
   fi
   ## A definitively unknown field must error (no numeric index printed).
   if bogus_idx="$(get_field "${db}" "zzbogus_${RANDOM}" 2>/dev/null)"; then
      note "get_field '${db}' bogus-field -> succeeded with '${bogus_idx}'"
   fi

   ## --- group_has_nonroot_member: a name not starting [a-zA-Z_] is rejected ---
   FUZZ_PASSWD="root:x:0:0:::"$'\n'"svc:x:1000:5000:::"
   FUZZ_GROUP="grp:x:5000:"$'\n'"root:x:0:"
   gnm="$(rand_str "${name_alpha}" 5)"
   if [[ "${gnm}" != [a-zA-Z_]* ]]; then
      if group_has_nonroot_member "${gnm}"; then
         note "group_has_nonroot_member accepted non-name '${gnm}'"
      fi
   fi
done

printf '%s\n' "FUZZFAILS=${fails}"
