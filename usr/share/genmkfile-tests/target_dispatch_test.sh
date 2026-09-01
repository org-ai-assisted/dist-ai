#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_parse_cmd runs each argument as a 'make_<target>' function. A VALID target followed by
## an UNRECOGNIZED one (e.g. 'genmkfile install deb-cleanuptypo') used to run the valid target
## and then SILENTLY DROP the misspelled one, reporting success -- a typo could skip a step
## (install without the intended cleanup) with no error. It must now fail loud, while a run of
## purely valid targets still runs them all. Drives the REAL make_parse_cmd with stub targets.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

locate_helper() {
   local candidate from_bin=''
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      from_bin="$(dirname -- "$(dirname -- "${GENMKFILE_BIN}")")/share/genmkfile/make-helper-one.bsh"
   fi
   for candidate in \
      "${GENMKFILE_SHARE:-}/make-helper-one.bsh" \
      "${from_bin}" \
      "${HOME:-}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
      "/usr/share/genmkfile/make-helper-one.bsh"
   do
      [ -n "${candidate}" ] || continue
      case "${candidate}" in
         '/make-helper-one.bsh' )
            continue
            ;;
      esac
      if test -r "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! helper_file="$(locate_helper)"; then
   printf '%s\n' 'FATAL: make-helper-one.bsh not found (set GENMKFILE_SHARE).' >&2
   exit 1
fi

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() {
   safe-rm -r -f -- "${test_root}"
}
trap cleanup EXIT

## Extract the real make_parse_cmd; stub die, the dispatcher, and a couple of targets.
{
   printf '%s\n' 'exit_with_error() { printf "DIE: %s\n" "$2" >&2; exit "$1"; }'
   printf '%s\n' 'make_function_run() { local f="$1"; shift; "$f" "$@"; }'
   printf '%s\n' 'make_all() { printf "RAN make_all\n"; }'
   printf '%s\n' 'make_install() { printf "RAN make_install\n"; }'
   printf '%s\n' 'make_dist() { printf "RAN make_dist\n"; }'
   sed -n '/^make_parse_cmd()/,/^}/p' -- "${helper_file}"
} > "${test_root}/fn.sh"
if ! grep --quiet '^make_parse_cmd()' "${test_root}/fn.sh"; then
   printf '%s\n' 'ERROR: could not extract make_parse_cmd.' >&2
   exit 1
fi
# shellcheck disable=SC1091
source "${test_root}/fn.sh"

tests_total=0
tests_failed=0

## check <desc> <want_rc> <want_substr_in_output> <arg...>
check() {
   local desc="$1" want_rc="$2" want_sub="$3"
   shift 3
   local out rc=0
   out="$( ( make_parse_cmd "$@" ) 2>&1 )" || rc=$?
   tests_total=$(( tests_total + 1 ))
   if [ "${rc}" -eq "${want_rc}" ] && [[ "${out}" == *"${want_sub}"* ]]; then
      pass "${desc}"
   else
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  ${desc}: rc=${rc} (want ${want_rc}) out=[${out}]" >&2
   fi
}
pass() { printf '%s\n' "PASS  $1"; }

check 'valid target followed by an unrecognized one -> die' 1 'unrecognized target' install deb-cleanuptypo
check 'two valid targets both run' 0 'RAN make_dist' install dist
check 'single valid target runs' 0 'RAN make_install' install
check 'no args -> make_all' 0 'RAN make_all'

## An unrecognized FIRST argument stays a loud "command not found" (rc 127), never silent.
out=''
rc=0
out="$( ( make_parse_cmd bogustargettypo ) 2>&1 )" || rc=$?
tests_total=$(( tests_total + 1 ))
if [ "${rc}" -ne 0 ]; then
   pass 'unrecognized first argument fails loud (never a silent success)'
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  unrecognized first argument: rc=${rc} out=[${out}]" >&2
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "target_dispatch_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "target_dispatch_test: ${tests_total} pass, 0 fail, 0 skip"
