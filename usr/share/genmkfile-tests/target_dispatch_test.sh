#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_parse_cmd runs each argument as a 'make_<target>' function. Two failure modes it must
## reject LOUDLY (never a silent success):
##   - a VALID target followed by an UNRECOGNIZED one ('genmkfile install deb-cleanuptypo'):
##     used to run install, then SILENTLY DROP the typo and report success -- a skipped step.
##   - an UNRECOGNIZED FIRST argument: used to fall through to make_function_run, which
##     EXECUTES it -- so a first arg naming a real PATH command ('genmkfile rm ...',
##     'genmkfile id') would RUN it. It must die instead.
## A run of purely valid targets still runs them all.
##
## make-helper-one.bsh is sourceable (its main is guarded by was_executed), so we source the
## REAL file and override only the dispatch sinks (make_function_run + a few target stubs)
## AFTER sourcing -- make_parse_cmd itself stays the real code, with no fragile sed extraction.

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
         '/make-helper-one.bsh')
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

GENMKFILE_PATH="$(dirname -- "${helper_file}")"
export GENMKFILE_PATH
## style-ok: allow-sc1091-disable -- helper_file is located at runtime, unfollowable
# shellcheck disable=SC1090,SC1091
source "${helper_file}"

## Override the dispatch sinks AFTER sourcing: an execute-through make_function_run plus
## recording target stubs, so make_parse_cmd's routing is observed without running real
## build targets. make_parse_cmd resolves these names at call time, so it sees the stubs.
# shellcheck disable=SC2317  # invoked indirectly via make_parse_cmd
exit_with_error() { printf 'DIE: %s\n' "$2" >&2; exit "$1"; }
# shellcheck disable=SC2317
make_function_run() { local f="$1"; shift; "${f}" "$@"; }
# shellcheck disable=SC2317
make_all() { printf 'RAN make_all\n'; }
# shellcheck disable=SC2317
make_install() { printf 'RAN make_install\n'; }
# shellcheck disable=SC2317
make_dist() { printf 'RAN make_dist\n'; }

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }

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

check 'valid target followed by an unrecognized one -> die' 1 'unrecognized target' install deb-cleanuptypo
check 'two valid targets both run' 0 'RAN make_dist' install dist
check 'single valid target runs' 0 'RAN make_install' install
check 'no args -> make_all' 0 'RAN make_all'

## An unrecognized FIRST argument must DIE, not fall through to make_function_run (which would
## EXECUTE it). Proof: a first arg that names a real command must not run it -- assert the
## command's marker is never emitted and the call fails.
out=''
rc=0
out="$( ( make_parse_cmd echo dispatch_exec_canary ) 2>&1 )" || rc=$?
tests_total=$(( tests_total + 1 ))
if [ "${rc}" -ne 0 ] && [[ "${out}" != *dispatch_exec_canary* ]]; then
   pass 'unrecognized first argument is NOT executed as a command'
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  first-arg exec: rc=${rc} out=[${out}]" >&2
fi

## And a non-command typo dies loud with a clear message (old code: bash "command not found").
out=''
rc=0
out="$( ( make_parse_cmd bogustargettypo ) 2>&1 )" || rc=$?
tests_total=$(( tests_total + 1 ))
if [ "${rc}" -ne 0 ] && [[ "${out}" == *'unrecognized target'* ]]; then
   pass 'unrecognized first argument fails loud with a clear message'
else
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  unrecognized first argument: rc=${rc} out=[${out}]" >&2
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "target_dispatch_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "target_dispatch_test: ${tests_total} pass, 0 fail, 0 skip"
