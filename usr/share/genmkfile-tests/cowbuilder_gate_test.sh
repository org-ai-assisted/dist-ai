#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_get_distdir REQUIRES + redirects to the cowbuilder dist folder only when
## the target actually builds/places dist artifacts. The dispatcher sets
## make_enforce_cowbuilder_distdir=false for a non-cowbuilder action (git-*,
## help, deb-*-dep) so it never trips on make_cowbuilder_dist_folder it does not
## use, and true (the default) for a real build/dist target.
##
## make-helper-one.bsh is sourceable (its main is guarded by was_executed), so we
## source the REAL file and call make_get_distdir directly -- no sed extraction.

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

## GENMKFILE_PATH so any runtime source inside the file resolves; sourcing does
## NOT run the was_executed-guarded main, so only function definitions load.
GENMKFILE_PATH="$(dirname -- "${helper_file}")"
export GENMKFILE_PATH
## style-ok: allow-sc1091-disable -- helper_file is located at runtime, unfollowable
# shellcheck disable=SC1090,SC1091
source "${helper_file}"

## Override the real exit_with_error (its make_output_error path needs colour +
## trace state that only the full run sets up) with a recording stub, so
## make_get_distdir's cowbuilder guard is observed in isolation.
# shellcheck disable=SC2317  # invoked indirectly by make_get_distdir
exit_with_error() { printf 'DIE: %s\n' "$2" >&2; exit 66; }

## DISTDIR='.' is a writable directory, so only the cowbuilder gate can exit here.
test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() { safe-rm -r -f -- "${test_root}"; }
trap cleanup EXIT
cd -- "${test_root}"

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }

## check <desc> <enforce-value-or-UNSET> <want_cowbuilder_exit>
check() {
   local desc="$1" enforce="$2" want_exit="$3"
   local out rc=0
   out="$(
      export DISTDIR='.' make_use_cowbuilder='true'
      [ "${enforce}" = 'UNSET' ] || export make_enforce_cowbuilder_distdir="${enforce}"
      make_get_distdir 2>&1
   )" || rc=$?
   tests_total=$(( tests_total + 1 ))
   local exited='false'
   case "${out}" in
      *make_cowbuilder_dist_folder*)
         exited='true'
         ;;
   esac
   if [ "${exited}" = "${want_exit}" ]; then
      pass "${desc}"
   else
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  ${desc}: exited=${exited} (want ${want_exit}) rc=${rc} out=[${out}]" >&2
   fi
}

check 'enforce=true demands the cowbuilder folder (build/dist target)' 'true' 'true'
check 'enforce=false does NOT demand it (non-cowbuilder action)' 'false' 'false'
check 'unset defaults to enforce (backward compatible)' 'UNSET' 'true'

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "cowbuilder_gate_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "cowbuilder_gate_test: ${tests_total} pass, 0 fail, 0 skip"
