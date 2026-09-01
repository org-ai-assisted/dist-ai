#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_get_distdir REQUIRES + redirects to the cowbuilder dist folder only when
## the target actually builds/places dist artifacts. The dispatcher sets
## make_enforce_cowbuilder_distdir=false for a non-cowbuilder action (git-*,
## help, deb-*-dep) so it never trips on make_cowbuilder_dist_folder it does not
## use, and true (the default) for a real build/dist target. Extracts the REAL
## make_get_distdir and stubs die, so the gate is exercised directly.

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

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() { safe-rm -r -f -- "${test_root}"; }
trap cleanup EXIT

## Extract the real make_get_distdir; stub die to record + exit non-zero.
{
   printf '%s\n' 'die() { printf "DIE: %s\n" "$2" >&2; exit 66; }'
   sed -n '/^make_get_distdir()/,/^}/p' -- "${helper_file}"
} > "${test_root}/fn.sh"
if ! grep --quiet '^make_get_distdir()' "${test_root}/fn.sh"; then
   printf '%s\n' 'ERROR: could not extract make_get_distdir.' >&2
   exit 1
fi
# shellcheck disable=SC1091
source "${test_root}/fn.sh"

## DISTDIR='.' is a writable directory, so only the cowbuilder gate can die here.
cd -- "${test_root}"

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }

## check <desc> <enforce-value-or-UNSET> <want_cowbuilder_die>
check() {
   local desc="$1" enforce="$2" want_die="$3"
   local out rc=0
   out="$(
      export DISTDIR='.' make_use_cowbuilder='true'
      [ "${enforce}" = 'UNSET' ] || export make_enforce_cowbuilder_distdir="${enforce}"
      make_get_distdir 2>&1
   )" || rc=$?
   tests_total=$(( tests_total + 1 ))
   local died='false'
   case "${out}" in
      *make_cowbuilder_dist_folder*)
         died='true'
         ;;
   esac
   if [ "${died}" = "${want_die}" ]; then
      pass "${desc}"
   else
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  ${desc}: died=${died} (want ${want_die}) rc=${rc} out=[${out}]" >&2
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
