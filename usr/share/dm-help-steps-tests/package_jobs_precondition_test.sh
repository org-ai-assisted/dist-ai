#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker '--package-jobs N' (parallel package
## builds in build-steps.d/2100_create-debian-packages).
##
## THE TRAP IT GUARDS: parallelism is only safe when genmkfile supports
## 'make_cow_suffix', which gives each worker its own 'cow.cow_<arch>.<slot>'
## snapshot. Without it N workers share ONE 'cow.cow_<arch>' and corrupt each
## other's chroot. A precondition carried only in prose, with nothing checking
## it, means enabling the speed-up against an older genmkfile silently produces
## a broken build.
##
## The contract now: the request is safe to pass unconditionally. 2100 verifies
## the preconditions itself and falls back to serial, SAYING SO, when one is not
## met -- never silently, because a request that was quietly reduced is
## indistinguishable from one that was honoured.
##
## Needs no root, no network -- it reads the shipped scripts.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

repo_root=""
locate_repo_root() {
   local candidate

   for candidate in "${DERIVATIVE_MAKER_DIR:-}" "${dm_checkout}"; do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}/build-steps.d/2100_create-debian-packages" ] \
         && [ -r "${candidate}/help-steps/parse-cmd" ]; then
         repo_root="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_repo_root; then
   printf '%s\n' "FATAL: no derivative-maker checkout with 2100_create-debian-packages + help-steps/parse-cmd." >&2
   exit 1
fi

create_packages="${repo_root}/build-steps.d/2100_create-debian-packages"
parse_cmd="${repo_root}/help-steps/parse-cmd"

## Fixed strings, not regex: these lines are quoted shell full of '$', '{' and
## '*', where a hand-built ERE is easy to get subtly wrong in either direction.
assert_contains() {
   local file needle label
   file="$1"
   needle="$2"
   label="$3"

   if grep --quiet --fixed-strings -- "${needle}" "${file}"; then
      pass "${label}"
   else
      fail "${label} -- not found in ${file}"
   fi
}

## The option exists and is wired to the variable 2100 reads.
assert_contains "${parse_cmd}" '--package-jobs)' \
   "parse-cmd accepts --package-jobs"
assert_contains "${parse_cmd}" 'export dist_build_package_jobs="${2:-}"' \
   "parse-cmd exports dist_build_package_jobs from --package-jobs"
assert_contains "${parse_cmd}" '--package-jobs N' \
   "parse-cmd documents --package-jobs in its usage"

## Both preconditions are CHECKED, not merely documented.
assert_contains "${create_packages}" 'make_use_cowbuilder' \
   "2100 checks that cowbuilder is in use"
assert_contains "${create_packages}" "grep --fixed-strings -- 'make_cow_suffix'" \
   "2100 probes genmkfile for make_cow_suffix support"

## An unmet precondition must fall back, and must say so. Both matter: a silent
## fallback is the failure mode this test exists to prevent.
if grep --quiet --fixed-strings -- 'building serially' "${create_packages}"; then
   pass "2100 announces the fallback to serial"
else
   fail "2100 does not announce a fallback to serial -- a reduced request would be silent"
fi

## The fallback must be a fallback, not a hard error: passing --package-jobs on a
## host that cannot honour it should still build.
if grep --quiet --fixed-strings -- 'error "dist_build_package_jobs must be a positive integer' "${create_packages}"; then
   pass "2100 still rejects a non-positive-integer job count outright"
else
   fail "2100 no longer validates the job count; 0 / non-numeric would spin the free-slot loop"
fi

## The probe must point at the genmkfile the build actually runs, i.e. the
## submodule copy 2100 invokes, not an installed one that may differ.
assert_contains "${create_packages}" \
   'packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh' \
   "2100 probes the genmkfile copy it builds with"

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: package jobs preconditions."
