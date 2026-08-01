#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'build-steps.d/1100_sanity-tests'
## check_required_packages_installed.
##
## THE BUG IT GUARDS: 'modprobe' was absent from the derivative-maker container,
## and nothing installed it. The reproducibility comparison needs it to attach an
## image through nbd; without it that route silently fell back to comparing the
## packed artifacts directly, which OOMs on a multi-gigabyte image, so the run
## reported only "diffoscope could not explain the diff" -- hours into a build,
## naming neither the tool nor the package.
##
## The fix is a package, not a probe: the tools the build and the reproducibility
## comparison invoke are installed by this step and declared in
## buildconfig.d/30_dependencies.conf. So what has to hold is that each one is in
## BOTH lists -- a probe that merely reports the gap would still leave the build
## unable to run.
##
## Drives the SHIPPED function, so a package silently dropped from either list
## fails here.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

sanity_tests=""
locate_subject() {
   local candidate

   for candidate in "${DM_SANITY_TESTS:-}" \
      "${DERIVATIVE_MAKER_DIR:-}/build-steps.d/1100_sanity-tests" \
      "${dm_checkout}/build-steps.d/1100_sanity-tests"; do
      case "${candidate}" in
         ''|'/build-steps.d/1100_sanity-tests')
            continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         sanity_tests="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: no derivative-maker build-steps.d/1100_sanity-tests found." >&2
   exit 77
fi

## Contract: defined, and actually dispatched. A defined-but-uncalled check is
## dead code that reads like coverage.
if grep --quiet --fixed-strings 'check_required_packages_installed()' "${sanity_tests}"; then
   pass "1100_sanity-tests defines check_required_packages_installed"
else
   fail "1100_sanity-tests does not define check_required_packages_installed"
fi
if sed -n '/^main()/,/^}/p' -- "${sanity_tests}" \
   | grep --quiet --fixed-strings 'check_required_packages_installed'; then
   pass "check_required_packages_installed is called from main"
else
   fail "check_required_packages_installed is defined but never called from main"
fi

## One list, not two: a separate binary-probe function had to repeat the
## tool-to-package mapping to stay correct, and drifted from the list that
## actually installs anything.
if grep --quiet --fixed-strings 'check-required-tools' "${sanity_tests}"; then
   fail "1100_sanity-tests reintroduced check-required-tools; the package list is the single source"
else
   pass "no separate binary-probe function duplicating the package list"
fi

## Read the list the SHIPPED function assigns, so an edit to the real line is
## what this test sees.
##
## Parsed, not 'eval'ed. The subject is a build script this suite also runs
## against branches and forks, and 'eval' on a line lifted out of it would
## execute whatever else that line carries -- a test harness is not the place to
## hand an arbitrary source tree a shell.
required_packages_list=""
package_list_line="$(sed -n '/^check_required_packages_installed()/,/^}/p' -- "${sanity_tests}" \
   | grep --max-count=1 -- '^ *required_packages_list=')"
if [ -z "${package_list_line}" ]; then
   printf '%s\n' "FAILED: no required_packages_list assignment in check_required_packages_installed." >&2
   exit 1
fi
## Everything after the first '=', with one layer of surrounding quotes removed.
required_packages_list="${package_list_line#*=}"
case "${required_packages_list}" in
   '"'*'"')
      required_packages_list="${required_packages_list#\"}"
      required_packages_list="${required_packages_list%\"}"
      ;;
   "'"*"'")
      required_packages_list="${required_packages_list#\'}"
      required_packages_list="${required_packages_list%\'}"
      ;;
esac
if [ -z "${required_packages_list}" ]; then
   printf '%s\n' "FAILED: required_packages_list parsed as empty from '${package_list_line}'." >&2
   exit 1
fi

deps_conf="$(dirname -- "$(dirname -- "${sanity_tests}")")/buildconfig.d/30_dependencies.conf"
if [ ! -r "${deps_conf}" ]; then
   printf '%s\n' "FAILED: buildconfig.d/30_dependencies.conf not found next to the subject." >&2
   exit 1
fi

## Every package that provides a tool the build or the comparison invokes. Named
## explicitly rather than derived, so removing one from the shipped list is a
## test failure instead of a silently shorter loop.
for needed_package in kmod qemu-utils kpartx parted; do
   case " ${required_packages_list} " in
      *" ${needed_package} "*)
         pass "${needed_package}: installed by check_required_packages_installed"
         ;;
      *)
         fail "${needed_package}: NOT in required_packages_list -- the container ships none of these, so the build gets no ${needed_package}"
         ;;
   esac

   ## Installing it in 1100 alone is not enough: without the declaration the rest
   ## of the build has no claim on it.
   if grep --quiet --fixed-strings "${needed_package}" "${deps_conf}"; then
      pass "${needed_package}: declared in buildconfig.d/30_dependencies.conf"
   else
      fail "${needed_package}: installed by 1100 but never declared as a build dependency"
   fi
done

## CANARY: the two membership tests above must be able to FAIL. A package that is
## in neither list has to be reported by both, or the matching is broken (e.g. a
## substring match that answers yes for everything).
canary_package="definitely-not-a-real-package"
case " ${required_packages_list} " in
   *" ${canary_package} "*)
      fail "canary broken: required_packages_list matching reports a nonexistent package as present"
      ;;
   *)
      pass "canary: required_packages_list matching can report a package as absent"
      ;;
esac
if grep --quiet --fixed-strings "${canary_package}" "${deps_conf}"; then
   fail "canary broken: 30_dependencies.conf matching reports a nonexistent package as present"
else
   pass "canary: 30_dependencies.conf matching can report a package as absent"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: required tools."
