#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'build-steps.d/1100_sanity-tests'
## check-required-tools.
##
## THE BUG IT GUARDS: 'modprobe' was absent from the derivative-maker container,
## and nothing checked. The reproducibility comparison needs it to attach an image
## through nbd; without it that route silently fell back to comparing the packed
## artifacts directly, which OOMs on a multi-gigabyte image, so the run reported
## only "diffoscope could not explain the diff" -- hours into a build, naming
## neither the tool nor the package.
##
## The rule is deliberately simple: every external tool the pipeline invokes must
## be present, always, asserted in one place, rather than each step reasoning
## about what it needs. A missing tool then fails in seconds with its package
## name instead of degrading into an unattributable report.
##
## Drives the SHIPPED function, extracted from 1100_sanity-tests with 'error'
## stubbed, so a regression in the real list or the real logic fails here.
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
      "${HOME}/derivative-maker/build-steps.d/1100_sanity-tests"; do
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
if grep --quiet --fixed-strings 'check-required-tools()' "${sanity_tests}"; then
   pass "1100_sanity-tests defines check-required-tools"
else
   fail "1100_sanity-tests does not define check-required-tools"
fi
if grep --quiet --extended-regexp '^ +check-required-tools "\$@"' "${sanity_tests}"; then
   pass "check-required-tools is called from main"
else
   fail "check-required-tools is defined but never called from main"
fi

repo_root_of_subject="$(dirname -- "$(dirname -- "${sanity_tests}")")"
has_sh="${repo_root_of_subject}/packages/kicksecure/helper-scripts/usr/libexec/helper-scripts/has.sh"
if [ ! -r "${has_sh}" ]; then
   printf '%s\n' "SKIP: helper-scripts has.sh not checked out at ${has_sh}." >&2
   exit 77
fi

guard="$(sed -n '/^check-required-tools()/,/^}/p' -- "${sanity_tests}")"
if [ -z "${guard}" ]; then
   printf '%s\n' "FAILED: could not extract check-required-tools." >&2
   exit 1
fi

## Drive the extracted function with 'error' stubbed to report and exit non-zero,
## exactly as help-steps/pre's does.
run_guard() {
   local body="$1" path_override="$2"

   ## has.sh comes from the same checkout: the function under test uses 'has'
   ## (R-090) rather than 'command -v', so the harness must provide the real one
   ## -- stubbing it would test the stub's idea of "present", not the shipped one.
   env GUARD_PATH="${path_override}" GUARD_HAS="${has_sh}" \
      bash -- "${test_dir}/required_tools_guard_inner.sh" "${body}" 2>&1
}

## --- every tool present -> must pass --------------------------------------
## Probe with the SAME 'has' the guard uses, from the same checkout: a host where
## 'has' and 'command -v' disagree would otherwise make this branch either skip
## when it could run, or run when the guard cannot pass.
# shellcheck disable=SC1090
source "${has_sh}"

missing_here=""
for tool in modprobe losetup mountpoint qemu-img qemu-nbd kpartx parted; do
   has "${tool}" || missing_here="${missing_here} ${tool}"
done

if [ -n "${missing_here}" ]; then
   printf '%s\n' "SKIP: this host lacks${missing_here}; cannot exercise the all-present branch." >&2
   exit 77
fi

rc=0
out="$(run_guard "${guard}" "${PATH}")" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "all tools present: passes"
else
   fail "all tools present: rejected (${rc}) -- ${out}"
fi

## --- a tool missing -> must fail, naming the tool AND its package ----------
empty_dir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${empty_dir}"
}
trap cleanup EXIT

rc=0
out="$(run_guard "${guard}" "${empty_dir}")" || rc="$?"

if [ "${rc}" -ne 0 ]; then
   pass "missing tools: fails (${rc})"
else
   fail "missing tools: ACCEPTED -- the check does not check"
fi

case "${out}" in
   *modprobe*)
      pass "failure names the missing tool"
      ;;
   *)
      fail "failure does not name the missing tool: ${out}"
      ;;
esac

## Naming the PACKAGE is the point: "modprobe not found" sends the reader
## hunting, "package: kmod" is actionable.
case "${out}" in
   *kmod*)
      pass "failure names the providing package"
      ;;
   *)
      fail "failure does not name the providing package: ${out}"
      ;;
esac

## The tool that caused this must be declared, or the check just relocates the
## problem to install time.
deps_conf="$(dirname -- "$(dirname -- "${sanity_tests}")")/buildconfig.d/30_dependencies.conf"
if [ -r "${deps_conf}" ]; then
   if grep --quiet --fixed-strings 'kmod' "${deps_conf}"; then
      pass "kmod is declared in buildconfig.d/30_dependencies.conf"
   else
      fail "kmod is asserted by 1100 but never declared as a build dependency"
   fi
else
   fail "buildconfig.d/30_dependencies.conf not found next to the subject"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: required tools."
