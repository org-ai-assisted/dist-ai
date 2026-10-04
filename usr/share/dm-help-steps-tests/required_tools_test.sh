#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the derivative-maker early-build-dependency contract.
##
## THE BUG IT GUARDS: 'modprobe' (package 'kmod') was absent from the
## derivative-maker container, and nothing installed it. The reproducibility
## comparison needs it to attach an image through nbd; without it that route
## silently fell back to comparing the packed artifacts directly, which OOMs on a
## multi-gigabyte image, so the run reported only "diffoscope could not explain
## the diff" -- hours into a build, naming neither the tool nor the package.
##
## The fix is a package, not a probe. The early build tools are INSTALLED by
## 'build-steps.d/1050_early-build-setup' (function 'install_required_packages')
## from the single-source list '$dist_build_early_dependencies' in
## 'variables.d/60_dependencies.bsh'; 'build-steps.d/1100_sanity-tests' only
## CHECKS their presence (function 'check-required-packages-present', read-only).
## What must hold for each needed tool:
##   - it is in '$dist_build_early_dependencies' (so 1050 installs it), AND
##   - it is in the full build-dependency declaration
##     '$dist_build_script_build_dependency' (so the rest of the build has a
##     claim on it -- installed-but-undeclared leaves the build unable to run).
## A presence check that merely reported the gap would still leave the build
## unable to run, which is why the install list, not a probe, is the contract.
##
## Parsed, not 'eval'ed: this suite also runs against branches and forks, and
## 'eval' on a line lifted out of a source tree would execute whatever else that
## line carries -- a test harness is not the place to hand an arbitrary source
## tree a shell.
##
## Needs no root, no network, no build.

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

## Resolve a build step under 'build-steps.d/': an explicit env override, then a
## copy staged alongside the test, then the derivative-maker checkout.
locate_build_step() {
   local step_name env_override candidate
   step_name="$1"
   env_override="${2:-}"

   for candidate in \
      "${env_override}" \
      "${test_dir}/${step_name}" \
      "${dm_checkout}/build-steps.d/${step_name}"; do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}" ]; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! early_setup="$(locate_build_step 1050_early-build-setup "${DM_EARLY_SETUP:-}")"; then
   printf '%s\n' "FATAL: no derivative-maker build-steps.d/1050_early-build-setup found." >&2
   exit 1
fi
if ! sanity_tests="$(locate_build_step 1100_sanity-tests "${DM_SANITY_TESTS:-}")"; then
   printf '%s\n' "FATAL: no derivative-maker build-steps.d/1100_sanity-tests found." >&2
   exit 1
fi

deps_conf="$(dirname -- "$(dirname -- "${early_setup}")")/variables.d/60_dependencies.bsh"
if [ ! -r "${deps_conf}" ]; then
   printf '%s\n' "FATAL: variables.d/60_dependencies.bsh not found at '${deps_conf}'." >&2
   exit 1
fi

## --- 1050 INSTALLS, from the single-source list ---

## Drop full-line '#' comments from stdin, so a commented-out call or a prose
## mention cannot satisfy a presence check below.
noncomment() {
   grep --invert-match --extended-regexp '^[[:space:]]*#' || true
}

if grep --quiet --fixed-strings 'install_required_packages()' "${early_setup}"; then
   pass "1050_early-build-setup defines install_required_packages"
else
   fail "1050_early-build-setup does not define install_required_packages"
fi

## Code (comments dropped) of each subject and its main() body, captured ONCE so
## the presence checks read a here-string, not a pipe a quiet grep would break
## (R-161: grep --quiet/-m on the right of a pipe SIGPIPEs the writer under
## pipefail). 'noncomment' (grep --invert-match) reads to EOF, so piping INTO it
## is safe.
early_setup_code="$(noncomment < "${early_setup}")"
early_setup_main="$(sed -n '/^main()/,/^}/p' -- "${early_setup}" | noncomment)"
sanity_code="$(noncomment < "${sanity_tests}")"
sanity_main="$(sed -n '/^main()/,/^}/p' -- "${sanity_tests}" | noncomment)"

if grep --quiet --fixed-strings 'install_required_packages' <<< "${early_setup_main}"; then
   pass "install_required_packages is called from 1050 main"
else
   fail "install_required_packages is defined but never called from 1050 main"
fi

## Installs the single-source variable, not a hand-maintained copy: a hardcoded
## list in 1050 would drift from the declaration the rest of the build reads.
if grep --quiet --fixed-strings 'dist_build_early_dependencies' <<< "${early_setup_code}"; then
   pass "1050 installs from \$dist_build_early_dependencies (single source)"
else
   fail "1050 does not reference \$dist_build_early_dependencies; a hardcoded list drifts"
fi

## --- 1100 CHECKS (read-only), does not install ---

if grep --quiet --fixed-strings 'check-required-packages-present()' "${sanity_tests}"; then
   pass "1100_sanity-tests defines check-required-packages-present"
else
   fail "1100_sanity-tests does not define check-required-packages-present"
fi

if grep --quiet --fixed-strings 'check-required-packages-present' <<< "${sanity_main}"; then
   pass "check-required-packages-present is called from 1100 main"
else
   fail "check-required-packages-present is defined but never called from 1100 main"
fi

## The presence check iterates the same single source, so it cannot drift from
## what 1050 installs.
if grep --quiet --fixed-strings 'dist_build_early_dependencies' <<< "${sanity_code}"; then
   pass "1100 checks \$dist_build_early_dependencies (single source)"
else
   fail "1100 does not reference \$dist_build_early_dependencies"
fi

## Read-only: 1100 must neither define the installer nor run apt-get. A mutation
## here is exactly the 'sanity test that changes the machine' this split removes.
## Comments are stripped first, so a prose mention of either does not false-fail.
if grep --quiet --fixed-strings 'install_required_packages' <<< "${sanity_code}"; then
   fail "1100 still references install_required_packages; the install belongs in 1050"
else
   pass "1100 does not install (no install_required_packages)"
fi
if grep --quiet --extended-regexp '(^|[^[:alnum:]_-])apt-get([^[:alnum:]_-]|$)' <<< "${sanity_code}"; then
   fail "1100 still runs apt-get; the sanity step must be read-only"
else
   pass "1100 runs no apt-get (read-only)"
fi

## One list, not two: a separate binary-probe function had to repeat the
## tool-to-package mapping to stay correct, and drifted from the list that
## actually installs anything.
if grep --quiet --fixed-strings 'check-required-tools' "${sanity_tests}"; then
   fail "1100_sanity-tests reintroduced check-required-tools; the package list is the single source"
else
   pass "no separate binary-probe function duplicating the package list"
fi

## --- parse the two lists, not 'eval' them ---

## Extract a dependency variable's declared tokens WITHOUT eval (the suite runs
## against forks; sourcing would execute arbitrary tree code). For each '=' or
## '+=' assignment line of the named variable, take the text between the FIRST
## double-quote pair -- so a trailing '# comment' and the =/+= distinction cannot
## leak in -- and join every line's tokens with single spaces.
##
## Scope (parse, not eval): this cannot model a later reassignment that resets the
## variable, a conditional guard around an append, or whether a token is the
## install ARGUMENT vs a mention elsewhere. Our lists use none of those shapes for
## the checked packages (declared unconditionally, never reset); modelling them
## would require evaluating the tree, which the fork-safety rule forbids.
extract_dep_tokens() {
   local var_name="$1" file="$2"
   grep --extended-regexp "^ *${var_name}\+?=" -- "${file}" \
      | sed --quiet --regexp-extended 's/^[^=]*=[^"]*"([^"]*)".*/\1/p' \
      | tr '\n' ' '
}

early_deps="$(extract_dep_tokens dist_build_early_dependencies "${deps_conf}")"
if [ -z "${early_deps// /}" ]; then
   printf '%s\n' "FAILED: no dist_build_early_dependencies tokens parsed from ${deps_conf}." >&2
   exit 1
fi

## Matched separately from the early list so a tool that is ONLY in the early list
## (and never declared as a build dependency) is still caught.
full_decl="$(extract_dep_tokens dist_build_script_build_dependency "${deps_conf}")"
if [ -z "${full_decl// /}" ]; then
   printf '%s\n' "FAILED: no dist_build_script_build_dependency tokens parsed from ${deps_conf}." >&2
   exit 1
fi

## --- membership: every needed tool in BOTH lists ---

## Named explicitly rather than derived, so removing one from either list is a
## test failure instead of a silently shorter loop.
for needed_package in kmod qemu-utils kpartx parted; do
   case " ${early_deps} " in
      *" ${needed_package} "*)
         pass "${needed_package}: in \$dist_build_early_dependencies (installed by 1050)"
         ;;
      *)
         fail "${needed_package}: NOT in \$dist_build_early_dependencies -- 1050 would not install it"
         ;;
   esac

   case " ${full_decl} " in
      *" ${needed_package} "*)
         pass "${needed_package}: declared in \$dist_build_script_build_dependency"
         ;;
      *)
         fail "${needed_package}: installed early but never declared as a build dependency"
         ;;
   esac
done

## CANARY: the membership tests above must be able to FAIL. A package in neither
## list has to be reported absent by both, or the matching is broken (e.g. a
## substring match that answers yes for everything).
canary_package="definitely-not-a-real-package"
case " ${early_deps} " in
   *" ${canary_package} "*)
      fail "canary broken: \$dist_build_early_dependencies matching reports a nonexistent package as present"
      ;;
   *)
      pass "canary: \$dist_build_early_dependencies matching can report a package as absent"
      ;;
esac
case " ${full_decl} " in
   *" ${canary_package} "*)
      fail "canary broken: \$dist_build_script_build_dependency matching reports a nonexistent package as present"
      ;;
   *)
      pass "canary: \$dist_build_script_build_dependency matching can report a package as absent"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: required tools."
